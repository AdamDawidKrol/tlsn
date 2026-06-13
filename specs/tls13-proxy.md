# Spec: TLS 1.3 support for proxy mode

Status: Draft
Scope: Proxy mode only (`crates/tlsn` proxy prover/verifier). MPC mode is out of scope.

## 1. Goals and non-goals

### Goals

- Support TLS 1.3 connections in proxy mode with the cipher suite
  `TLS13_AES_128_GCM_SHA256` (the TLS 1.3 counterpart of the currently supported
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`).
- Preserve the existing security model of proxy mode: the verifier observes the
  genuine wire bytes, and the prover proves in ZK that the committed secrets are
  consistent with the observed ciphertext.
- Preserve the existing privacy model: the verifier learns nothing about
  application plaintext beyond what the prover discloses, plus record lengths
  and handshake metadata.
- Keep TLS 1.2 fully working; version is negotiated per connection.

### Non-goals (v1)

- PSK handshakes / session resumption (already disabled via
  `Resumption::disabled()`; additionally rejected at verification, see §6.5).
- 0-RTT / early data.
- HelloRetryRequest (rejected at verification; see §10 open questions).
- KeyUpdate (connection fails at finalization if observed).
- Post-handshake client authentication.
- Cipher suites other than `TLS13_AES_128_GCM_SHA256` (no SHA-384, no ChaCha20).
- MPC mode TLS 1.3.

## 2. Background: how proxy mode works today (TLS 1.2)

1. The prover runs an unmodified rustls `ClientConnection`
   (`crates/tlsn/src/prover/client/proxy/mod.rs`), pinned to TLS 1.2,
   secp256r1, and the two AES-128-GCM suites. The verifier relays the TCP
   stream and records all TLS bytes (`InspectReader`); the prover records its
   own copy (`TlsBytes`).
2. The prover's rustls `KeyLog` captures the 48-byte master secret
   (`keylog.rs`, label `CLIENT_RANDOM`).
3. At finalization both sides independently parse the recorded wire bytes into
   a `TlsTranscript` (`crates/core/src/transcript/tls/builder.rs`). In TLS 1.2
   the handshake is in the clear up to CCS, so each side extracts the
   certificate chain, the ServerKeyExchange signature, both randoms
   (`CertBinding::V1_2`), and computes `cf_hash` / `session_hash` /
   `sf_hash` inputs.
4. In the interactive ZK VM (`ProverZk` / `VerifierZk`):
   - The prover commits the master secret (`mark_private` / `mark_blind`,
     `alloc_proxy_refs` in `crates/tlsn/src/proxy.rs`).
   - The `Prf` graph (`hmac-sha256`, `MSMode::Direct`) derives the session
     keys and `cf_vd` / `sf_vd` inside the VM from public randoms and
     transcript hashes.
   - `VerifyDataCheck` proves that the encrypted Finished records on the wire
     contain exactly those verify-data values, binding the committed master
     secret to this particular session.
   - The key references (`SessionKeys`) feed the downstream record proofs:
     AES-CTR plaintext/ciphertext consistency and GHASH tag verification
     (`crates/tlsn/src/tag.rs`, j0 from the explicit nonce, 13-byte
     `make_tls12_aad`).
5. The verifier checks the certificate chain and the ServerKeyExchange
   signature over `client_random || server_random || kx_params`
   (`HandshakeData::verify`, `CertBinding::V1_2`).

## 3. TLS 1.3 design overview

TLS 1.3 changes three things that matter to this pipeline:

1. **The handshake is encrypted** after ServerHello (EncryptedExtensions,
   Certificate, CertificateVerify, Finished are under handshake traffic keys),
   so the verifier cannot parse it from the wire.
2. **Authentication moves from ServerKeyExchange to CertificateVerify**: the
   server signs the running transcript hash, not the randoms + kx params.
3. **The key schedule is HKDF-based** with separate handshake and application
   key epochs, per-epoch sequence numbers, implicit nonces, and an inner
   content-type byte.

The central design decision: **the prover discloses the handshake traffic
secrets to the verifier at finalization.** Disclosure is safe and sufficient:

- *Privacy*: handshake traffic secrets decrypt only the handshake flight
  (extensions, certificate chain, CertificateVerify, Finished) and
  NewSessionTicket is **not** under handshake keys (it is under application
  keys; see §6.4). The handshake plaintext is exactly what the verifier already
  sees in the clear in TLS 1.2. Application traffic secrets are never
  disclosed.
- *Security*: knowing `server_handshake_traffic_secret` lets the prover forge a
  Finished MAC, but never a CertificateVerify signature from a certificate
  chaining to a trusted root. The verifier independently decrypts the handshake
  from the **wire bytes it recorded itself**, with AEAD tag checks, and
  verifies CertificateVerify over the transcript hash it recomputes itself.
  Since HKDF is collision-resistant, the ZK proof that the *committed*
  `handshake_secret` expands to the *disclosed* handshake traffic secrets binds
  the committed secret — and hence the derived application keys — to the
  authenticated handshake.

This makes Finished verification a **cleartext** check on the verifier (no ZK
needed), and removes `VerifyDataCheck` entirely from the 1.3 path. The ZK work
reduces to one HKDF chain (§5).

### Trust chain (verifier's view)

```
wire bytes (observed by verifier, network assumption — unchanged from 1.2)
  └─ AEAD decrypt handshake records with disclosed {c,s}_hs_traffic_secret
       └─ tag check binds disclosed secrets to wire ciphertext
       └─ cert chain → webpki roots
       └─ CertificateVerify over H(CH..Certificate)  ← server authentication
       └─ server Finished over H(CH..CertificateVerify) (cleartext check)
  └─ ZK: committed handshake_secret
       ├─ expands to disclosed {c,s}_hs_traffic_secret   (public decode)
       └─ expands to master_secret → application keys    (private)
            └─ AES-CTR plaintext proofs + GHASH tag proofs on app records
```

## 4. Secret capture on the prover (replaces `MasterSecretLog`)

rustls's `KeyLog` only exposes *traffic* secrets
(`{CLIENT,SERVER}_HANDSHAKE_TRAFFIC_SECRET`, `{CLIENT,SERVER}_TRAFFIC_SECRET_0`),
not `handshake_secret`. Traffic secrets alone cannot link the handshake epoch
to the application epoch in ZK (they are siblings under `handshake_secret` /
`master_secret`). The prover must therefore capture `handshake_secret` itself.

**Mechanism** (validated by spike, see
`specs/spikes/tls13-secret-capture-RESULTS.md` — all assertions pass on the
locked rustls 0.23.40): a custom `rustls::crypto::tls13::Hkdf` implementation
wrapping the suite's existing `&'static dyn Hkdf`, installed via the
`CryptoProvider`'s `Tls13CipherSuite.hkdf_provider`. For a non-PSK client
handshake, rustls completes the ECDHE itself and calls
`extract_from_secret(Some(derived_salt), ecdhe_shared)` exactly once
(`KeySchedule::input_secret`; `Hkdf::extract_from_kx_shared_secret` is *not*
used in the client path). The wrapper recomputes the PRK with one inline HMAC,
yielding `handshake_secret` directly. Identification is deterministic, not
order-based: the wrapper also wraps the returned `HkdfExpander`, and the
extract whose expander is later asked to expand with label
`"tls13 c hs traffic"` is the handshake secret (the expansion `info` also
carries the transcript hashes `h2`/`h3` as a cross-check). The existing
`KeyLog` hook is kept to capture the two handshake traffic secrets for
disclosure and validation.

Construction notes from the spike:

- `rustls::crypto::ring::hmac` is `pub(crate)`; the wrapper must delegate to
  the suite's existing HKDF instance (it cannot build its own
  `HkdfUsingHmac`).
- `Tls13CipherSuite` cannot be built with struct-update syntax
  (`CipherSuiteCommon` is non-`Copy`); reconstruct it field-by-field (all
  fields are public).
- Per-connection attribution: one leaked (suite + wrapper) instance per
  connection, recycled through a bounded pool so the leak is O(max
  concurrency), not O(connections).

New type `SecretLog` in `crates/tlsn/src/prover/client/proxy/keylog.rs`:

```rust
enum CapturedSecrets {
    V1_2 { ms: [u8; 48] },
    V1_3 {
        handshake_secret: [u8; 32],
        client_hs_traffic_secret: [u8; 32],
        server_hs_traffic_secret: [u8; 32],
    },
}
```

`ProxyTlsClient::poll` passes `CapturedSecrets` to `ProxyProver::finalize`
instead of `Vec<u8>`.

A rustls fork is **not** needed: the spike retired this risk (the sized
fallback — a hook in `KeySchedule::input_secret`, ~30–60 LoC plus rebase
burden — is documented in the spike results for the record).

## 5. ZK key schedule (new module in `components/hmac-sha256`)

New `KeySchedule13` alongside `Prf`, same flush-driven driver pattern
(`wants_flush()` / `flush(vm)` / setters), so `ProxyProver` / `ProxyVerifier`
drive it identically to `Prf` today.

### Inputs

| Value | Visibility | Source |
|---|---|---|
| `handshake_secret` HS (32B) | private (prover) / blind (verifier) | `SecretLog` / committed |
| `h2 = H(CH..SH)` | public | computable from plaintext wire records |
| `h3 = H(CH..server Finished)` | public | computed after handshake decryption (§6) |
| labels, lengths | public constants | RFC 8446 §7.1 |

### Derivation graph (all HMAC-SHA256, reusing `hmac.rs` / `mpz_hash::Sha256`)

```
c_hs = HKDF-Expand-Label(HS, "c hs traffic", h2, 32)   → decode PUBLIC
s_hs = HKDF-Expand-Label(HS, "s hs traffic", h2, 32)   → decode PUBLIC
derived = HKDF-Expand-Label(HS, "derived", H(""), 32)
MS   = HKDF-Extract(salt = derived, ikm = 0^32)        = HMAC(derived, 0^32)
c_ap = HKDF-Expand-Label(MS, "c ap traffic", h3, 32)   (private)
s_ap = HKDF-Expand-Label(MS, "s ap traffic", h3, 32)   (private)
client_write_key = HKDF-Expand-Label(c_ap, "key", "", 16)
client_write_iv  = HKDF-Expand-Label(c_ap, "iv",  "", 12)
server_write_key = HKDF-Expand-Label(s_ap, "key", "", 16)
server_write_iv  = HKDF-Expand-Label(s_ap, "iv",  "", 12)
```

Every `HKDF-Expand-Label` here is a single-block HMAC (HkdfLabel < 64 bytes,
output ≤ 32 bytes ⇒ one `T(1)` block), i.e. ~3 SHA-256 compressions each.
Total ≈ 10 HMACs — cheaper than the TLS 1.2 PRF graph.

The two-phase availability of `h3` maps onto the existing two-flush pattern
(today: `set_cf_hash` … decode `cf_vd` … `set_sf_hash`):

1. `set_sh_hash(h2)` → flush → decode `c_hs`, `s_hs` publicly.
2. Caller (verifier) decrypts and verifies the handshake (§6), computes `h3`.
3. `set_sf_hash(h3)` → flush → key references available.

The **public decode** of `c_hs`/`s_hs` is the disclosure mechanism: the
verifier never accepts these values out-of-band from the prover; they fall out
of the ZK execution, so equality between "disclosed" and "proven" is automatic.

### Output

```rust
pub struct ScheduleOutput13 {
    pub keys: SessionKeys13,            // 16B keys, 12B IVs
    pub c_hs: Array<U8, 32>,            // decoded public
    pub s_hs: Array<U8, 32>,            // decoded public
}
```

Note the IV width change (4 → 12 bytes) versus `hmac_sha256::SessionKeys`.
`mpc_tls::SessionKeys` (used as the proxy-mode key handle in `TlsOutput`)
gains a V1_3 variant or the IV fields become version-dependent — to be settled
during implementation; the consumers are `verify_tags` and the transcript
plaintext proofs.

### Verify data (cleartext, not ZK)

`finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)`,
`verify_data = HMAC(finished_key, transcript_hash)` — computed by **both**
parties locally from the disclosed handshake traffic secrets. `VerifyDataCheck`
and the `cf_vd`/`sf_vd` decode futures are not used in the 1.3 path.

## 6. Transcript parsing and verification (`TlsTranscriptBuilder`)

`TlsTranscriptBuilder` gains a TLS 1.3 path, selected by the
`supported_versions` extension in ServerHello. The builder gets a new optional
input:

```rust
pub fn handshake_secrets(mut self, c_hs: [u8; 32], s_hs: [u8; 32]) -> Self
```

(prover passes its captured values; verifier passes the publicly decoded
values from §5 — ordering of finalization steps changes accordingly, see §8).

### 6.1 Record stream structure

```
sent:  CH | CCS(ignored) | [hs-epoch: Finished]                  | [app epoch: app records...]
recv:  SH | CCS(ignored) | [hs-epoch: EE, Cert, CV, Finished]    | [app epoch: NST*, app records...]
```

- Sequence numbers restart at 0 per epoch and per direction.
- All encrypted records have outer type `application_data(23)` and
  `legacy_record_version = 0x0303`; the real content type is the last
  non-zero byte of the decrypted inner plaintext (zero padding follows it).
- There is no explicit nonce: `nonce = write_iv XOR (0^4 || seq_be64)`.

### 6.2 Handshake processing (both parties, in the clear)

1. Parse CH and SH from plaintext records. Enforce: negotiated suite is
   `TLS13_AES_128_GCM_SHA256`; no `pre_shared_key` in SH (§6.5); no HRR
   (a SH with the special HRR random ⇒ `TlsTranscriptError`).
2. Compute `h2 = H(CH..SH)`.
3. Decrypt the server handshake-epoch records with `s_hs` (AES-128-GCM in the
   clear, 5-byte AAD, implicit nonce). **Tag failure ⇒ hard error.** Strip
   padding/inner type, reassemble the handshake message stream:
   EncryptedExtensions, Certificate, CertificateVerify, Finished
   (CertificateRequest ⇒ unsupported in v1, error).
4. Decrypt the client Finished record with `c_hs` the same way.
5. Verify CertificateVerify: signature scheme ∈
   { `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256` } over
   `0x20×64 || "TLS 1.3, server CertificateVerify" || 0x00 || H(CH..Certificate)`.
6. Verify server Finished: `HMAC(finished_key(s_hs), H(CH..CertificateVerify))`,
   and client Finished: `HMAC(finished_key(c_hs), H(CH..server Finished [+ CR/Cert as applicable]))`.
7. Compute `h3 = H(CH..server Finished)`.

Steps 3–6 require a cleartext AES-GCM + HKDF implementation in `tlsn-core`
(RustCrypto `aes-gcm`, `hkdf`/`hmac` crates; `ring` is also already in the
dependency tree via the rustls fork).

### 6.3 `CertBinding::V1_3` and `HandshakeData::verify`

```rust
pub struct CertBindingV1_3 {
    /// Transcript hash H(CH..Certificate) — the CertificateVerify input.
    pub cv_transcript_hash: [u8; 32],
    /// Signature scheme used in CertificateVerify.
    pub sig_scheme: SignatureScheme13, // ecdsa_secp256r1_sha256 | rsa_pss_rsae_sha256
}
```

`HandshakeData { certs, sig, binding }` is reused; `sig` stores the
CertificateVerify signature. `HandshakeData::verify` for `V1_3`:

1. Verify cert chain to roots at `time` (existing webpki path).
2. Reconstruct the signed message from `cv_transcript_hash` (step 5 above) and
   verify `sig` with the end-entity key.

The binding of `cv_transcript_hash` to the actual session is established
*online* by the verifier (it recomputed the hash from wire bytes itself). An
offline attestation verifier trusts the notary for this linkage — the same
trust shape as `V1_2`, where the notary attests `server_ephemeral_key`.

The `ServerEphemKey`-based signature of `HandshakeData::verify` changes:
`server_ephemeral_key` is meaningless in 1.3 (it does not participate in
authentication). The parameter becomes version-dependent (e.g. move it into
`CertBinding::V1_2`'s verification path only).

### 6.4 `Record` list for the ZK record proofs

Only **application-epoch** records enter `TlsTranscript::{sent, recv}`:

- The "first record is the Finished record" invariant
  (`validate_finished_record`) applies to V1_2 only. For V1_3 the lists start
  at app-epoch `seq = 0` and handshake-epoch records are *not* present (they
  are fully verified in the clear, nothing to prove in ZK).
- `Record.explicit_nonce` is empty for V1_3; the nonce is derived from
  `seq` + the in-VM IV (§7). (`Option`alizing or documenting the field —
  implementation detail.)
- `Record.typ` for V1_3 carries the **inner** content type. NewSessionTicket
  records (inner type `handshake`) and alerts stay in the list (their tags are
  proven like any other record, keeping the seq sequence contiguous) but are
  excluded from `to_transcript()` (already filtered to `ApplicationData`).
- `Record.ciphertext` excludes the auth tag (as today) but **includes** the
  inner content-type byte and any padding; consequently
  `ciphertext.len() = inner_plaintext.len()`, and the app-data plaintext
  carried in `Record.plaintext` covers `ciphertext[..len-1-padding]`. v1
  simplification: require zero padding from our own client (rustls default)
  and tolerate server padding by treating `plaintext = inner_plaintext` with
  the trailing `type || 0^pad` bytes appended as known-public suffix (§7.2).

### 6.5 Mandatory rejections (verifier)

- `pre_shared_key` extension accepted by the server (PSK has no
  CertificateVerify ⇒ no server authentication for our purposes).
- HelloRetryRequest (v1).
- KeyUpdate observed in either direction (key epoch would advance and
  invalidate the single-epoch ZK key references).
- CertificateRequest (client auth in 1.3 changes the Finished transcript; v1).
- Handshake-record AEAD tag failures, cert chain failures, CertificateVerify
  or either Finished mismatch: all hard errors.

## 7. Record-layer ZK proofs

### 7.1 Nonce construction (`components/cipher`)

`Aes128`'s CTR block circuit hardcodes `iv(4, secret) || explicit_nonce(8,
public) || counter(4, public)`. TLS 1.3 needs
`(iv(12, secret) XOR seq_pad(12, public)) || counter(4, public)`.

Extension: a new block allocation variant (new `AES128_POST_KS`-style circuit
or a VM-level XOR of the 12-byte secret IV reference with a public 12-byte
per-record value before the AES call — bitwise XOR with a public operand is
free in the circuit representation). API sketch:

```rust
fn alloc_ctr_block_xor_nonce(&mut self, vm) -> Result<CtrBlockXor<...>>;
// assign(vm, seq_pad: [u8; 12], counter: [u8; 4])
```

Used by both `verify_tags` (j0: counter = 1) and the keystream proofs
(counter ≥ 2). `AES_GCM_START_COUNTER = 2` is unchanged.

### 7.2 Tag verification (`crates/tlsn/src/tag.rs`)

- Add `make_tls13_aad` to `tls-core` (5 bytes:
  `0x17 || 0x0303 || (ciphertext_len + 16)`); `verify_tags` branches on
  `TlsVersion` for both AAD and j0 nonce construction. The
  `TlsVersion::V1_3 => ProtocolVersion::TLSv1_3` arm in `tag.rs` is currently
  dead code and wrong for AAD purposes (1.3 AAD uses `0x0303` on the wire);
  the branch keys off the version enum, not the wire version constant.
- GHASH itself is unchanged (`ghash.rs`).

### 7.3 Plaintext proofs (`transcript_internal`, prover `prove.rs` / verifier `verify.rs`)

The AES-CTR keystream consistency proofs change only in nonce construction
(§7.1). Plaintext layout: the proven plaintext for each record is the inner
plaintext (`content || type || padding`); the trailing `type || padding` bytes
are public (the verifier learned the inner type when checking lengths —
actually the inner type of records whose plaintext is *not* disclosed is
unknown to the verifier). Resolution for v1: the prover additionally commits
the final byte (+ padding length implicitly via record bookkeeping) as a
**disclosed** suffix of each record — record types are metadata, not
application content; this matches the verifier's 1.2 knowledge (record types
visible on the wire). The application transcript ranges
(`Transcript`/`PartialTranscript` indexing) count only `content` bytes, so
range math in `to_transcript()` and commitment range mapping must subtract the
suffix per record.

## 8. Prover/verifier finalization flow changes (`crates/tlsn/src/proxy/`)

### Allocation timing

`alloc_proxy_refs` runs before the connection, when the negotiated version is
unknown. v1 approach: **allocate both graphs** (TLS 1.2 `Prf` + `KeySchedule13`;
the unused one is simply never flushed/executed — verify with the QuickSilver
VM that unexecuted allocations are free or cheap). If preprocessing cost is
measurable, fall back to a per-session `tls_version` knob in
`TlsClientConfig`. Decision gate: harness benchmark (§9).

Integration notes from the implemented `KeySchedule13` (work item 2):

- The graph is allocated eagerly in `alloc(vm, hs)`; unexecuted allocations
  are the only cost when 1.2 is negotiated.
- Drive it like `Prf`; constant-message nodes are assigned on the first
  `flush`, and the schedule reaches `Complete` only after both `set_sh_hash`
  and `set_sf_hash` plus a flush. Setter order is not enforced.
- Nothing is decoded inside the component: the verifier-side public decode of
  `c_hs`/`s_hs` (the §5 disclosure step) and the prover-side assert against
  `SecretLog` are the caller's `vm.decode` calls in §8's flows.

### Prover (`ProxyProver::finalize`)

```
1. Parse plaintext CH/SH from TlsBytes → h2.
2. Assign + commit handshake_secret; set_sh_hash(h2); flush
   → c_hs/s_hs decoded (must equal SecretLog values; assert).
3. Build TlsTranscript with handshake_secrets(c_hs, s_hs)
   → decrypts handshake, verifies CV/Finished, yields h3, CertBindingV1_3,
     app-epoch records.
4. set_sf_hash(h3); flush → key references complete.
5. (No VerifyDataCheck.)
```

### Verifier (`ProxyVerifier::finalize`)

```
1. Parse plaintext CH/SH from recorded wire bytes → h2 (own computation).
2. commit(HS blind); set_sh_hash(h2); flush → learns c_hs/s_hs from public decode.
3. Build TlsTranscript with handshake_secrets(c_hs, s_hs) from its own wire
   bytes → AEAD-checks, cert chain + CertificateVerify + Finished verification,
   h3, CertBindingV1_3.
4. set_sf_hash(h3); flush → blind key references for record proofs.
```

Note the order inversion versus 1.2 (ZK phase 1 now precedes transcript
building, because handshake decryption needs the disclosed secrets).

`verifier/verify.rs` replaces the hardcoded `CertBinding::V1_2` match with a
version dispatch calling the V1_3 `HandshakeData::verify` path (§6.3).

### Client config (`prover/client/proxy/mod.rs`)

- `with_protocol_versions(&[&TLS13, &TLS12])` (or per `TlsClientConfig`).
- Suite filter: add `SupportedCipherSuite::Tls13` matching
  `TLS13_AES_128_GCM_SHA256`.
- Key-exchange groups: secp256r1 stays mandatory for 1.2. For 1.3 the group
  never enters the attestation (authentication is CertificateVerify), so
  `X25519` MAY be enabled for 1.3 to reduce HRR; v1 keeps secp256r1-only for a
  smaller diff, revisit after HRR telemetry.
- Install the secret-capturing `CryptoProvider` + `SecretLog` (§4).

## 9. Work breakdown

| # | Item | Crate(s) | Notes |
|---|---|---|---|
| 1 | `SecretLog` + HKDF-capturing `CryptoProvider` | `tlsn` | §4; DONE (`prover/client/proxy/capture.rs` + `keylog.rs`; `CapturedSecrets` enum; `ProxyProver::finalize(CapturedSecrets)` with V1_3 error seam; bounded process-global `CapturePool`; 2 new tests incl. real 1.3 handshake capture; production still 1.2-only). See integration notes below. |
| 2 | `KeySchedule13` ZK graph + RFC 8448 vectors | `hmac-sha256` | §5; DONE (`src/key_schedule.rs`, 22/22 tests incl. RFC 8448) |
| 3 | XOR-nonce CTR block variant | `cipher` | §7.1; DONE (spec `specs/tasks/tls13-cipher-xor-nonce.md`; `src/aes/mod.rs`, 5/5 tests incl. NIST GCM KAT). See integration notes below. |
| 4 | `make_tls13_aad` | `tls-core` | DONE (`src/cipher.rs`, `fn make_tls13_aad(len) -> [u8; 5]`, len includes tag) |
| 5 | Cleartext 1.3 handshake decrypt/verify, `CertBindingV1_3`, builder 1.3 path, `Record` semantics | `tlsn-core` | §6; DONE (spec `specs/tasks/tls13-core-handshake.md`; 104/104 tests). See integration notes below. |
| 6 | `verify_tags` 1.3 branch | `tlsn` | §7.2; DONE (spec `specs/tasks/tls13-verify-tags.md`; `src/tag.rs` `TagKeyIv` enum, 4 new tests). See integration notes below. |
| 7 | Plaintext-proof suffix handling + range math | `tlsn` (`transcript_internal`) | §7.3; DONE (spec `specs/tasks/tls13-plaintext-proofs.md`; `CipherParams` enum + suffix/range math, 24 new tests). See integration notes below. |
| 8 | Prover/verifier finalize flows, config plumbing | `tlsn` | §8; spec `specs/tasks/tls13-finalize-flows.md`; **DONE (wiring)**: `ProxyKeys` versioned key handle (`TlsOutput.keys`); dual-graph allocation (`Prf` + `KeySchedule13`) in `alloc_proxy_refs`; reordered 1.3 finalize (schedule phase-1 discloses `c_hs`/`s_hs` → build transcript → phase-2 from `h3`) on both prover & verifier; `tlsn-core` accessors `peek_tls_version_and_sh_hash` + `TlsTranscript::tls13_{sh,sf}_hash`; version-dispatched `verify_tags` / `prove`/`verify` / `HandshakeData::verify` / cf-sf checks. New hermetic unit tests; 1.2 e2e (`test_proxy`) unchanged. **Deferred to item 9**: flipping the client version list to offer 1.3 (the shared fixture auto-negotiates 1.3) and the prover→verifier per-record content-length / inner-plaintext channel — both need the 1.3-enabled fixture. |
| 8b | TLS 1.3 record metadata channel + prover inner-plaintext recovery | `tlsn`, `tlsn-core` | §6.1/§7.3/open-q §5; spec `specs/tasks/tls13-record-metadata-channel.md`; depends on item 8 (DONE). **DONE**: `CapturedSecrets::V1_3` extended with the `CLIENT/SERVER_TRAFFIC_SECRET_0` app secrets; the builder decrypts the app-epoch records (`tls13_app_secrets`) to recover each inner plaintext and frame `Record.{typ,plaintext,content_len}` (new `Record.content_len`); the prover→verifier per-record `Tls13Metadata{sent,recv}` of `Tls13RecordMeta{typ,content_len}` is sent at finalize time over the shared proxy IO channel (`ctx.io_mut()`, between key-schedule phase 1 and phase 2) and the verifier reframes from it (`tls13_record_meta`); item 7's `alloc_suffix` generalized to the declared inner type with `RecordParams.{inner_type,is_app_data}`; locked §5 classification — `prove`/`verify` run the `type \|\| padding` suffix proof over **every** app-epoch record (`verify.rs`/`prove.rs` no longer filter to `ApplicationData` for 1.3), NSTs/KeyUpdates/alerts keep their content blind but are still suffix-proven, and `content_len()` now uses the validated per-record lengths. New hermetic unit tests (prover recovery incl. NST + padded record, `Tls13Metadata` round-trip + verifier framing match, generalized `0x16` suffix pass/fail, content_len wiring, NST excluded from the app transcript); 1.2 paths byte-for-byte (`test_proxy` unchanged). **Gated on item 9**: live 1.3 e2e exercising the channel end-to-end (needs the 1.3-enabled fixture + version flip). |
| 9 | Fixtures + tests + bench + version flip | `server-fixture`, `harness`, `tlsn` | §9.1; spec `specs/tasks/tls13-e2e-fixture-bench.md`; depends on item 8b (DONE). **DONE (functional e2e)**: client version flip to `&[&TLS13,&TLS12]` (`prover/client/proxy/mod.rs`); version-configurable fixture `bind_with_versions` (`server-fixture`, now `with_no_client_auth` — see below); live prover↔verifier 1.3 e2e (`test_proxy_tls13`), 1.2-pinned `test_proxy`, and the negotiation matrix (`test_proxy_negotiation_matrix`) all green; webpki cert-chain happy path retired (real fixture chain verifies vs `CA_CERT_DER` in `test_proxy_tls13`/matrix) + a 1.3 wrong-root negative (`tlsn-core` `test_verify_v1_3_wrong_root`). **First live 1.3 run surfaced two cross-item integration bugs, both fixed:** (1) the shared fixture's optional client auth (`allow_unauthenticated` `WebPkiClientVerifier`) made the 1.3 server emit a `CertificateRequest`, which the item-5 builder rejects by design (§6.5) — fixed by dropping TLS-layer client auth from the fixture (no proxy/MPC test presents a client cert; rustls clients only send one on request, so 1.2/MPC/example behaviour is preserved); (2) with a default sig-alg set the RSA-cert fixture signed CertificateVerify with `rsa_pss_rsae_sha512`, which the item-5 builder rejects (§6.2 allows only the two SHA-256 schemes) — fixed by pinning the proxy client's offered signature schemes to `ecdsa_secp256r1_sha256` + `rsa_pss_rsae_sha256` (keeping `RSA_PKCS1_SHA256` in the verification-only `all` set for the cert chain). **Open-question §2 RESOLVED (item 9)**: the dual `Prf`+`KeySchedule13` allocation is **material** — it adds ~+2.25 s (~+150%, roughly 2.5×) to a 1.2 session's preprocessing (measured on the real `mpz_zk` VOLE backend via the e2e path; VOLE correlations are generated per allocated AND-gate regardless of execution). Decision: keep always-both as the negotiation default, **recommend a session-pinned `tls_version` knob** (offer + allocate one graph) as the opt-in optimization. **Deferred**: the §4 harness `tls_version` selector + 1.3 `metrics.csv` rows and the allocation knob itself — the harness needs Linux netns + `sudo` and does not run on the dev host (would ship unvalidated), and the real per-bench saving needs the cross-party allocation knob (item-8-level). See open-question §2 for the full table + rationale. |

Suggested order: 1 (DONE) → 2+4 (DONE) → 5 ∥ 3 (DONE) → 6 ∥ 7 (DONE) →
8 (DONE) → 8b (DONE) → **9** (unblocked now).

### Commit hygiene (rule)

**Commit every keypoint update.** Each completed work-item (a row in the table
above) lands as its own atomic commit — never batch several items into one, and
never leave a finished keypoint uncommitted. A keypoint commit bundles:

- the implementation,
- its tests,
- the matching task spec under `specs/tasks/`,
- and the relevant `Cargo.lock` slice (only the dependency lines that item adds).

Use a Conventional-Commits message scoped to the affected crate
(e.g. `feat(core): …`, `feat(hmac-sha256): …`, `chore(spikes): …`). This keeps
the branch reviewable and bisectable, with each commit building on its own.

### Integration notes from items 3 & 5 (as built)

- **Cipher package name is `tlsn-cipher`** (the lib is `cipher`, but `-p cipher`
  collides with the RustCrypto dev-dep; use `-p tlsn-cipher`). The TLS 1.3
  block methods live on `Aes128`: `set_iv_tls13(Array<U8,12>)`,
  `alloc_ctr_block_tls13(vm)`, `alloc_keystream_tls13(vm, len)`. The `N`
  generic of the returned `CtrBlock`/`Keystream` is now `Array<U8, 12>` and
  carries the **public `seq_pad`** (`0^4 || seq_be64`), assigned via the
  unchanged `Keystream::assign(vm, seq_pad, ctr)`. J0 = counter 1; keystream =
  counter from `AES_GCM_START_COUNTER` (2). Set `iv13` (and key) before alloc.
- **`HandshakeData::verify` signature** is now
  `verify<'k>(&self, verifier, time, server_ephemeral_key: impl Into<Option<&'k ServerEphemKey>>, server_name)`.
  Existing 1.2 callers passing `&key` keep compiling; the V1_3 path ignores it.
- **RSA-PSS in 1.3**: the pinned `rustls-webpki 0.103` exposes **only**
  `RSA_PSS_2048_8192_SHA256_LEGACY_KEY`, which is the correct verifier for
  `rsa_pss_rsae_sha256` (rsaEncryption SPKI key + RSA-PSS-SHA256 sig). The
  note in the item-5 task spec recommending a "non-legacy" constant is
  superseded: there is no such constant in this webpki, and the legacy one is
  correct.
- **`hkdf` crate not added** — HKDF-Expand-Label is implemented on `hmac`+`sha2`
  in `crates/core/src/transcript/tls/tls13.rs` (`pub(crate)`). `aes-gcm`/`aead`
  were promoted to normal deps of `tlsn-core`.
- **`h2`/`h3` are internal to `build_v1_3`** and not exposed on
  `TlsTranscript`. Item 8 needs `h2` (for `KeySchedule13::set_sh_hash`) and
  `h3` (for `set_sf_hash`) — add accessors or recompute in the finalize flow.
- **Finished accessors** (`client_finished`/`server_finished`/`cf_vd`/`sf_vd`/
  `sf_hash`) remain `-> &Record`/`Option` and are **TLS 1.2 only**, guarded by
  `debug_assert_eq!(version, V1_2)`. Item 8 must version-dispatch before
  calling them (the 1.3 path has no Finished records in `sent`/`recv`).
- **Item 7 still owns**: verifier-side inner content-type classification of
  app-epoch records and the `type || padding` suffix range math. Item 5 framed
  app-epoch `Record`s (empty `explicit_nonce`, per-epoch `seq` from 0,
  `ciphertext` includes inner type + padding, tag split off) and left
  `plaintext = None` on the verifier path with a contract comment at that seam.
- **Deferred to item 9**: the full webpki cert-chain happy-path test and a live
  TLS 1.3 wire capture (RFC 8448's 1024-bit/SAN-less cert is rejected by
  webpki). Item 5 validated decrypt/verify via synthetic RFC 8448 wire data
  plus `connection.rs` dispatch tests.

### Integration notes from items 1, 6 & 7 (as built)

- **Item 1 — secret capture (`tlsn`)**: `MasterSecretLog` is replaced by
  `SecretLog` in `crates/tlsn/src/prover/client/proxy/keylog.rs`, which yields
  `CapturedSecrets::{ V1_2 { ms: [u8;48] }, V1_3 { handshake_secret,
  client_hs_traffic_secret, server_hs_traffic_secret: [u8;32] } }`. The
  HKDF-capturing provider lives in `prover/client/proxy/capture.rs`; leaked
  (suite+wrapper) instances recycle through a process-global `CapturePool`
  (`OnceLock`) leased per connection. `mod client`/`mod proxy` were widened to
  `pub(crate)` so `CapturedSecrets` is nameable; `hmac`+`sha2` were added as
  `tlsn` deps. **Production still pins `with_protocol_versions(&[&TLS12])`** —
  the capturing 1.3 suite is in `cipher_suites` but never offered until item 8
  flips the version list.
- **Item 1 finalize seam**: `ProxyProver::finalize` now takes
  `CapturedSecrets` (was `Vec<u8>`). The `V1_2 { ms }` arm is the prior 1.2
  flow byte-for-byte; the `V1_3 { .. }` arm currently returns a typed
  `TlsnError` ("…not implemented (work-breakdown item 8)"). **Item 8 fills this
  arm** — and that is also where `with_protocol_versions` gains
  `&rustls::version::TLS13`. The `#[allow(dead_code)]` on the `V1_3` fields can
  be removed once item 8 consumes them.
- **Item 6 — `verify_tags` (`tlsn`)**: signature is
  `verify_tags(vm, key_iv: TagKeyIv, mac_key, records)` (the standalone
  `tls_version` arg was removed; it is derived from the variant).
  `TagKeyIv::V1_3` carries a temporary `#[allow(dead_code)]` to drop when
  item 8 constructs it.
- **Item 7 — plaintext proofs (`tlsn`)**: `prove_plaintext` / `verify_plaintext`
  take `cipher: CipherParams` (`V1_2 { iv:[u8;4] }` / `V1_3 { iv:[u8;12] }`).
  `RecordParams` gained `seq`/`inner_len`/`content_len`; **item 8b** added
  `inner_type`/`is_app_data` and threads the real per-record content lengths via
  `RecordParams::from_records` (prover: the decrypted `record.plaintext`/the
  framed `Record.content_len`; verifier: the prover-declared `Record.content_len`,
  validated by the suffix proof). `alloc_suffix` now assigns the declared inner
  type, and the suffix proof runs over **every** app-epoch record (locked §5
  classification) — non-app-data records (`is_app_data == false`) contribute no
  transcript content. The verifier length check routes through the
  `content_len()` helper in `verifier/verify.rs`, now using the validated
  per-record lengths instead of the wire over-estimate.

### 9.1 Test plan

- **Key schedule**: RFC 8448 ("simple 1-RTT") test vectors against
  `KeySchedule13` in the ideal VM, plus cross-check against `ring`/RustCrypto
  HKDF.
- **Transcript fixtures**: capture `tls_sent.bin`/`tls_recv.bin` 1.3
  equivalents from `tls-server-fixture` (enable 1.3 in the fixture's rustls
  server config); unit tests mirroring the existing builder tests, plus
  negative tests: wrong hs secret (tag failure), tampered CertificateVerify,
  PSK acceptance, KeyUpdate injection, padding handling, NewSessionTicket
  filtering.
- **End-to-end**: proxy-mode prover↔verifier integration test over 1.3;
  both-versions negotiation matrix (client offers {1.3,1.2} × server {1.3,
  1.2, both}).
- **Interop**: manual/CI runs against OpenSSL `s_server` and a public 1.3
  endpoint (middlebox-compat mode, multiple NSTs, padded records).
- **Bench**: add a 1.3 row to `crates/harness` `bench.toml`; compare
  preprocessing and finalization vs 1.2 (expect: finalization cheaper — no
  Finished ZK checks; preprocessing depends on the dual-allocation decision,
  §8).

## 10. Open questions

1. **`handshake_secret` capture**: ~~confirm the rustls `Hkdf` trait exposes
   enough~~ **RESOLVED** — spike passed on rustls 0.23.40
   (`specs/spikes/tls13-secret-capture-RESULTS.md`, runnable via
   `cargo run -p tls13-secret-capture`): the wrapper provider captures
   `handshake_secret` directly and the full §5 derivation chain was validated
   in cleartext against the keylog. No fork needed. The spike also confirmed
   the §5 math and the wasm build poses no incremental risk.
2. **Dual allocation cost** (both 1.2 and 1.3 graphs in the ZK VM):
   **MEASURED — the dual allocation is MATERIAL** (item 9). v1 ships
   **always-both** (`alloc_proxy_refs` allocates `Prf` + `KeySchedule13` because
   the negotiated version is unknown at preprocessing; only the negotiated graph
   is driven at finalize). Earlier assumption was "unexecuted allocations are
   ~free" — **the measurement refutes this**: the unused graph's gates are still
   *preprocessed*.

   **Measurement** (item 9, real `mpz_zk` VOLE backend over the in-memory e2e
   duplex; `test_proxy` pinned 1.2; always-both vs a PRF-only baseline that
   skips the 1.3 gate-producing allocations; 4 runs each, tight clustering):

   | allocation        | `preprocess()` flush | host-side `alloc()` |
   |-------------------|----------------------|---------------------|
   | PRF-only (1.2)    | ~1.47 s              | ~1.9 ms             |
   | always-both (v1)  | ~3.73 s              | ~7.2 ms             |
   | **Δ (1.3 graph)** | **+~2.25 s (~+150%)**| +~5 ms              |

   So the always-allocated `KeySchedule13` graph **roughly 2.5×'s the
   preprocessing of a 1.2-only session**. Root cause: the QuickSilver/VOLE
   prover's `vm.flush()` generates correlations **per allocated AND-gate**,
   independent of whether those gates' inputs are ever committed or the graph is
   ever executed online. `KeySchedule13` (~10 HMAC-SHA-256s) is comparable in
   AND-gate count to the 1.2 PRF graph, so allocating both ≈ doubles
   preprocessing. (Online/finalize cost is unaffected — the unused graph is never
   driven; only preprocessing pays.) The wall-times are host-specific, but the
   ratio is gate-count-driven and so transport-independent.

   **Decision / recommendation**: keep **always-both as the default** (it is the
   only correct choice when the client offers both versions and lets the *server*
   negotiate — the v1 proxy model, parent §2/§8), but because the tax is now
   quantified as material, **add a session-pinned `tls_version` knob** as the
   opt-in optimization: `None` = negotiate ⇒ allocate both (today's default);
   `Some(V1_2|V1_3)` = offer only that version on the client **and** allocate only
   that graph in `alloc_proxy_refs` on **both** prover and verifier (they must
   stay symmetric or the 2PC VMs desync). A pinned session then pays for one
   graph only (~1.5 s instead of ~3.7 s here). This knob is the recommended
   follow-up; it was **not** implemented in item 9 — see the harness note below.

   **Harness bench (deferred)**: the §4 harness `tls_version` selector + 1.3
   `metrics.csv` rows were **not landed**. The harness requires Linux network
   namespaces + `sudo` (`ip netns exec`, `crates/harness/runner/src/server_fixture.rs`)
   and does **not** run on the macOS dev host, so any harness wiring would ship
   unvalidated; additionally, a *per-bench* version selector against the shared,
   started-once fixture only yields the real preprocessing saving when paired with
   the cross-party allocation knob above (a larger item-8-level change). The open
   question is nonetheless resolved by the direct e2e measurement above, which is
   more precise than the harness proxy would be. Landing the `tls_version` knob +
   the harness selector + 1.3 bench rows is tracked as the recommended follow-up.
3. **HRR**: rejected in v1. If telemetry shows meaningful failure rates with
   secp256r1-only, either enable X25519 for 1.3 (no attestation impact) or
   implement the `message_hash` transcript-reset rule in the builder.
4. **`SessionKeys` shape**: ~~how the 12-byte IVs flow through `TlsOutput` to
   the record proofs without disturbing the MPC-mode 1.2 type~~ **RESOLVED** —
   item 8 introduced the `ProxyKeys` enum (`crates/tlsn/src/proxy.rs`):
   `V1_2(mpc_tls::SessionKeys)` keeps MPC mode's 1.2 type byte-for-byte (it is
   wrapped at `TlsOutput` construction), and `V1_3 { 16B keys + 12B IVs + GHASH
   key }` carries the 1.3 material. Helpers `recv_tag_key_iv()` /
   `sent_cipher_params()` / `recv_cipher_params()` / `server_write_mac_key()`
   produce the version-correct `TagKeyIv` / `CipherParams` so call sites never
   branch on the version. `mpc_tls::SessionKeys` is untouched.
5. **Padding from servers / record classification**: v1 treats `type ||
   padding` as a disclosed public suffix per record (§7.3). No application-data
   leakage concern from disclosing padding lengths (the verifier already sees
   record lengths on the wire; padding disclosure reveals the true content
   length — this weakens the padding's traffic-analysis purpose for the
   *verifier* only, who already relays the connection in proxy mode; accepted).
   **RESOLVED (classification, item 8b):** the verifier ZK-proves the inner type
   of **every** app-epoch record and classifies on the proven value — the
   prover-sent `(inner_type, content_len)` metadata is a hint the suffix proof
   validates, not trusted input. This prevents a prover from mislabeling an
   `application_data` record as `handshake`/`alert` to drop it and shift
   transcript positions. Cost: a few extra public-suffix bytes per NST
   (negligible). See `specs/tasks/tls13-record-metadata-channel.md` §5.

## 11. Explicitly unchanged

- Verifier proxy I/O loop, `InspectReader`, `TlsBytes` capture.
- GHASH computation, `AES_GCM_START_COUNTER`, QuickSilver VM setup.
- Attestation/commitment formats above `TlsTranscript` (ranges, hash
  commitments, selective disclosure) — they operate on the application
  transcript, which is version-agnostic, except for the range math in §7.3.
- TLS 1.2 paths, byte-for-byte.
