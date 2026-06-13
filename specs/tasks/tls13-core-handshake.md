# Task: Cleartext TLS 1.3 handshake decrypt/verify + `CertBindingV1_3` + builder 1.3 path (`tlsn-core`)

Parent spec: `specs/tls13-proxy.md` §6 (and §3 trust chain). Work-breakdown
item 5 — the largest single piece.
Scope: `crates/core` (`src/connection.rs`, `src/transcript/tls.rs`,
`src/transcript/tls/builder.rs`, a new cleartext-crypto submodule, `Cargo.toml`).
Independent of items 3/6/7; can be built in parallel with item 3.

## 0. Context

In TLS 1.2 proxy mode both parties parse the **plaintext** handshake from the
recorded wire bytes (`TlsTranscriptBuilder::parse_handshake_components`):
ClientHello/ServerHello/Certificate/ServerKeyExchange are in the clear, so the
builder extracts the cert chain, the SKE signature, both randoms
(`CertBinding::V1_2`), and computes `cf_hash`/`session_hash`/`sf_hash`.

In TLS 1.3 the handshake after ServerHello is **encrypted** under handshake
traffic keys. The design (parent §3–§5) is: the prover discloses the two
handshake traffic secrets `c_hs`/`s_hs`; **both** parties then decrypt the
handshake flight from their own copy of the wire bytes, AEAD-tag-check it,
verify the certificate chain + CertificateVerify + both Finished messages **in
the clear** (no ZK for the handshake), and record the application-epoch records
for the downstream ZK record proofs.

This task implements that cleartext path in `tlsn-core`. It does **not** touch
the ZK VM, the prover/verifier finalize flows (item 8), or the record-layer ZK
proofs (item 7).

## 1. Deliverables

A. `connection.rs`: `CertBindingV1_3`, `CertBinding::V1_3`, `SignatureScheme13`,
   and a version-aware `HandshakeData::verify`.
B. New cleartext crypto submodule: HKDF-Expand-Label, handshake-key derivation,
   AES-128-GCM record decryption (XOR nonce, `make_tls13_aad`, padding strip),
   `finished_key`, `verify_data`.
C. `TlsTranscriptBuilder` 1.3 path: version detection, `handshake_secrets()`
   input, `h2`, handshake-flight decryption + reassembly + verification, `h3`,
   `CertBindingV1_3`, cert chain, CV signature, app-epoch record framing.
D. `TlsTranscript` accessor guards so a 1.3 transcript (no Finished records in
   `sent`/`recv`) is well-formed.
E. Dependencies + tests (RFC 8448 known-answer for the crypto helper; builder
   tests gated on a 1.3 fixture coordinated with item 9).

## 2. `connection.rs`

### 2.1 New types

```rust
/// TLS 1.3 CertificateVerify signature scheme (the two we support).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme13 {
    EcdsaSecp256r1Sha256, // 0x0403
    RsaPssRsaeSha256,     // 0x0804
}

/// TLS 1.3 certificate binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBindingV1_3 {
    /// Transcript hash H(ClientHello .. Certificate) — the input the server
    /// signs in CertificateVerify (RFC 8446 §4.4.3).
    pub cv_transcript_hash: [u8; 32],
    /// Signature scheme used in CertificateVerify.
    pub sig_scheme: SignatureScheme13,
}
```

Add the variant (the enum is already `#[non_exhaustive]`):

```rust
pub enum CertBinding {
    V1_2(CertBindingV1_2),
    V1_3(CertBindingV1_3),
}
```

`HandshakeData { certs, sig, binding }` is reused. For 1.3, `sig` holds the
CertificateVerify signature bytes (`ServerSignature.sig`); `binding.sig_scheme`
is the authoritative scheme for verification. `ServerSignature.alg` is
informational for 1.3 — set it to the closest `SignatureAlgorithm`
(`ECDSA_NISTP256_SHA256` for ecdsa; for rsa_pss_rsae use
`RSA_PSS_2048_8192_SHA256_LEGACY_KEY` as a label or extend the enum — see note
below).

> **Note on RSA-PSS:** TLS 1.3 `rsa_pss_rsae_sha256` verifies with
> `webpki::ring::RSA_PSS_2048_8192_SHA256` (the **non-legacy-key** variant),
> whereas TLS 1.2's `rsa_pss_*` maps to the `*_LEGACY_KEY` algs. The V1_3
> verify path must pick the non-legacy alg from `sig_scheme`, independent of
> `ServerSignature.alg`. If you prefer a single source of truth, you may add
> non-legacy `RSA_PSS_2048_8192_SHA256` to `SignatureAlgorithm` and drop
> `sig_scheme` from the binding — but the parent spec keeps `sig_scheme`
> explicit; either is acceptable as long as verification uses the non-legacy
> RSA-PSS alg.

### 2.2 `HandshakeData::verify` version dispatch

The `server_ephemeral_key` parameter is meaningless for 1.3 (authentication is
the CertificateVerify signature over the transcript, not the kx params). Make
it optional and dispatch on `self.binding`:

```rust
pub fn verify(
    &self,
    verifier: &ServerCertVerifier,
    time: u64,
    server_ephemeral_key: Option<&ServerEphemKey>, // required for V1_2, ignored for V1_3
    server_name: &ServerName,
) -> Result<(), HandshakeVerificationError>
```

- **V1_2** arm: unchanged logic; `server_ephemeral_key` must be `Some` (else a
  new `HandshakeVerificationError` variant, e.g. `MissingEphemeralKey`).
- **V1_3** arm:
  1. Split certs, verify the chain to roots at `time` (existing webpki path,
     identical to V1_2).
  2. Reconstruct the signed message (RFC 8446 §4.4.3):
     ```
     message = 0x20 * 64
             || b"TLS 1.3, server CertificateVerify"
             || 0x00
             || binding.cv_transcript_hash
     ```
  3. Map `binding.sig_scheme` → webpki alg:
     `EcdsaSecp256r1Sha256 => webpki::ring::ECDSA_P256_SHA256`,
     `RsaPssRsaeSha256 => webpki::ring::RSA_PSS_2048_8192_SHA256`.
  4. `EndEntityCert::verify_signature(alg, &message, &self.sig.sig)`.

Add a `HandshakeVerificationError` variant for the missing-ephemeral-key case
and (optionally) a clearer error for unsupported 1.3 sig schemes.

Update the existing `connection.rs` unit tests to pass
`Some(data.server_ephemeral_key())` for the V1_2 cases. Add V1_3 verify tests
in §5.

## 3. Cleartext crypto submodule

New module (e.g. `crates/core/src/transcript/tls/tls13.rs`, or
`crates/core/src/connection/tls13_crypto.rs` — pick one and keep it
`pub(crate)`). Implement with RustCrypto crates already adjacent in the tree.

Add to `crates/core/Cargo.toml` `[dependencies]` (versions per workspace):
`aes-gcm` (already a `fixtures`/dev dep — promote to a normal dep or gate the
1.3 path behind a feature if you want to avoid always pulling it; simplest:
make it a normal dep), `hkdf = "0.12"`, `hmac = "0.12"`, `aead`. `sha2` is
already a dependency.

```rust
const HASH_LEN: usize = 32; // SHA-256

/// HKDF-Expand-Label (RFC 8446 §7.1).
/// HkdfLabel = u16(length) || u8(len)"tls13 "+label || u8(len)context.
fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8>;

/// Derive (write_key[16], write_iv[12]) from a traffic secret.
fn traffic_keys(secret: &[u8; 32]) -> ([u8; 16], [u8; 12]) {
    // key = HKDF-Expand-Label(secret, "key", "", 16)
    // iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
}

/// finished_key = HKDF-Expand-Label(secret, "finished", "", 32).
fn finished_key(secret: &[u8; 32]) -> [u8; 32];

/// verify_data = HMAC-SHA256(finished_key, transcript_hash).
fn verify_data(finished_key: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32];

/// Decrypt one TLS 1.3 record body (ciphertext incl. tag) into the inner
/// plaintext, returning (inner_content_type, content_bytes).
///
/// nonce = iv XOR (0^4 || seq_be64); aad = make_tls13_aad(record_body_len);
/// strip trailing zero padding; the last non-zero byte is the inner type.
fn decrypt_record(
    key: &[u8; 16],
    iv: &[u8; 12],
    seq: u64,
    record_body: &[u8], // ciphertext || 16-byte tag, as on the wire
) -> Result<(u8 /* inner type */, Vec<u8> /* content */), TlsTranscriptError>;
```

Use `tls_core::cipher::make_tls13_aad` (item 4) for the AAD. AEAD: `aes_gcm::Aes128Gcm`
with a 96-bit nonce. Tag failure ⇒ hard `TlsTranscriptError` (parent §6.5).

## 4. Builder 1.3 path (`builder.rs`)

### 4.1 New input

```rust
impl<'a> TlsTranscriptBuilder<'a> {
    /// Supplies the disclosed TLS 1.3 handshake traffic secrets used to
    /// decrypt the handshake flight. Ignored for TLS 1.2.
    pub fn handshake_secrets(mut self, c_hs: [u8; 32], s_hs: [u8; 32]) -> Self;
}
```

Store as `Option<([u8; 32], [u8; 32])>`.

### 4.2 Version detection

In `build()` / `parse_handshake_components`, determine the version from the
**ServerHello** `supported_versions` extension, not `legacy_version` (which is
`0x0303` even for 1.3). `tls_core` exposes
`ServerHelloPayload::supported_versions()` (returns the negotiated
`ProtocolVersion`). If it is `TLSv1_3` ⇒ take the 1.3 path; otherwise the
existing 1.2 path. Reject a ServerHello carrying the HelloRetryRequest special
random and any `pre_shared_key` server extension (parent §6.5) with a
`TlsTranscriptError`.

Branch `parse_handshake_components` into `parse_handshake_components_v1_2`
(today's logic, factored out unchanged) and `parse_handshake_components_v1_3`
(new).

### 4.3 1.3 handshake processing (`parse_handshake_components_v1_3`)

Inputs: parsed `sent_raw` / `recv_raw` records (`Vec<OpaqueMessage>`) and the
`handshake_secrets`. Steps (parent §6.2):

1. Extract plaintext ClientHello (first sent handshake record) and ServerHello
   (first recv handshake record). Enforce negotiated suite is
   `TLS13_AES_128_GCM_SHA256`; no PSK; no HRR.
2. `h2 = SHA256(CH_handshake_msg_bytes || SH_handshake_msg_bytes)` — the
   handshake-message bytes (the record payloads with the 4-byte handshake
   headers, **not** the 5-byte record headers). Middlebox-compat CCS records
   (`ChangeCipherSpec`, 1 byte) are ignored and excluded from the transcript
   hash.
3. Reassemble the **server** handshake-epoch ciphertext: the encrypted records
   after ServerHello (and the ignored CCS), each with outer type
   `application_data`. Derive `(s_key, s_iv) = traffic_keys(s_hs)`. For each
   such record at handshake-epoch `seq = 0, 1, …`, `decrypt_record`, append
   the `content` bytes to a server-handshake byte stream and track the inner
   type (must be `handshake`(22); a non-handshake inner type before Finished is
   an error). Stop after the server `Finished` message.
4. Parse the server stream into handshake messages with
   `HandshakeMessagePayload::read_version(.., ProtocolVersion::TLSv1_3)`:
   expect `EncryptedExtensions`, `Certificate(TLS13)`, `CertificateVerify`,
   `Finished` in order. `CertificateRequest` ⇒ unsupported-in-v1 error.
   (`tls_core::msgs::handshake::HandshakePayload` has
   `EncryptedExtensions`, `CertificateTLS13(CertificatePayloadTLS13)`,
   `CertificateVerify(DigitallySignedStruct)`, `Finished(Payload)`.)
5. Compute running transcript hashes over the concatenated handshake messages
   `CH || SH || EE || Cert` ⇒ `cv_transcript_hash = H(CH..Certificate)`;
   `H(CH..CertificateVerify)` for the server Finished check;
   `h3 = H(CH..server Finished)`.
6. Verify the server `Finished`:
   `verify_data(finished_key(s_hs), H(CH..CertificateVerify))` equals the
   Finished payload ⇒ else error.
7. Decrypt the **client** Finished record (first client handshake-epoch
   encrypted record after CH and the ignored CCS) with `(c_key, c_iv) =
   traffic_keys(c_hs)` at client-epoch `seq = 0`; verify
   `verify_data(finished_key(c_hs), H(CH..server Finished))`. (Client auth is
   rejected in v1, so the client transcript ends at the server Finished.)
8. Extract cert chain from `Certificate(TLS13)` (the entries' DERs, dropping
   the per-cert extensions). Map the CertificateVerify `SignatureScheme`
   (`ecdsa_secp256r1_sha256` / `rsa_pss_rsae_sha256`) to `SignatureScheme13`
   (other schemes ⇒ unsupported-in-v1 error). Build:
   - `server_cert_chain = certs`
   - `server_signature = ServerSignature { alg, sig }` from CertificateVerify
   - `certificate_binding = CertBinding::V1_3(CertBindingV1_3 {
       cv_transcript_hash, sig_scheme })`
9. Return `h2`/`h3` to the caller as needed. (Unlike 1.2 there is no
   `cf_hash`/`session_hash`/`sf_hash`; those builder outputs are `None` for
   1.3 — see §4.5.)

### 4.4 App-epoch record framing

Add `parse_records_tls13(records, app_data) -> Vec<Record>` (sibling of
`parse_records`). It frames **only application-epoch** records (parent §6.4):

- Skip the handshake-epoch records (CH/SH plaintext, the ignored CCS, and the
  encrypted handshake flight) already consumed in §4.3. The app epoch begins at
  the first encrypted record after the (client/server) Finished.
- Restart `seq` at 0 per epoch and per direction.
- Each app-epoch record becomes:
  ```rust
  Record {
      seq,
      typ,                         // see below
      plaintext,                   // see below
      explicit_nonce: Vec::new(),  // empty for 1.3
      ciphertext: body[..body.len() - 16].to_vec(), // includes inner type + padding
      tag: Some(body[body.len() - 16..].to_vec()),
  }
  ```
  i.e. `ciphertext` is the full inner ciphertext (so `ciphertext.len() ==
  inner_plaintext.len()`); the tag is the trailing 16 bytes. There is **no**
  8-byte explicit nonce to strip (contrast `split_into_record`).
- **`typ` and `plaintext`:**
  - The **inner content type** and content are only known after decryption.
    When `app_data` (the known inner plaintext, supplied by the prover that
    holds the application keys) is available, decrypt-classify is not needed
    here — instead the prover supplies, per record, the inner plaintext so the
    builder can set `typ` (last non-zero byte) and `plaintext` (content, i.e.
    inner bytes minus the trailing `type || padding`).
  - When `app_data` is absent (verifier before the ZK record proofs), set
    `plaintext = None` and `typ = ContentType::ApplicationData` provisionally;
    the authoritative inner-type classification and the
    `type || padding` suffix proof are **item 7** (parent §7.3). Document this
    clearly; do not attempt verifier-side decryption here.
- NewSessionTicket records (inner type `handshake`) and alerts stay in the list
  (their tags are proven in ZK to keep `seq` contiguous) but are excluded from
  `to_transcript()` — which already filters to `ApplicationData`.

> The precise `app_data`→record mapping for 1.3 (how the prover conveys inner
> plaintexts and how ranges subtract the `type||padding` suffix) is finalized
> in item 7. For item 5, define the framing and the `plaintext = None` /
> prover-supplied paths, and add a clear TODO/contract comment referencing
> item 7. Keep `to_transcript()` correct for the records it can see.

### 4.5 `build()` wiring

- Route to the 1.3 path when version is detected as `TLSv1_3` (or when
  `self.version == Some(V1_3)`), else the existing 1.2 path.
- For 1.3: `cf_hash = session_hash = None`, `sf_hash = None`. The
  `validate_finished_record` "first record is Finished" invariant is **1.2
  only** — skip it for 1.3 (the handshake-epoch records are fully verified in
  the clear and are not in `sent`/`recv`). Keep `validate_seq` (now per-epoch
  from 0).
- `certificate_binding` is `CertBinding::V1_3(..)` from §4.3.

## 5. `TlsTranscript` accessor guards (`tls.rs`)

The 1.2-only accessors `client_finished`, `server_finished`, `cf_vd`, `sf_vd`,
`sf_hash`, `cf_hash`, `session_hash` assume Finished records sit at
`sent[0]`/`recv[0]`. For 1.3 those records are not in the lists.

- Document all of the above as **TLS 1.2 only**.
- Change `client_finished` / `server_finished` from `-> &Record`
  (`.expect(...)`) to `-> Option<&Record>`, OR keep the signatures and add a
  `debug_assert!(self.version == TlsVersion::V1_2)` plus a panic message that
  names the version. Recommended: return `Option` and update the (few) 1.2
  call sites — cleaner and prevents 1.3 panics. (Call sites outside `core` are
  in `crates/tlsn` and are version-dispatched in item 8; coordinate the
  signature with that, or keep `&Record` + assert to minimize this task's blast
  radius. Either is acceptable; state which you chose.)
- `to_transcript()` is version-agnostic and already filters to
  `ApplicationData` — no change beyond the 1.3 records being framed correctly
  (§4.4). The §7.3 range/suffix math is item 7.

## 6. Tests

### 6.1 Crypto helper (self-contained, RFC 8448 known-answer)

Use the RFC 8448 "simple 1-RTT handshake" trace (it publishes the client/server
handshake traffic secrets, the encrypted EncryptedExtensions/Certificate/
CertificateVerify/Finished records, and the expected plaintexts):

1. `hkdf_expand_label` matches RFC 8448 intermediate values
   (`key`/`iv`/`finished` expansions).
2. `decrypt_record(s_key, s_iv, 0, server_record_0)` returns inner type
   `handshake` and the published EncryptedExtensions/… plaintext; padding
   stripped correctly.
3. Tag tamper ⇒ error.
4. `verify_data(finished_key(s_hs), H(CH..CertificateVerify))` equals the
   published server Finished verify-data.

### 6.2 `HandshakeData::verify` V1_3

Construct a `HandshakeData` with `CertBinding::V1_3` from a known 1.3 trace
(RFC 8448 uses a test cert that won't chain to Mozilla roots — either add it to
the test root store like the existing `appliedzkp` fixture, or capture a fresh
1.3 fixture from `tls-server-fixture`). Assert:

- valid CV + chain ⇒ `Ok`;
- tampered `cv_transcript_hash` ⇒ `InvalidServerSignature`;
- tampered `sig` ⇒ `InvalidServerSignature`;
- wrong server name / bad time ⇒ `ServerCert(_)`.

### 6.3 Builder 1.3 path

Needs a 1.3 wire fixture (`tls_sent.bin` / `tls_recv.bin` 1.3 equivalents) plus
the captured `c_hs`/`s_hs`. This couples to **item 9** (fixture capture). To
keep item 5 testable standalone, either:

- (preferred) capture a minimal 1.3 fixture now from `tls-server-fixture` with
  TLS 1.3 enabled (a few app records), commit it under
  `crates/core/src/transcript/fixtures/`, and write builder tests mirroring
  `test_parse_handshake` / `test_parse_app_records` / `test_parse_into_transcript`;
  or
- gate the full-builder integration test behind the item-9 fixture and land the
  §6.1/§6.2 known-answer tests now.

Builder assertions: `transcript.version() == V1_3`; cert chain non-empty and
matches the fixture server cert; `certificate_binding` is `CertBinding::V1_3`
with a non-zero `cv_transcript_hash`; app-epoch records have empty
`explicit_nonce`, contiguous per-epoch `seq` from 0, 16-byte tags;
`to_transcript()` yields the expected application bytes.

Negative builder tests (some may move to item 9): wrong `s_hs` ⇒ tag failure;
PSK accepted in SH ⇒ rejected; HRR ⇒ rejected.

## 7. Acceptance criteria

- `cargo test -p tlsn-core` passes, including the new 1.3 crypto-helper KATs,
  V1_3 `HandshakeData::verify` tests, and (fixture-permitting) builder tests;
  all existing 1.2 tests pass unchanged.
- `cargo clippy -p tlsn-core` clean; `cargo fmt` applied.
- Handshake AEAD tag failure, cert-chain failure, CertificateVerify mismatch,
  and either Finished mismatch are all hard errors (parent §6.5).
- Changes confined to `crates/core` (+ `Cargo.toml` deps). No ZK-VM, no
  `crates/tlsn` finalize-flow, no item-7 range math in this task — leave clear
  contract comments at the item-7 boundary (§4.4) and item-8 boundary (§5 call
  sites).
- `CertBinding`, `TlsTranscript`, and the builder remain byte-for-byte
  compatible for TLS 1.2.
```
