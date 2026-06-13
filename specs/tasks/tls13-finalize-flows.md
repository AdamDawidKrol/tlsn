# Task: TLS 1.3 prover/verifier finalize flows + config plumbing (`tlsn`)

Parent spec: `specs/tls13-proxy.md` §8 (and §4, §5, open-questions §2/§4).
Work-breakdown item 8 — the integration step that ties items 1–7 together into
a working end-to-end proxy-mode 1.3 handshake.
Scope: `crates/tlsn` (`src/proxy.rs`, `src/proxy/prover.rs`,
`src/proxy/verifier.rs`, `src/prover.rs`, `src/verifier.rs`,
`src/prover/client/proxy/mod.rs`, `src/prover/client/proxy/keylog.rs`), plus
small accessor additions in `crates/core` (§5).

## 0. Prerequisites and dependencies

This task assumes the following are merged into the working branch:

- **Item 1 — `SecretLog` + HKDF-capturing `CryptoProvider`** (parent §4). This
  is currently only a passing spike (`crates/spikes/tls13-secret-capture`); it
  must be productionized into `crates/tlsn/src/prover/client/proxy/keylog.rs`
  **before or as the first part of** this task. §3 below specifies the surface
  item 8 consumes; if item 1 is not yet done, build it first (it is small and
  self-contained — the spike validated the mechanism).
- **Item 2** `KeySchedule13` (`hmac_sha256`, DONE).
- **Item 5** `tlsn-core` 1.3 handshake/builder/`CertBinding::V1_3` (DONE).
- **Item 6** `verify_tags` `TagKeyIv` enum (`tag.rs`) — DONE on branch
  `maciej/tls13-verify-tags`. As built:
  `enum TagKeyIv { V1_2 { key: Array<U8,16>, iv: Array<U8,4> }, V1_3 { key: Array<U8,16>, iv: Array<U8,12> } }`,
  `verify_tags(vm, key_iv: TagKeyIv, mac_key, records)` (no `tls_version` arg;
  `V1_3` carries a temporary `#[allow(dead_code)]`).
- **Item 7** plaintext-proof `CipherParams` enum + suffix/range math
  (`transcript_internal`) — DONE on branch `maciej/tls13-plaintext-proofs`. As
  built: `enum CipherParams { V1_2 { key, iv: iv4 }, V1_3 { key, iv: iv12 } }`,
  `prove_plaintext(vm, cipher: CipherParams, plaintext, records, reveal, commit)`
  and verifier twin; `RecordParams` gained `seq` / `inner_len` / `content_len`
  (1.3 `content_len` falls back to `inner_len` until this task threads it);
  `verifier/verify.rs` got a `content_len()` length-check helper.

Both branches must be merged into the working branch before (or as part of)
this task. They touch disjoint files from each other and from item 8's primary
finalize files, so they merge cleanly.

## 1. Versioned key handle (`ProxyKeys`) — resolves open-question §4

`mpc_tls::SessionKeys` has 4-byte IVs and is shared with MPC mode (1.2 only) —
**do not change it**. Introduce a proxy-local versioned key handle, e.g. in
`crates/tlsn/src/proxy.rs`:

```rust
pub(crate) enum ProxyKeys {
    V1_2(mpc_tls::SessionKeys),               // 4-byte IVs
    V1_3 {
        client_write_key: Array<U8, 16>,
        client_write_iv: Array<U8, 12>,
        server_write_key: Array<U8, 16>,
        server_write_iv: Array<U8, 12>,
        server_write_mac_key: Array<U8, 16>,  // = AES_serverkey(0^16)
    },
}
```

Give it helpers that produce the item-6/item-7 inputs per direction:

```rust
impl ProxyKeys {
    fn recv_tag_key_iv(&self) -> tag::TagKeyIv;       // server key + iv (4B or 12B)
    fn sent_cipher_params(&self) -> auth::CipherParams; // client key + iv
    fn recv_cipher_params(&self) -> auth::CipherParams; // server key + iv
    fn server_write_mac_key(&self) -> Array<U8, 16>;
}
```

`TlsOutput.keys` becomes `ProxyKeys` (it is currently `mpc_tls::SessionKeys`).
Update `TlsOutput` and its consumers (`prover.rs`, `verifier.rs`) accordingly.

## 2. Client config (`prover/client/proxy/mod.rs`)

- **Protocol versions**: change
  `with_protocol_versions(&[&rustls::version::TLS12])` to
  `&[&rustls::version::TLS13, &rustls::version::TLS12]` (offer both; the server
  negotiates). Optionally make this a `TlsClientConfig` knob, but v1 can hard-code
  both.
- **Cipher-suite filter**: extend `ALLOWED_SUITES` handling so the
  `cipher_suites` filter also keeps the TLS 1.3 suite
  `TLS13_AES_128_GCM_SHA256`:
  ```rust
  .filter(|s| match s {
      SupportedCipherSuite::Tls12(t) => ALLOWED_SUITES.contains(&t.common.suite),
      SupportedCipherSuite::Tls13(t) => t.common.suite == CipherSuite::TLS13_AES_128_GCM_SHA256,
  })
  ```
- **Key-exchange groups**: keep `ALLOWED_GROUPS = [secp256r1]` for v1 (parent §8;
  X25519-for-1.3 is a later HRR-reduction option, no attestation impact).
- **Secret capture**: replace `MasterSecretLog` with item 1's `SecretLog` and
  install the secret-capturing `CryptoProvider` (the per-connection HKDF wrapper
  from §4/the spike). For 1.2 connections `SecretLog` still captures the 48-byte
  master secret via the `CLIENT_RANDOM` keylog hook; for 1.3 it captures
  `handshake_secret` + the two handshake traffic secrets (§3).
- Resumption stays `Resumption::disabled()`.

## 3. Captured-secret plumbing (`keylog.rs` + `poll`) — from item 1

Item 1 provides (parent §4):

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

`ProxyTlsClient::poll` (State::Connected, on `server_closed`) currently does
`let ms = self.ms_log.take()` and passes `Vec<u8>` to `prover.finalize(ms, ..)`.
Change it to take `CapturedSecrets` and pass that. The negotiated version is
available directly from the prover's rustls connection
(`self.conn.protocol_version()`), so the prover does **not** need to re-parse it
— pass it (or derive `CapturedSecrets`'s variant) from there. The
`FinalizeFuture` / `finalize` signatures change from `ms: Vec<u8>` to
`secrets: CapturedSecrets`.

## 4. Allocation: dual-graph in `alloc_proxy_refs` (`proxy.rs`)

`alloc` runs during preprocessing, **before** the connection, when the
negotiated version is unknown. v1 approach (parent §8, open-question §2):
**allocate both graphs**; only one is driven at finalize.

Change `alloc_proxy_refs` to allocate, in addition to today's `Prf` + cf/sf
`VerifyDataCheck`:

- `hs: Array<U8, 32>` marked `Private`/`Blind` per `ms_visibility`, then
  `KeySchedule13::alloc(vm, hs) -> ScheduleOutput13`.
- A 1.3 decrypt cipher + its GHASH key via `alloc_ghash_key` using
  `schedule_out.keys.server_write_key` (the 1.3 server key; note the cipher must
  use `set_iv_tls13(schedule_out.keys.server_iv)` only where an IV is needed —
  the GHASH key derivation `AES_K(0^16)` uses `alloc_block`, which needs only
  the key, so it works unchanged).
- Public decode futures for `schedule_out.c_hs` / `schedule_out.s_hs` (the §5
  disclosure mechanism): `vm.decode(c_hs)` / `vm.decode(s_hs)`.

`References` grows to carry both the 1.2 set (today's `ms`, `keys`, `cf_vd`) and
the 1.3 set (`hs`, `KeySchedule13` handle, `ScheduleOutput13` refs incl. the
12-byte-IV `SessionKeys13`, the 1.3 `server_write_mac_key`, and the
`c_hs`/`s_hs` decode futures). Both `Prf` and `KeySchedule13` live on the
`ProxyProver`/`ProxyVerifier` structs.

> The unused graph's allocations are the only preprocessing cost — confirm with
> the QuickSilver VM that unexecuted allocations are cheap (§9 decision gate).
> If measurably expensive, fall back to a `tls_version` knob on
> `TlsClientConfig` and allocate one graph; document the trade-off.

## 5. Small `tlsn-core` additions (fills item 5's deferred gap)

The 1.3 finalize flow needs `h2` **before** building the transcript (the
schedule must disclose `c_hs`/`s_hs` before decryption can happen) and `h3`
**after** (to finish the schedule). Item 5 kept these internal to
`build_v1_3`. Add to `crates/core`:

1. A pre-parse that yields the negotiated version and `h2` from the plaintext
   ClientHello/ServerHello without needing the handshake secrets — e.g. a free
   function `tlsn_core::transcript::peek_tls_version_and_sh_hash(tls_sent, tls_recv) -> Result<(TlsVersion, [u8; 32])>`, or a `TlsTranscriptBuilder` method. (The verifier has no rustls, so it relies on this; the prover may instead use `conn.protocol_version()` for the version and this for `h2`.)
2. An `h3` accessor on the built 1.3 transcript:
   `TlsTranscript::tls13_sf_hash() -> Option<[u8; 32]>` (and optionally
   `tls13_sh_hash()`), populated by `build_v1_3`. Keep these `Option`/1.3-only,
   alongside the existing 1.2-only `cf_hash`/`sf_hash`.

## 6. Prover finalize (`proxy/prover.rs`)

Branch on the negotiated version (from `CapturedSecrets` / `conn.protocol_version()`).
The 1.2 path is unchanged. The **1.3 path** (parent §8, note the order
inversion vs 1.2 — ZK phase 1 precedes transcript building):

```
1. (version, h2) = peek_tls_version_and_sh_hash(traffic.tls_sent, traffic.tls_recv)   // §5
2. let CapturedSecrets::V1_3 { handshake_secret, c_hs: cap_c_hs, s_hs: cap_s_hs } = secrets;
   vm.assign(refs.hs, handshake_secret); vm.commit(refs.hs);
3. ks13.set_sh_hash(h2);
   while ks13.wants_flush() { ks13.flush(vm); vm.execute_all(ctx).await; }
   c_hs = refs.c_hs_decode.try_recv()?;  s_hs = refs.s_hs_decode.try_recv()?;
   assert c_hs == cap_c_hs && s_hs == cap_s_hs;   // sanity; mismatch => error
4. tls_transcript = TlsTranscript::builder()
       .time(time).version(V1_3)
       .tls_sent(..).tls_recv(..).app_sent(..).app_recv(..)
       .handshake_secrets(c_hs, s_hs)
       .build()?;                          // decrypts hs flight, verifies CV + both Finished, yields h3, CertBindingV1_3, app-epoch records
5. h3 = tls_transcript.tls13_sf_hash().expect("1.3");
   ks13.set_sf_hash(h3);
   while ks13.wants_flush() { ks13.flush(vm); vm.execute_all(ctx).await; }
6. // No cf/sf VerifyDataCheck for 1.3.
   output = TlsOutput { keys: ProxyKeys::V1_3 { .. from refs ScheduleOutput13 + mac_key }, tls_transcript };
```

## 7. Verifier finalize (`proxy/verifier.rs`)

Mirror of §6 with `hs` **blind** (never assigned) and `c_hs`/`s_hs` learned
from the **public decode** (no assert):

```
1. (version, h2) = peek_tls_version_and_sh_hash(sent, recv)
2. vm.commit(refs.hs);                       // blind
3. ks13.set_sh_hash(h2); flush+execute loop; c_hs/s_hs = public-decode try_recv
4. tls_transcript = builder.handshake_secrets(c_hs, s_hs).tls_sent(sent).tls_recv(recv).build()?
                       // AEAD-checks from its own wire bytes; cert chain + CertificateVerify + both Finished
5. h3 = tls_transcript.tls13_sf_hash(); ks13.set_sf_hash(h3); flush+execute loop
6. output = TlsOutput { keys: ProxyKeys::V1_3 { .. }, tls_transcript }; return without cf/sf checks
```

The verifier's `finalize` currently returns the two `VerifyDataCheck`s. For 1.3
there are none; return `Option`s (or empty checks) and have the caller
(`verifier.rs`) skip `.check()` for 1.3 (§8).

## 8. Orchestration (`prover.rs`, `verifier.rs`)

Both call `verify_tags(..)` after finalize and run the transcript plaintext
proofs (`prove`/`verify`). Version-dispatch all of these off
`tls_transcript.version()` / `ProxyKeys`:

- **`verify_tags`** (item 6, as built): the signature is now
  `verify_tags(vm, key_iv: TagKeyIv, mac_key, records)` — the separate
  `tls_version` arg was removed (derived via `TagKeyIv::tls_version()`). Build
  `TagKeyIv::V1_3 { key, iv: server_iv12 }` from `ProxyKeys` (server side, for
  `tls_transcript.recv()`), plus `server_write_mac_key`. **Remove the
  `#[allow(dead_code)]` on `TagKeyIv::V1_3`** (item 6 added it because the
  variant was unconstructed until this task).
- **`prove` / `verify`** (item 7, as built; `prover/prove.rs` /
  `verifier/verify.rs`): the signature is now
  `prove_plaintext(vm, cipher: CipherParams, plaintext, records, reveal, commit)`
  (and the verifier twin). Build `CipherParams::V1_3 { key, iv12 }` from
  `ProxyKeys` for both sent (client) and recv (server) directions, replacing the
  `TODO(item 8)` `CipherParams::V1_2` stubs.
  - **Thread per-record `content_len` and `seq` into item 7's `RecordParams`
    for 1.3.** Item 7's `RecordParams::from_records` currently falls back to
    `content_len = inner_len` (correct only for 1.2) and is exercised only by
    unit tests that build `RecordParams` directly. For 1.3 the real values must
    flow from the `Record`s: `seq = record.seq`; `content_len =
    record.plaintext.len()` on the prover (content is known) and, on the
    verifier, the prover-declared content length validated by the suffix proof
    (parent §10 q5). Decide whether to extend `from_records` to read these from
    `Record` (it has `seq`; `content_len` needs the plaintext boundary) or to
    pass an explicit per-record length table; either way this is the bridge
    that makes item 7's 1.3 path actually run on real records.
- **`HandshakeData::verify` dispatch** (`verifier/verify.rs`, currently the
  hardcoded `CertBinding::V1_2` destructure ~lines 65–89): replace with a match
  on `tls_transcript.certificate_binding()` — V1_2 passes
  `Some(&binding.server_ephemeral_key)`, V1_3 passes `None` (item 5's
  `verify` takes `impl Into<Option<&ServerEphemKey>>`). (Item 7 also edits
  `verifier/verify.rs` for the §2.6 length check via a `content_len()` helper —
  build on that, don't duplicate it.)
- **cf/sf `VerifyDataCheck`**: only `.check()` them for V1_2 (1.3 has none).

## 9. Decision gate: dual-allocation cost (open-question §2)

Before finalizing the always-allocate-both approach (§4), add a `harness`
benchmark row (item 9) and compare preprocessing cost for 1.2-negotiated
sessions with vs without the extra `KeySchedule13` allocation. If the delta is
negligible (expected, since the unused graph is never executed), keep
dual-allocation. If not, switch to a `TlsClientConfig` version knob. Record the
measurement in parent spec open-question §2.

## 10. Tests

- **End-to-end proxy 1.3**: a prover↔verifier integration test over TLS 1.3
  against `tls-server-fixture` (1.3 enabled — coordinate with item 9, which owns
  the fixture/server config and bench). Assert: handshake verified, app
  transcript revealed/committed correctly, tags verified, `CertBinding::V1_3`
  produced, `server_name` returned.
- **Negotiation matrix**: client offers {1.3, 1.2}; server configured for
  {1.3-only, 1.2-only, both}; assert the negotiated version drives the correct
  graph and both succeed.
- **1.2 regression**: existing proxy-mode 1.2 e2e tests pass unchanged.
- **Negative**: tampered server Finished / CertificateVerify ⇒ verifier
  finalize errors (cleartext check); KeyUpdate or PSK acceptance ⇒ rejected
  (parent §6.5; some of these may live in item 5's builder tests).

Several of these depend on the item 9 fixtures/server; gate the full e2e behind
item 9 and land the unit-level wiring (config, dual-alloc, `ProxyKeys` mapping,
finalize branch compiles + drives the schedule) first.

## 11. Acceptance criteria

- `cargo build -p tlsn` and `cargo clippy -p tlsn --all-targets` clean;
  `cargo fmt` applied. (Note: the `mpz-circuits-data` build script writes
  outside the workspace — build/test may need unsandboxed permissions.)
- A TLS 1.3 proxy session completes end-to-end (gated on item 9 fixtures):
  dual-graph allocation, 1.3-reordered finalize (schedule discloses
  `c_hs`/`s_hs` → cleartext handshake decrypt/verify → `h3` → app keys),
  `verify_tags` + plaintext proofs over app-epoch records, `CertBinding::V1_3`
  verification, no Finished ZK checks.
- TLS 1.2 proxy behavior is unchanged (regression tests pass).
- `mpc_tls::SessionKeys` is untouched (MPC-mode 1.2 unaffected); the 12-byte IVs
  flow via `ProxyKeys` only.
- Open-question §2 (dual-allocation cost) and §4 (`SessionKeys` shape) are
  resolved in the parent spec with the chosen approach + the §9 measurement.
```
