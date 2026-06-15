# Task: TLS 1.3 signed attestations in proxy mode (`attestation`, `examples`)

Parent spec: `specs/tls13-proxy.md` (proxy-mode TLS 1.3, items 1–9 DONE).
This is the **follow-up "item 10"**: the parent spec stopped at the *interactive*
proxy-mode 1.3 e2e (`test_proxy_tls13`). The attestation/notary workflow
(`crates/attestation`, `crates/examples/attestation`) was never extended to 1.3 —
it is hardwired to TLS 1.2 (it stores a `server_ephemeral_key` field that a 1.3
session does not have) and the example notary rejects proxy mode.

Goal: let a **notary running in proxy mode** issue a **signed attestation** over a
**TLS 1.3** session, and let the prover build a verifiable **presentation** from
it — end to end, demonstrated by a runnable example and tests.

## 0. Why it doesn't work today

Two concrete blockers (verified against the current code):

1. **The attestation body can't represent a 1.3 binding.** `Body`
   (`crates/attestation/src/lib.rs`) has a *required*
   `server_ephemeral_key: Field<ServerEphemKey>`, and `AttestationBuilder::build`
   (`crates/attestation/src/builder.rs:158`) errors if it is unset. A 1.3 session
   has no server ephemeral key in its authentication path: 1.3 authenticates via
   the CertificateVerify signature over the handshake transcript hash
   (`CertBinding::V1_3 { cv_transcript_hash, sig_scheme }`, see
   `crates/core/src/connection.rs`). `HandshakeData::verify` already dispatches
   1.2-vs-1.3 and *ignores* the ephemeral key for 1.3.

2. **The example notary is MPC + 1.2 only.** `crates/examples/attestation/prove.rs`
   rejects `VerifierCommitStart::Proxy` (lines 304–310) and panics on any non-1.2
   binding (`let CertBinding::V1_2(binding) = … else { panic!() }`, line 368).

Everything *below* the attestation body is already version-aware: the proxy
verifier produces `transcript_commitments` for both versions
(`crates/tlsn/src/verifier/verify.rs`), the prover/verifier `tls_transcript()`
exposes `server_cert_chain()` / `server_signature()` / `certificate_binding()`
(the latter returns the version-agnostic `CertBinding`), and
`HandshakeData::verify` already has a working 1.3 path
(`verify_v1_3`, `crates/core/src/connection.rs`).

## 1. Trust model (what the notary must attest for 1.3)

In **1.2** the notary-attested anchor is `server_ephemeral_key`: the notary
witnessed it, it is stored as a public `Body` field, and at presentation-verify
time `verify_v1_2` checks the *withheld* `HandshakeData.binding`'s key equals the
attested key, then verifies the ServerKeyExchange signature over
`client_random || server_random || kx_params`.

In **1.3** the anchor must be `cv_transcript_hash` (+ `sig_scheme`): the proxy
verifier recomputes `cv_transcript_hash` itself from the wire bytes it recorded
(parent spec §6.3). So the notary attests the **`CertBinding`** it observed, and
at presentation-verify time we check the withheld `HandshakeData.binding` equals
the attested binding, then `verify_v1_3` verifies the CertificateVerify signature
over `cv_transcript_hash` against the (withheld) end-entity certificate.

The shape is identical to 1.2 ("notary attests the connection binding; the
withheld handshake data must match it and carry a valid signature"), so we
**generalize the attested field from `ServerEphemKey` to `CertBinding`**.

## 2. `tlsn-core` change (`crates/core/src/connection.rs`)

Add `PartialEq, Eq` to the binding types so the presentation can assert
"attested binding == opened binding":

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertBindingV1_2 { /* … */ }

// SignatureScheme13 already derives PartialEq, Eq.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertBindingV1_3 { /* … */ }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertBinding { V1_2(CertBindingV1_2), V1_3(CertBindingV1_3) }
```

(`ServerEphemKey` and `[u8; 32]` are already `PartialEq, Eq`, so this is just
adding the derives. No logic change.)

## 3. `tlsn-attestation` changes

### 3.1 Body field (`crates/attestation/src/lib.rs`)

Replace the ephemeral-key field with the version-agnostic binding:

```rust
pub struct Body {
    verifying_key: Field<VerifyingKey>,
    connection_info: Field<ConnectionInfo>,
    cert_binding: Field<CertBinding>,        // was: server_ephemeral_key: Field<ServerEphemKey>
    cert_commitment: Field<ServerCertCommitment>,
    extensions: Vec<Field<Extension>>,
    transcript_commitments: Vec<Field<TranscriptCommitment>>,
}
```

- `FieldKind::ServerEphemKey = 0x02` → rename to `FieldKind::CertBinding = 0x02`
  (keep the discriminant).
- `hash_fields` / the destructuring in it: swap `server_ephemeral_key` →
  `cert_binding` (keep it in the same hashed position).
- Accessor `server_ephemeral_key(&self) -> &ServerEphemKey` →
  `cert_binding(&self) -> &CertBinding`.
- Bump `VERSION` to `Version(1)` — the body layout/semantics changed. This
  changes 1.2 attestation bytes too; acceptable (in-repo crate is alpha
  `VERSION(0)`; production runs a separate released version — see parent spec
  context). Call this out in the commit message.

### 3.2 Domain separator (`crates/attestation/src/serialize.rs`)

`hash_fields` calls `hasher.hash_separated(&cert_binding.data)`, so add:

```rust
impl_domain_separator!(tlsn_core::connection::CertBinding);
```

(The `ServerEphemKey` separator may stay; it is still referenced by 1.2 internals
elsewhere — verify with the compiler and drop if unused.)

### 3.3 Builder (`crates/attestation/src/builder.rs`)

- Field `server_ephemeral_key: Option<ServerEphemKey>` → `cert_binding:
  Option<CertBinding>`.
- Setter `server_ephemeral_key(&mut self, key: ServerEphemKey)` →
  `cert_binding(&mut self, binding: CertBinding)`.
- In `build`, populate `Body.cert_binding` from `cert_binding.ok_or_else(…)`
  ("certificate binding was not set").

### 3.4 Identity proof (`crates/attestation/src/connection.rs`)

Change `ServerIdentityProof::verify_with_provider` to take the attested binding
and enforce the anchor for **both** versions:

```rust
pub fn verify_with_provider(
    self,
    provider: &CryptoProvider,
    time: u64,
    cert_binding: &CertBinding,               // was: server_ephemeral_key: &ServerEphemKey
    commitment: &ServerCertCommitment,
) -> Result<ServerName, ServerIdentityProofError> {
    // 1. commitment opening matches (unchanged)
    // 2. ANCHOR: the withheld handshake data must carry exactly the binding the
    //    notary attested.
    let data = self.opening.data();
    if data.binding != *cert_binding {
        return Err(/* ErrorKind::Certificate, "binding does not match attestation" */);
    }
    // 3. crypto verify; 1.2 needs the ephemeral key, 1.3 ignores it.
    let ephemeral = match cert_binding {
        CertBinding::V1_2(b) => Some(&b.server_ephemeral_key),
        CertBinding::V1_3(_) => None,
    };
    data.verify(&provider.cert, time, ephemeral, &self.name)?;
    Ok(self.name)
}
```

This keeps the 1.2 guarantee (verify_v1_2 still re-checks the key) and adds the
1.3 anchor (equality of `cv_transcript_hash`/`sig_scheme`, then signature check).

### 3.5 Presentation (`crates/attestation/src/presentation.rs`)

In `Presentation::verify`, pass the binding instead of the ephemeral key:

```rust
identity.verify_with_provider(
    provider,
    attestation.body.connection_info().time,
    attestation.body.cert_binding(),          // was: .server_ephemeral_key()
    attestation.body.cert_commitment(),
)
```

### 3.6 Fixtures + crate tests

Update every caller of the old API to the new one (mechanical):
`crates/attestation/src/fixtures.rs`, `crates/attestation/src/builder.rs`
(tests), `crates/attestation/tests/api.rs`,
`crates/attestation/tests/fixtures/generate_presentation_fixture.rs`. They
currently do `let CertBinding::V1_2(CertBindingV1_2 { server_ephemeral_key, .. })
= … ; builder.server_ephemeral_key(server_ephemeral_key)` — replace with
`builder.cert_binding(handshake_data.binding.clone())` (or the transcript's
`certificate_binding().clone()`).

Add a **new crate-level test** that builds + verifies an attestation/presentation
over a **`CertBinding::V1_3`** (synthesize a `HandshakeData` with a `V1_3` binding
the way the 1.2 fixtures synthesize a `V1_2` one; reuse the RFC-8448-style data or
the e2e fixture chain). Cover the negative: tampered `cv_transcript_hash` ⇒
verify fails (anchor or signature).

## 4. New example: proxy-mode notary, TLS 1.3 (`crates/examples`)

Add `crates/examples/attestation/proxy_tls13.rs`, registered in
`crates/examples/Cargo.toml` as example `attestation_proxy_tls13`. It runs all
three roles in-process (like the existing `proxy` example) and writes the same
`*.attestation.tlsn` / `*.secrets.tlsn` / `*.presentation.tlsn` artifacts, then
verifies the presentation.

Structure (reuse patterns from `crates/examples/proxy/proxy.rs` and
`crates/examples/attestation/{prove,present}.rs`):

1. **prover** (proxy mode): `ProxyTlsConfig` + `TlsClientConfig`; do the HTTP
   request; `TranscriptCommitConfig` (commit the whole transcript, no reveal);
   `prover.prove(&ProveConfig{ transcript_commit })` → `ProverOutput {
   transcript_commitments, transcript_secrets, .. }`; build the
   `AttestationRequest` with `server_name`, `handshake_data` from
   `prover.tls_transcript()` (`server_cert_chain()`, `server_signature()`,
   `certificate_binding().clone()` — now a `V1_3` binding), and
   `transcript_commitments`; send to notary; receive + `request.validate`; build
   the `Presentation`; verify it and print the disclosed transcript.

2. **notary** (proxy mode): accept `VerifierCommitStart::Proxy` and dial the
   server (reuse the `proxy` example's `TcpStream::connect` + `set_nodelay` +
   `run(server_socket)`); `verifier.verify().await?.accept().await?` → take
   `transcript_commitments`; build the attestation:

   ```rust
   let mut builder = Attestation::builder(&att_config).accept_request(request)?;
   builder
       .connection_info(ConnectionInfo { time, version, transcript_length })
       .cert_binding(tls_transcript.certificate_binding().clone())   // V1_3
       .transcript_commitments(transcript_commitments);
   ```

   **`transcript_length` for 1.3**: do **not** sum `record.ciphertext.len()` like
   the 1.2 example does — for 1.3 the ciphertext includes the inner
   `type || padding` suffix and the NST/alert records. Use the **content length**
   (`record.content_len` for app-data records; mirror `content_len(...)` in
   `crates/tlsn/src/verifier/verify.rs`). Getting this wrong makes the
   presentation's transcript-length check fail.

3. **Server**: default to the in-repo fixture pinned to 1.3
   (`tlsn_server_fixture::bind_with_versions(socket, TLS13_ONLY)`) so the example
   is deterministic and CI-able, using `CA_CERT_DER` roots. Optionally support a
   real endpoint via env (`SERVER_HOST`/`SERVER_PORT`/`SERVER_DOMAIN` +
   `RootCertStore::mozilla()`, gated on the `tlsn/mozilla-certs` feature already
   enabled for `tlsn-examples` in `crates/examples/Cargo.toml`) so it can be
   pointed at a public 1.3 site (cf. `crates/examples/proxy/proxy_real.rs`).

Assert in the example that the negotiated version is 1.3 (the notary's
`tls_transcript().version() == TlsVersion::V1_3` and `CertBinding::V1_3`), and
that `Presentation::verify` returns the expected server name + disclosed bytes.

## 5. Test plan

- `cargo test -p tlsn-attestation` — existing tests pass after the mechanical API
  migration; the **new V1_3 attestation/presentation** test passes (happy path +
  tampered-binding negative).
- `cargo run --example attestation_proxy_tls13` (fixture, 1.3) — produces the
  three artifacts and verifies the presentation; prints the disclosed transcript.
- Keep the MPC + 1.2 example (`attestation_prove`/`present`/`verify`) green after
  the `cert_binding` API change (update its notary to `.cert_binding(...)`).
- Existing proxy/MPC e2e (`crates/tlsn/tests`) unchanged.

## 6. Build/sandbox note

A transitive build script (`mpz-circuits-data`) writes into its own cargo
checkout, which fails under a restricted sandbox; build/run unsandboxed (or grant
filesystem write). Debug builds reuse the cached deps from the existing test runs.

## 7. Out of scope

- MPC-mode TLS 1.3 (parent spec §1 keeps it out of scope).
- Selective field disclosure in the attestation body (`BodyProof` still proves all
  fields).
- Changing the released/production attestation format compatibility story beyond
  the in-repo `VERSION` bump.

## 8. Commit hygiene

Two atomic commits (parent spec "commit every keypoint" rule):
1. `feat(attestation): version-agnostic cert binding (TLS 1.3 attestations)` —
   §2–§3 + fixtures/tests + the new V1_3 crate test + `Cargo.lock` slice.
2. `feat(examples): proxy-mode TLS 1.3 notary attestation example` — §4 + the
   `Cargo.toml` example registration.
