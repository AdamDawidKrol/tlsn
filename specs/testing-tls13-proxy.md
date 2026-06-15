# Testing TLS 1.3 in proxy mode

A reproducible guide for exercising the proxy-mode TLS 1.3 support (parent design
in `specs/tls13-proxy.md`; attestation extension in
`specs/tasks/tls13-proxy-attestation.md`).

Scope: **proxy mode only** (the verifier/notary relays the wire bytes and the
prover proves consistency in ZK). MPC-mode TLS 1.3 is out of scope. The only
supported 1.3 cipher suite is `TLS13_AES_128_GCM_SHA256`.

## Prerequisites

- A normal Rust toolchain; build with plain `cargo` from a real terminal.
- **Build note**: a transitive build script (`mpz-circuits-data`) writes into its
  own cargo checkout. Under a restricted sandbox (e.g. an agent sandbox) this
  fails with `PermissionDenied`; build/run unsandboxed there. In a normal
  terminal this is a non-issue.
- The fixture-based tests/examples need **no network**. The real-endpoint runs
  need outbound TCP 443.

## 1. Automated tests (fixture, deterministic — start here)

These spin the in-repo server fixture up in-process; no external server needed.
The proxy e2e tests are marked `#[ignore]`, so pass `--ignored`.

```bash
# Interactive proxy↔verifier 1.3 e2e (the canonical "does 1.3 work" test).
cargo test -p tlsn --test test test_proxy_tls13 -- --ignored

# All three proxy e2e tests at once: 1.2 (test_proxy), 1.3 (test_proxy_tls13),
# and the negotiation matrix (client offers both; server drives the version).
cargo test -p tlsn --test test test_proxy -- --ignored

# Attestation crate: version-agnostic cert binding + TLS 1.3 attestation/
# presentation (happy path + tampered-transcript-hash negative).
cargo test -p tlsn-attestation
cargo test -p tlsn-attestation --features fixtures --test api
```

Expected: all pass. The `api` target is gated on the `fixtures` feature, so the
V1_3 cases (`test_api_v1_3`, `test_api_v1_3_tampered_transcript_hash`) only run
with `--features fixtures`.

Relevant sources: `crates/tlsn/tests/test.rs`,
`crates/attestation/tests/api.rs`.

## 2. End-to-end examples (runnable, with output)

### 2a. Signed attestation over TLS 1.3 (recommended)

`attestation_proxy_tls13` runs prover + proxy-mode notary + presentation verifier
in one process and writes `example-json.{attestation,secrets,presentation}.tlsn`.

```bash
# Default: in-repo fixture pinned to TLS 1.3 (self-contained, no network).
cargo run -p tlsn-examples --example attestation_proxy_tls13
```

Expected output:

```
Notarization and presentation verified successfully!
Negotiated TLS version: V1_3
Authenticated server: test-server.io
```

Point it at a real, public TLS 1.3 endpoint with `SERVER_HOST` (Mozilla roots are
used automatically). With only `SERVER_HOST` set it reproduces the interactive
example's lvbet request (path + headers):

```bash
SERVER_HOST=betslips.lvbet.pl cargo run -p tlsn-examples --example attestation_proxy_tls13
```

Expected: `Negotiated TLS version: V1_3`, `Authenticated server:
betslips.lvbet.pl`, `Notarization and presentation verified successfully!`, then
the disclosed request + JSON response.

Overrides (env): `SERVER_HOST`, `SERVER_PORT` (default `443`), `SERVER_DOMAIN`
(default = host), `REQUEST_PATH`. Source:
`crates/examples/attestation/proxy_tls13.rs`.

### 2b. Interactive verification over TLS 1.3

`proxy_real` runs an interactive proxy session (no signed artifact) against a real
endpoint; it defaults to the public lvbet endpoint.

```bash
cargo run -p tlsn-examples --example proxy_real
```

Expected: `Negotiated TLS version: V1_3`, then the verified sent/received
transcript. Source: `crates/examples/proxy/proxy_real.rs`.

## 3. Pre-flight: will a given endpoint work?

The proxy client offers a deliberately narrow handshake. Before wiring an
endpoint into an example, emulate that exact handshake with `openssl` — if this
succeeds with no HelloRetryRequest and `Verify return code: 0`, the tlsn proxy
will negotiate 1.3 too:

```bash
openssl s_client -connect HOST:443 -servername HOST \
  -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups P-256 \
  -sigalgs "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256" </dev/null
```

Look for: `New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256`, a
`Peer signature type` of `ecdsa_secp256r1_sha256` or `rsa_pss_rsae_sha256`, and
`Verify return code: 0 (ok)`.

### Endpoint requirements (enforced by the proxy client)

- **TLS 1.3** with **`TLS13_AES_128_GCM_SHA256`** (the only 1.3 suite offered).
- **secp256r1 (P-256)** key exchange, with **no HelloRetryRequest** (the client
  offers only a P-256 key share; HRR is rejected by design). This is the most
  common failure mode for X25519-preferring servers.
- CertificateVerify signed with **`ecdsa_secp256r1_sha256`** or
  **`rsa_pss_rsae_sha256`** (an ECDSA cert must be on P-256).
- No PSK/session resumption, no client auth / `CertificateRequest`, no
  `KeyUpdate` (all rejected; resumption is disabled client-side).

Pinned in `crates/tlsn/src/prover/client/proxy/mod.rs`
(`ALLOWED_GROUPS`, `ALLOWED_SUITES`, `PROXY_SIG_ALGS`).

## 4. Confirming it really negotiated 1.3

Because the client offers both 1.3 and 1.2 (server-negotiated), always assert the
version rather than assuming. The verifier reads it from the wire bytes it
recorded:

```rust
verifier.tls_transcript().version()            // == TlsVersion::V1_3
verifier.tls_transcript().certificate_binding() // CertBinding::V1_3(_)
```

The examples and tests above already assert this.

## 5. What is not covered

- MPC-mode TLS 1.3 (out of scope).
- Harness benchmarks for 1.3 (`crates/harness` needs Linux netns + `sudo` and has
  no 1.3 rows; see `specs/tls13-proxy.md` open-question §2 for the direct e2e
  measurement instead).
