# Task: TLS 1.3 e2e — fixture, version flip, live tests, bench (`tlsn`)

Parent spec: `specs/tls13-proxy.md` §9.1, open-question §2.
Work-breakdown **item 9** — the final integration/validation layer. Items 1–8b
implemented the full proxy-mode TLS 1.3 stack but it has only ever run under
*hermetic unit tests*; **no live prover↔verifier 1.3 session has executed
end-to-end**. This task turns it on and proves it works, then benchmarks it.

Expect this to surface cross-item integration bugs (items 1–8b). Fixing wiring
bugs **inside `crates/tlsn` / `crates/core`** is in scope; if a bug points at a
deeper design issue in a completed item, fix it minimally and call it out.

Scope: `crates/server-fixture/server` (the `bind` fixture used by the e2e
tests), `crates/tlsn/src/prover/client/proxy/mod.rs` (version flip),
`crates/tlsn/tests/` (e2e + negotiation matrix), `crates/harness` (bench).

## 0. Current state / why the version flip is delicate

- The proxy client pins TLS 1.2: `create_client_config`
  (`crates/tlsn/src/prover/client/proxy/mod.rs`) calls
  `with_protocol_versions(&[&rustls::version::TLS12])`. Item 8 left this 1.2-only
  on purpose; the capturing 1.3 suite is already in the provider's `cipher_suites`
  (item 1/8).
- The e2e fixture `tlsn_server_fixture::bind`
  (`crates/server-fixture/server/src/lib.rs`) builds a **default**
  `ServerConfig` — which supports **both** 1.3 and 1.2. So the instant the client
  offers 1.3, rustls negotiates **1.3** for *every* test that uses `bind`,
  including the existing `test_proxy`. **The negotiated version is therefore
  controlled by the server in tests.** Item 9 must make the server version
  configurable so both 1.2 and 1.3 stay covered.

## 1. Client version flip (`prover/client/proxy/mod.rs`)

Change the protocol-version list to offer both, server-negotiated:

```rust
.with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
```

The suite filter already keeps `TLS13_AES_128_GCM_SHA256` (item 8) and
`ALLOWED_GROUPS = [secp256r1]` stays (parent §8). Confirm rustls offers the 1.3
suite + a `key_share`/`supported_versions` for secp256r1. Leave
`Resumption::disabled()`.

> Optional: a `TlsClientConfig` version-preference knob (default: offer both).
> Not required for v1 — the server side drives negotiation in tests — but add it
> if it makes the matrix cleaner. Document if you do.

## 2. Version-configurable fixture (`crates/server-fixture/server`)

Add a version-list parameter to the server so tests can pin negotiation:

- Add e.g. `bind_with_versions<T>(socket, versions: &[&'static rustls::SupportedProtocolVersion])`
  (or a small `FixtureConfig`), building the `ServerConfig` via
  `ServerConfig::builder()` → `with_protocol_versions(versions)` →
  `with_client_cert_verifier(..)` → `with_single_cert(..)`.
- Keep `bind(socket)` as a thin wrapper that offers **both** (current behavior),
  so non-version-sensitive callers are unchanged.
- Note the fixture uses `futures_rustls`' re-exported rustls — use
  `futures_rustls::rustls::version::{TLS12, TLS13}` to match its rustls version
  (this can differ from `crates/tlsn`'s rustls; keep them straight).

## 3. e2e tests (`crates/tlsn/tests/test.rs` + `utils.rs`)

Mirror the existing `#[ignore]`-gated `test_proxy` for 1.3. The proving/finalize
plumbing (`run_prover_proxy`, `run_verifier`, `finish_prover`) is version-agnostic
and should be reused as-is.

1. **Preserve 1.2 coverage**: update `test_proxy` so its server is pinned to
   **1.2-only** (`bind_with_versions(.., &[&TLS12])`), so it keeps exercising the
   1.2 path even though the client now offers both. (Its assertions are
   unchanged.)
2. **`test_proxy_tls13`**: server pinned **1.3-only** (`&[&TLS13]`); client offers
   both → negotiates 1.3. Assert: `server_name == SERVER_DOMAIN`; the revealed
   ranges (`0..10` sent/recv) match; and **assert the session is actually 1.3** —
   `verifier_output` / `tls_transcript` should expose `CertBinding::V1_3` (add a
   tiny accessor or check via the transcript's `version()` if not already
   reachable from the test). This is the canonical happy-path live 1.3 run.
3. **Negotiation matrix** (`#[ignore]`, table-driven): client offers both; server
   ∈ {both, 1.2-only, 1.3-only}; assert the negotiated version is {1.3, 1.2, 1.3}
   respectively and each session completes + reveals correctly. (When the server
   offers both, the client's `TLS13`-first preference yields 1.3.)
4. **webpki cert-chain happy path** (deferred from item 5): the 1.3
   `test_proxy_tls13` already drives `CertBindingV1_3::verify` against the
   verifier's `CA_CERT_DER` root store (`utils.rs` already trusts `CA_CERT_DER`).
   Assert it verifies; add a negative case if cheap (wrong root ⇒ verification
   error). This retires the item-5 deferral (RFC 8448's cert was webpki-rejected;
   the fixture cert chain is real and chains to `CA_CERT_DER`).

Run the live tests with `cargo test -p tlsn --test test -- --ignored`.

## 4. Bench (`crates/harness`) — also resolves open-question §2

Add a TLS 1.3 dimension to the bench so we can compare against 1.2 and measure
the dual-allocation cost (parent open-question §2):

- The harness drives a prover/verifier against the fixture
  (`crates/harness/core/src/bench.rs`, config in `crates/harness/bench.toml`).
  Add a way to select the TLS version per bench (e.g. a `tls_version` field on
  the bench/group, defaulting to 1.2), and have the harness pin the fixture
  server accordingly (reuse §2's `bind_with_versions`).
- Add 1.3 bench rows mirroring the existing `cable`/`mobile_5g`/`fiber` groups
  (or a single representative row) so `metrics.csv` gains 1.3 numbers.
- **Open-question §2 measurement**: compare *preprocessing* cost for a
  1.2-negotiated session **with** the always-allocated `KeySchedule13` graph
  (current, item 8) vs a hypothetical without it. Easiest proxy: report the
  preprocessing time/size delta the dual allocation adds. If negligible (expected
  — the unused graph is never executed), record "keep always-both" in parent
  open-question §2; if material, recommend the `TlsClientConfig` version knob and
  note it. Put the measurement + decision in the parent spec.

> If wiring a version knob through the harness is disproportionately large,
> land §1–§3 first (the functional e2e), then do the bench as a follow-up commit
> — but still record the open-question §2 decision from whatever measurement is
> feasible. Note any harness limitation in your report.

## 5. Acceptance criteria

- `cargo build`/`cargo clippy --all-targets` clean across touched crates; `cargo
  fmt` applied. (`mpz-circuits-data` build script writes outside the workspace —
  build/test may need unsandboxed permissions.)
- **1.2 unchanged**: `test_proxy` (now 1.2-pinned server) passes; `test_mpc`
  behavior unchanged; all existing unit tests pass.
- **Live 1.3 works**: `test_proxy_tls13` passes — a real prover↔verifier proxy
  session negotiates `TLS13_AES_128_GCM_SHA256`, the handshake/cert chain
  verifies (`CertBinding::V1_3` against `CA_CERT_DER`), tags verify, the app
  transcript is revealed/committed correctly, and `server_name` is returned.
- **Negotiation matrix** passes for all three server configurations.
- Bench has a 1.3 row (or a documented reason it's deferred), and parent
  open-question §2 is resolved with the measured dual-allocation cost.
- The work-breakdown table row 9 is marked done; note anything punted.

## 6. Notes / likely bug surface (first live 1.3 run)

These are the seams most likely to break when 1.3 runs end-to-end for the first
time; check them early:

- **Finalize-time metadata channel (item 8b)**: the prover sends `Tls13Metadata`
  over `ctx.io_mut()` between key-schedule phase 1 and phase 2, and the verifier
  reads it before building its transcript. Verify the send/recv ordering matches
  under the real mux (deadlocks/ordering bugs surface here, not in unit tests).
- **Prover app-key capture (item 8b/1)**: `CLIENT/SERVER_TRAFFIC_SECRET_0` must be
  captured for the *real* handshake (the capture pool attribution, item 1) and
  the app-record decryption must reproduce the inner plaintexts. A capture miss
  shows up as a transcript-build failure.
- **Dual-graph execution (item 8)**: only the negotiated graph is driven; confirm
  the 1.3 path's `KeySchedule13` flush/execute rounds interleave correctly with
  the metadata exchange and that the unused `Prf` graph stays unexecuted.
- **`h2`/`h3` peeking + record framing (items 5/8/8b)**: `peek_tls_version_and_sh_hash`
  and the app-epoch `seq`/epoch boundaries must match the live wire bytes
  (middlebox-compat CCS, NewSessionTickets after the handshake).
- **NST handling (item 8b)**: the fixture/rustls server typically sends
  NewSessionTickets right after the handshake — the canonical case for the §5
  "prove every record's inner type" path. This is the live exercise of that code.
