# Spike: capture `handshake_secret` from rustls for TLS 1.3 proxy mode

Status: Ready to execute
Parent spec: `specs/tls13-proxy.md` (§4 "Secret capture", §5 "ZK key schedule")
Type: Time-boxed feasibility spike (1–2 days). Code quality bar: prototype.
Deliverable: working spike crate + findings report. **No changes to existing crates.**

## 1. Context (read this first)

TLSNotary proxy mode (`crates/tlsn/src/prover/client/proxy/`) runs an
unmodified rustls `ClientConnection` on the prover and currently captures the
TLS 1.2 master secret via rustls's `KeyLog` (`keylog.rs`, label
`CLIENT_RANDOM`).

For TLS 1.3 the plan (parent spec §5) requires the prover to commit
**`handshake_secret`** (the HKDF-Extract output that sits above both the
handshake traffic secrets and the master secret) in a ZK proof. rustls's
`KeyLog` only emits *traffic* secrets
(`{CLIENT,SERVER}_HANDSHAKE_TRAFFIC_SECRET`, `{CLIENT,SERVER}_TRAFFIC_SECRET_0`)
— these cannot link the handshake epoch to the application epoch in ZK, so
they are not sufficient.

**This spike answers one question: can we reliably capture `handshake_secret`
from unmodified rustls (the version locked in this workspace) via a custom
`Hkdf` provider — or do we need a rustls fork?**

## 2. Verified facts (starting points, re-verify against the locked version)

The workspace locks `rustls 0.23.40` (`Cargo.lock`; `crates/tlsn/Cargo.toml`
uses features `["std", "tls12", "ring"]`). The following was verified by
reading the vendored `rustls 0.23.32` source — re-verify against 0.23.40
(`cargo vendor` or the local registry copy under
`~/.cargo/registry/src/*/rustls-0.23.*`):

1. `Tls13CipherSuite` has a public field `hkdf_provider: &'static dyn
   rustls::crypto::tls13::Hkdf`. The `Hkdf` and `HkdfExpander` traits
   (`src/crypto/tls13.rs`) are public and implementable.
2. The TLS 1.3 client key schedule makes these `Hkdf` calls on the negotiated
   suite's provider (`src/tls13/key_schedule.rs`), in order, for a non-PSK,
   non-ECH handshake:
   - `extract_from_zero_ikm(None)` — early secret
     (`KeySchedule::new_with_empty_secret`).
   - `extract_from_secret(Some(derived_salt), ecdhe_shared_secret)` —
     **the handshake secret** (`KeySchedule::input_secret`, called from
     `KeySchedulePreHandshake::into_handshake`; the client completes the key
     exchange itself in `src/client/tls13.rs` and passes the raw shared
     secret bytes). NOTE: `Hkdf::extract_from_kx_shared_secret` is NOT used
     in this path.
   - `extract_from_zero_ikm(Some(salt))` — master secret
     (`KeySchedule::input_empty`).
3. All `Derive-Secret` / traffic-secret expansions go through the
   `HkdfExpander` returned by those extract calls (`expand_block` /
   `expand_slice` with `info` slices that encode the `HkdfLabel` struct:
   length, `"tls13 " + label`, transcript-hash context). **Because our wrapper
   returns the expander, it observes every expansion including the label
   bytes and the transcript-hash context.**
4. The repo's test server `crates/tls-server-fixture` builds its
   `ServerConfig` with rustls defaults ⇒ it already accepts TLS 1.3. Only the
   proxy-mode *client* pins TLS 1.2 today.

Fact (3) gives a deterministic identification strategy: the extract call whose
returned expander is later asked to expand with label `"c hs traffic"` /
`"s hs traffic"` **is** the handshake-secret extraction. No call-order
heuristics, no keylog correlation needed for identification (the keylog is
used as *validation* instead). Bonus: the `info` of those expansions contains
`h2 = H(CH..SH)`, and the `"c ap traffic"` expansion on the master-secret
expander contains `h3 = H(CH..SF)` — both are inputs the parent spec needs
anyway.

## 3. Task

Create a new workspace crate `crates/spikes/tls13-secret-capture`
(`publish = false`, binary crate; add to the workspace `members` in the root
`Cargo.toml` — this is the only allowed edit outside the new crate).

### 3.1 Components to build

1. **`CapturingHkdf`** implementing `rustls::crypto::tls13::Hkdf`:
   - Delegates all crypto to the ring-backed implementation. Two options,
     pick whichever works: (a) wrap the `Hkdf` instance already referenced by
     `rustls::crypto::ring::default_provider()`'s
     `TLS13_AES_128_GCM_SHA256` suite, or (b) build one with
     `rustls::crypto::tls13::HkdfUsingHmac(&rustls::crypto::ring::hmac::HMAC_SHA256)`
     (check visibility in 0.23.40).
   - On `extract_from_secret(salt, ikm)`: record `(salt, ikm)` and the PRK
     (recompute `PRK = HMAC-SHA256(salt or 0^32, ikm)` with RustCrypto
     `hmac`/`sha2`), tag the record with a fresh `extract_id`, and return a
     **`CapturingExpander`** wrapping the delegate's expander.
   - `CapturingExpander` implements `HkdfExpander`; on every
     `expand_block`/`expand_slice` it records `(extract_id, info_concat)`
     and delegates.
   - Also wrap `extract_from_zero_ikm` (the master secret comes from there;
     its expander must be capturable too) and `expander_for_okm`.
   - Captures go into an `Arc<Mutex<CaptureLog>>` shared with the test
     harness.
2. **Provider assembly**: start from
   `rustls::crypto::ring::default_provider()`; replace the TLS 1.3 suite with
   a leaked copy whose `hkdf_provider` points at the `CapturingHkdf`:

   ```rust
   let suite: &'static Tls13CipherSuite = /* ring's TLS13_AES_128_GCM_SHA256 */;
   let captured = Box::leak(Box::new(Tls13CipherSuite {
       hkdf_provider: Box::leak(Box::new(CapturingHkdf::new(log.clone()))),
       ..*suite
   }));
   ```

   Restrict `cipher_suites` to this suite only and pin
   `with_protocol_versions(&[&rustls::version::TLS13])`.
   Document every place where 0.23.40 makes this awkward (private fields,
   non-`Clone` types, etc.) — that friction is a spike finding.
3. **`KeyLogCapture`**: a `KeyLog` impl recording **all** labels + client
   randoms (extend the pattern of
   `crates/tlsn/src/prover/client/proxy/keylog.rs`).
4. **Test harness** (`main.rs` or `#[tokio::test]`s):
   - Spin `tls_server_fixture::bind_test_server` on an in-memory duplex
     (mirror existing usage; `rg bind_test_server` for examples in the
     repo's tests) and connect a `ClientConnection` built from the capturing
     provider. Drive one HTTP request/response, then close.
   - The client side here can use `futures-rustls` or sync rustls over the
     duplex — whatever is fastest to wire up; this harness is throwaway.

### 3.2 Verification chain (the actual spike result)

After the connection closes, from the capture log alone:

1. Identify `handshake_secret`: the extract whose expander saw an expansion
   with `info` containing label `"tls13 c hs traffic"`. Extract `h2` from
   that same `info` (parse the `HkdfLabel` encoding: `u16` length, `u8`-len
   label, `u8`-len context).
2. Using RustCrypto (`hkdf`/`hmac`/`sha2`) — *not* the rustls delegate —
   recompute and assert:
   - `Derive-Secret(HS, "c hs traffic", h2) == keylog CLIENT_HANDSHAKE_TRAFFIC_SECRET`
   - `Derive-Secret(HS, "s hs traffic", h2) == keylog SERVER_HANDSHAKE_TRAFFIC_SECRET`
   - `derived = Derive-Secret(HS, "derived", H(""))`;
     `MS = HKDF-Extract(derived, 0^32)`; extract `h3` from the captured
     `"c ap traffic"` expansion info; assert
     `Derive-Secret(MS, "c ap traffic", h3) == keylog CLIENT_TRAFFIC_SECRET_0`
     and `Derive-Secret(MS, "s ap traffic", h3) == keylog SERVER_TRAFFIC_SECRET_0`.
3. Print a clear PASS/FAIL summary for each assertion.

Step 2 is exactly the ZK derivation graph from the parent spec §5 — passing
assertions validate both the capture mechanism *and* the spec's key-schedule
math in one shot. Cross-check the per-label derivations against RFC 8446 §7.1
and, ideally, one RFC 8448 test vector for the `Derive-Secret` helper itself.

### 3.3 Concurrency / production-shape question (answer in the report, code optional)

The provider is shared `&'static` state, but production needs per-connection
attribution. Evaluate (no full implementation required):

- (a) one leaked provider **per connection** (`Box::leak` of suite + wrapper
  per session — measure the leak size, judge acceptability), vs.
- (b) one global provider with a global capture log, attributing entries to
  connections post-hoc by matching derived handshake traffic secrets against
  that connection's keylog entries (which *are* keyed by `client_random`).

Recommend one for the production `SecretLog` (parent spec §4).

### 3.4 Stretch goal (only if time remains)

`crates/wasm` builds the prover for `wasm32-unknown-unknown`. Check whether
the capturing-provider approach compiles for that target with the provider
setup used there (which crypto provider does the wasm build use? `ring`'s
wasm support?). A compile check or a written analysis of the blocker is
enough.

## 4. Constraints

- Do NOT modify any existing crate (except adding the spike crate to the
  workspace `members` list).
- Do NOT add dependencies to existing crates. The spike crate may use:
  `rustls` (workspace version, `ring` feature), `tls-server-fixture`,
  `tokio`, `futures`, `futures-rustls`, RustCrypto `hkdf`/`hmac`/`sha2`,
  `hex`. Use workspace versions where defined.
- If the wrapper approach hits a hard wall (e.g. required types not
  constructible in 0.23.40), STOP building workarounds. Document the exact
  blocker (type, field, visibility) and assess the fallback: a minimal rustls
  fork exposing one hook in `KeySchedule::input_secret` — estimate the patch
  size by reading the source.

## 5. Deliverables

1. `crates/spikes/tls13-secret-capture` — running spike, all §3.2 assertions
   passing via `cargo run -p tls13-secret-capture` (or `cargo test -p ...`).
2. `specs/spikes/tls13-secret-capture-RESULTS.md` answering:
   - Does the capture work on the locked rustls version? (PASS/FAIL per
     assertion)
   - Exact construction friction encountered (fields, visibility, leaks).
   - Identification robustness: what happens with HRR, ECH, PSK paths —
     reasoning from source is fine (all three are out of scope/disabled in
     the parent spec, but note whether they would confuse the capture).
   - Per-connection attribution recommendation (§3.3) with rationale.
   - wasm finding (§3.4) or "not assessed".
   - Recommendation: wrapper provider vs rustls fork, with confidence level.
   - Any corrections needed to parent spec §4/§5 (e.g. if the rustls call
     path differs in 0.23.40 from the §2 description).

## 6. Success criteria

The spike is a **success** if either:
- all §3.2 assertions pass (wrapper approach is viable), or
- a precise, source-referenced blocker is documented with a sized fork
  fallback (wrapper approach is rejected with evidence).

The spike is a **failure** only if the question remains open.
