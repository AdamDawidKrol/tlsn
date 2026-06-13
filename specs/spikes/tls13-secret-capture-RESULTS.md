# Results: capture `handshake_secret` from rustls for TLS 1.3 proxy mode

Status: **COMPLETE — SUCCESS**
Spec: `specs/spikes/tls13-secret-capture.md`
Parent: `specs/tls13-proxy.md` (§4, §5)
rustls version verified against: **0.23.40** (workspace-locked; vendored source at
`~/.cargo/registry/src/index.crates.io-*/rustls-0.23.40`)

## TL;DR

The TLS 1.3 `handshake_secret` **can be captured reliably from unmodified
rustls 0.23.40** via a custom `rustls::crypto::tls13::Hkdf` provider wrapper. No
fork is needed. All §3.2 assertions pass:

```
[PASS] RFC 8448 self-check (Derive-Secret + HkdfLabel)
[PASS] Identify handshake_secret via "c hs traffic" expansion (extract_from_secret)
[PASS] Derive-Secret(HS, "c hs traffic", h2) == CLIENT_HANDSHAKE_TRAFFIC_SECRET
[PASS] Derive-Secret(HS, "s hs traffic", h2) == SERVER_HANDSHAKE_TRAFFIC_SECRET
[PASS] Captured master-secret extract PRK == recomputed MS
[PASS] Derive-Secret(MS, "c ap traffic", h3) == CLIENT_TRAFFIC_SECRET_0
[PASS] Derive-Secret(MS, "s ap traffic", h3) == SERVER_TRAFFIC_SECRET_0
OVERALL: PASS  (wrapper approach is viable on rustls 0.23.40)
```

Reproduce: `cargo run -p tls13-secret-capture` (exit 0 ⇔ all assertions pass).

**Recommendation: implement the production `SecretLog` with the wrapper provider,
not a rustls fork. Confidence: high.**

## 1. Does the capture work on the locked rustls version? (PASS/FAIL per assertion)

Yes. A throwaway crate `crates/spikes/tls13-secret-capture` installs a
`CapturingHkdf` (wrapping ring's `&'static dyn Hkdf`) into a `CryptoProvider`
built from `rustls::crypto::ring::default_provider()`, runs **one real TLS 1.3
HTTP exchange** against `tls_server_fixture::bind_test_server_hyper`
(`TLS13_AES_128_GCM_SHA256`, X25519), and then — *from the capture log alone* —
reconstructs the entire key schedule with RustCrypto (`hkdf`/`hmac`/`sha2`) and
checks it against rustls's own `KeyLog` output.

Captured values from a representative run (random per run):

| Value | Bytes |
|---|---|
| `handshake_secret` (HS) | `c98242048a75687eeea5a5d450967b5ec3b29cb054913ea5a410dc0337e9999f` |
| `h2 = H(CH..SH)` | `cbba10309e9f650279add67c892f38e9a36cf73bb350c6b674bcb88b23943cdc` |
| `derived` (HS→MS salt) | `d73927c9c259222f880b1a4ad7444a4063a37863be0e653536cec48685cd2559` |
| `master_secret` (MS) | `139d502193c84009988cbbc84dba4c63b9bb13b71dcc0cae931673b0aa458a0c` |
| `h3 = H(CH..SF)` | `9bbacd2335eae4e530b0e949d8ed14cd9d19074073606aff25c8799138c357db` |

### Assertion results

| # | Assertion | Result |
|---|---|---|
| 0 | RFC 8448 self-check: `early=HKDF-Extract(0,0)` and `Derive-Secret(early,"derived","")` match the published vectors | **PASS** |
| 1 | `handshake_secret` is identified deterministically as the `extract_from_secret` whose expander expands with label `"tls13 c hs traffic"` | **PASS** |
| 2 | `Derive-Secret(HS, "c hs traffic", h2) == CLIENT_HANDSHAKE_TRAFFIC_SECRET` (keylog) | **PASS** |
| 3 | `Derive-Secret(HS, "s hs traffic", h2) == SERVER_HANDSHAKE_TRAFFIC_SECRET` (keylog) | **PASS** |
| 4 | `derived = Derive-Secret(HS,"derived",H(""))`; `MS = HKDF-Extract(derived, 0^32)`; captured MS-extract PRK equals recomputed MS (bonus cross-check) | **PASS** |
| 5 | `Derive-Secret(MS, "c ap traffic", h3) == CLIENT_TRAFFIC_SECRET_0` (keylog) | **PASS** |
| 6 | `Derive-Secret(MS, "s ap traffic", h3) == SERVER_TRAFFIC_SECRET_0` (keylog) | **PASS** |

Assertions 2/3/5/6 are exactly the ZK derivation graph from parent spec §5, so
passing them validates **both** the capture mechanism *and* the spec's
key-schedule math.

### The capture log confirms the §2 call path verbatim

The wrapper observed (one HTTP GET; suffix calls are NST/resumption):

```
extract calls (13):
  #0  extract_from_zero_ikm(None)            -> early secret   (prk = 33ad0a1c… == RFC 8448 early secret, since IKM=0)
  #1  extract_from_secret(Some(32B), 32B)    -> HANDSHAKE SECRET  (salt = derived_early, ikm = X25519 shared secret)
  #5  extract_from_zero_ikm(Some(32B))       -> master secret  (salt = derived)
  #2..#12 expander_for_okm(...)              -> traffic-key / finished / resumption expanders

expand calls (key ones):
  owner #0  label "tls13 derived"      ctx 32B   (Derive-Secret(early,"derived",H("")))
  owner #1  label "tls13 c hs traffic" ctx 32B   <-- identifies #1 as HS; ctx = h2
  owner #1  label "tls13 s hs traffic" ctx 32B
  owner #1  label "tls13 derived"      ctx 32B   (Derive-Secret(HS,"derived",H("")))
  owner #5  label "tls13 c ap traffic" ctx 32B   <-- ctx = h3
  owner #5  label "tls13 s ap traffic" ctx 32B
keylog labels: [CLIENT_HANDSHAKE_TRAFFIC_SECRET, SERVER_HANDSHAKE_TRAFFIC_SECRET,
                CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, EXPORTER_SECRET]
```

Identification is **deterministic and needs no call-order heuristics**: the
unique `extract_from_secret` whose returned expander is later asked to expand
with `"tls13 c hs traffic"` *is* the handshake-secret extraction, and the
context bytes of that same expansion *are* `h2`. The PRK recorded for that
extract (`HMAC-SHA256(salt, ikm)`, recomputed by the wrapper) **is**
`handshake_secret` — confirmed because it then derives the keylog traffic
secrets exactly. The parent spec's "capture inputs and recompute" shape
(§4/§10.1) is therefore unnecessary: we get the secret itself with one HMAC.

## 2. Exact construction friction encountered (fields, visibility, leaks)

Two real frictions, both worked around without leaving the public API. **Both
mean the spec's §3.1 / §4 code sketches do not compile as written and need
amending** (see §7):

1. **`HkdfUsingHmac(&ring::hmac::HMAC_SHA256)` — option (b) — is NOT available.**
   `rustls::crypto::ring::hmac` is declared `pub(crate)` in 0.23.40
   (`src/crypto/ring/mod.rs:19`, gated on `any(test, feature="tls12")`), so
   `HMAC_SHA256` is not reachable from outside the crate. Only **option (a)**
   works: wrap the `&'static dyn Hkdf` already living in ring's
   `TLS13_AES_128_GCM_SHA256` suite, obtained via
   `rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.tls13().unwrap().hkdf_provider`.
   The `HkdfUsingHmac` / `HkdfExpanderUsingHmac` types and the `Hkdf` /
   `HkdfExpander` traits *are* public and implementable (`src/crypto/tls13.rs`),
   so wrapping is straightforward.

2. **`Tls13CipherSuite { hkdf_provider, ..*base }` does NOT compile.**
   The struct-update sketch in spec §3.1 fails because `Tls13CipherSuite.common`
   is a `CipherSuiteCommon`, which derives **no `Copy`/`Clone`**
   (`src/suites.rs:16`). Functional-update from `*base` (a `&'static` borrow)
   would have to *move* `common` out of a shared reference → `E0507`. Fix:
   reconstruct the suite field-by-field. Every field is individually `Copy` or a
   `&'static` reference, and all are `pub`:
   ```rust
   let suite: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
       common: CipherSuiteCommon {
           suite: base.common.suite,
           hash_provider: base.common.hash_provider,
           confidentiality_limit: base.common.confidentiality_limit,
       },
       hkdf_provider: capturing,          // &'static CapturingHkdf
       aead_alg: base.aead_alg,
       quic: base.quic,
   }));
   ```

Everything else is constructible and public:
- `Tls13CipherSuite.hkdf_provider: &'static dyn Hkdf` — **public field** ✓
  (`src/tls13/mod.rs:21`).
- `CryptoProvider` — public struct, all public fields; `default_provider()`
  returns it owned, so `provider.cipher_suites = vec![…]` just works
  (`src/crypto/mod.rs:184`). This is the *identical* pattern the existing proxy
  client already uses (`crates/tlsn/.../proxy/mod.rs:90`,
  `CryptoProvider { cipher_suites, .. }`).
- `SupportedCipherSuite::Tls13(&'static Tls13CipherSuite)` — public variant
  (`src/suites.rs:72`).
- `CipherSuiteCommon`, `Tls13CipherSuite`, `SupportedCipherSuite`,
  `rustls::Stream`, `rustls::client::ClientConnection`, `rustls::version::TLS13`,
  `rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError}`,
  `rustls::crypto::hmac::Tag` — all public.

**Leaks.** `hkdf_provider` requires `&'static`, and `CryptoProvider.cipher_suites`
requires `SupportedCipherSuite::Tls13(&'static Tls13CipherSuite)`. So the
wrapper *and* the patched suite must be `'static`. The spike uses `Box::leak`
for both (acceptable for a throwaway; see §4 for production handling). Per
leaked provider that is ~the patched `Tls13CipherSuite` (~80 B) + the boxed
`CapturingHkdf` (`&dyn` 16 B + `Arc` 8 B ≈ a 32 B allocation) + the `Arc`'d
capture log it pins alive.

**Harness friction (not a rustls finding).** `tls-server-fixture`'s TLS server
runs on `futures-rustls 0.25`, which depends on **rustls 0.22**, a *different*
crate instance from the workspace's rustls 0.23. The two interoperate fine over
the wire (it is just TLS), but it means the client side here cannot reuse
`futures-rustls` — it would build a 0.22 `ClientConfig` incompatible with our
0.23 provider/`Hkdf` impl. The spike therefore drives a **synchronous rustls
0.23 `ClientConnection`** (via `rustls::Stream`) on a dedicated OS thread over a
loopback `TcpStream`, while the fixture HTTP server runs on a tokio task. This
mirrors how production proxy mode already pumps an unmodified
`ClientConnection` itself (`read_tls`/`write_tls`), so it is representative.

## 3. Identification robustness: HRR / ECH / PSK / KeyUpdate

All three problem paths are out of scope / disabled in the parent spec
(§1 non-goals, §6.5 mandatory rejections). Reasoning from the 0.23.40 source on
whether they would *confuse the capture*:

- **PSK / resumption (`KeySchedule::new`/`From<KeyScheduleEarly>`):** with a PSK,
  the early secret comes from `extract_from_secret(None, psk)` instead of
  `extract_from_zero_ikm(None)`, and there is a binder-key expansion
  (`"res binder"`/`"ext binder"`). The *handshake-secret* extract is still the
  `extract_from_secret(Some(derived), ecdhe)` whose expander expands
  `"c hs traffic"`, so the identification rule still pinpoints HS correctly.
  But PSK changes early-secret provenance and the parent spec rejects PSK at
  verification anyway (§6.5), so this is moot. **No confusion of HS
  identification.** (Observed in this very run: the *server* issued
  NewSessionTickets, producing extra `"res master"`/`"resumption"` expansions on
  the master-secret expander — these are clearly distinguishable by label and do
  not touch the `"c hs traffic"` rule.)
- **HelloRetryRequest:** rustls feeds a synthetic `message_hash` into the
  transcript; the key-schedule *call shape* is unchanged (still one
  `extract_from_secret` for HS), so HS identification is unaffected — only `h2`
  would reflect the post-HRR transcript. Parent spec rejects HRR in v1.
- **ECH:** adds `extract_from_secret(None, client_hello_inner_random)` calls for
  the ECH confirmation secret (`"ech accept confirmation"` /
  `"hrr ech accept confirmation"`, `src/tls13/key_schedule.rs:215,949`). These
  are **additional** `extract_from_secret` calls — a naive "first
  `extract_from_secret`" heuristic *would* be fooled, but the spike's
  label-driven rule (expander expands `"c hs traffic"`) is **not**, because the
  ECH-confirmation expanders only ever expand the confirmation label. ECH is not
  enabled by the proxy client.
- **KeyUpdate:** post-handshake, derives the next app traffic secret via
  `derive_next` (`"traffic upd"`) on an `expander_for_okm`. It never produces a
  new `extract_from_secret`/`"c hs traffic"`, so HS identification is unaffected;
  the parent spec fails the connection on observed KeyUpdate (§6.5) for the
  separate reason that the ZK key references assume a single epoch.

**Conclusion:** the `"c hs traffic"` label rule is robust across all these
paths for *identifying* HS. The only path that changes *what HS is* (PSK/HRR
transcript) is rejected upstream.

## 4. Per-connection attribution recommendation (§3.3)

**Recommendation: option (a) — one provider per connection — with a bounded
"leak via recycling" pool. Confidence: high.**

Rationale:

- **Why not (b) (one global provider + post-hoc matching):** the wrapper's
  `&'static dyn Hkdf` is shared across *all* concurrent connections, so every
  extract/expand from every in-flight handshake interleaves into one capture
  structure behind a single global `Mutex`. That mutex is taken on *every* HKDF
  operation of *every* connection → a real contention point for a concurrent
  notary. Attribution then requires deriving each candidate connection's
  `c_hs`/`s_hs` from each `FromSecret` PRK + its `h2` and matching against that
  connection's keylog (which *is* keyed by `client_random`). It works (each
  connection's randoms ⇒ unique `h2` ⇒ unique `c_hs`), but it adds crypto +
  matching logic and an unbounded global log that must be pruned. Strictly more
  fragile than (a).
- **Why (a):** a per-connection wrapper gives **perfect, zero-ambiguity
  attribution** with no matching and no shared lock — each
  `ProxyTlsClient::new` builds its own `CapturingHkdf` + patched suite +
  `Arc<Mutex<CaptureLog>>`, exactly where the proxy client *already* customises
  the provider today (`crates/tlsn/.../proxy/mod.rs:90`). The capture is read
  out at finalization into `SecretLog` for that one connection.
- **The leak caveat (the one real cost of (a)):** rustls forces `&'static`, so a
  naive `Box::leak` per connection leaks ~120–250 B **permanently** per
  connection — unbounded growth for a long-lived notary, unacceptable as-is. Fix:
  keep a small **object pool** of leaked (suite + wrapper) instances sized to
  max concurrency; reset/drain each `CaptureLog` between connections. The leak
  is then `O(max concurrent connections)`, not `O(total connections)`. The only
  per-connection mutable state is the `Arc<Mutex<CaptureLog>>`, which is trivial
  to clear and reuse.

If a pool is deemed not worth the complexity for v1, the acceptable fallback is
(b) with **immediate drain**: a global log whose entries are moved into the
owning connection's `SecretLog` the moment its handshake completes (matched by
`client_random`), keeping memory bounded — at the cost of the global-lock
contention noted above.

## 5. wasm finding (§3.4)

**Assessed by analysis (no compile run).** A full `wasm32-unknown-unknown`
compile of the spike crate is not meaningful as-is: its *harness* uses
`tokio::net`, OS threads and `std::net::TcpStream`, none of which exist on
`wasm32-unknown-unknown`. The toolchain target was also not installed in this
environment. The relevant question is narrower — *does the capturing-provider
machinery compile for wasm?* — and the answer is **yes, with high confidence**:

- The wasm prover (`crates/wasm` → `tlsn-sdk-core` → `crates/tlsn`) uses the
  **same** crypto provider as native: `crates/tlsn/.../proxy/mod.rs:73` calls
  `rustls::crypto::ring::default_provider()` unconditionally (no `cfg`). So
  wasm already links rustls-on-ring today.
- `crates/wasm/Cargo.toml` already enables `getrandom`'s `js`/`wasm_js` backends
  (lines 42–45), which is exactly what `ring` 0.17 needs for its RNG on
  `wasm32-unknown-unknown`. ring 0.17 supports that target.
- The capturing wrapper adds **no new cryptography**: it forwards to the
  existing ring `&dyn Hkdf` and otherwise uses `std::sync`, `hmac`, `sha2`,
  `hkdf` — all pure-Rust, `no_std`-friendly RustCrypto crates that already build
  for wasm. `CapturingHkdf`/`CapturingExpander`/`KeyLogCapture` use only
  `Arc`/`Mutex`/`Vec`.

Therefore the wrapper introduces **no incremental wasm risk** beyond what the
wasm prover already carries by linking rustls+ring. The production `SecretLog`
should be split so the capture types live in a module free of `tokio::net`/
threads (they already are, in `capture.rs`), keeping them wasm-clean. A
confirming `cargo build --target wasm32-unknown-unknown` of an extracted
capture-only library is recommended as a cheap follow-up when the prover's 1.3
path lands.

## 6. Recommendation: wrapper provider vs rustls fork

**Use the wrapper provider. Do NOT fork rustls. Confidence: high.**

- The wrapper captures `handshake_secret` *itself* (not just inputs to
  recompute), works on the exact locked version (0.23.40), uses only public
  API, and reuses the provider-customisation pattern the proxy client already
  has. The verification chain — which is the real ZK key schedule — is validated
  end-to-end against rustls's own output and against RFC 8448.
- The only frictions (§2) are cosmetic: no `pub(crate)` `hmac` (use option (a)),
  and manual struct construction instead of `..*base`. Neither is a blocker.
- A fork would add permanent maintenance/rebase cost (the parent spec §4 itself
  calls a fork "a build/maintenance decision, not a protocol decision") for zero
  capability gain here.

Fork sizing (for completeness, in case future requirements change): a minimal
fork would add a single hook in `KeySchedule::input_secret`
(`src/tls13/key_schedule.rs:675`) to surface the `(salt, secret)` or the
resulting PRK — roughly a one-field callback on `KeySchedule` plumbed from
`Tls13CipherSuite`/config, ~30–60 LoC plus the rebase surface. **Not
recommended**, since the wrapper already obtains the same secret.

## 7. Corrections needed to parent spec §4/§5

§5 key-schedule **math is correct** and is now empirically validated (labels,
`MS = HKDF-Extract(derived, 0^32)`, `c_ap`/`s_ap` over `h3`, the two-phase
`h2`→`h3` availability). The §2 call-path facts in the spike spec all reproduce
on 0.23.40, including "`extract_from_kx_shared_secret` is NOT used" (the client
calls `input_secret` → `extract_from_secret`). The needed corrections are about
**construction code**, not protocol:

1. **§4 (and spike §3.1.2) — `Tls13CipherSuite { hkdf_provider, ..*suite }` does
   not compile.** `CipherSuiteCommon` is not `Copy`/`Clone`; you cannot move
   fields out of a `&'static` suite. Reconstruct the suite field-by-field (see
   §2.2 above). Recommend updating the §3.1 sketch.

2. **§4 / §3.1.1 — option (b) is infeasible on 0.23.40.**
   `HkdfUsingHmac(&rustls::crypto::ring::hmac::HMAC_SHA256)` won't compile
   because `rustls::crypto::ring::hmac` is `pub(crate)`. Only option (a)
   (wrap the ring suite's existing `&'static dyn Hkdf`) is viable. Recommend
   striking option (b) or noting its unavailability.

3. **§4 wording — capture is stronger than "capture inputs and recompute".** The
   spec hedges ("equivalently, capture the ECDHE shared secret + salt and
   recompute locally"). In practice the wrapper recomputes the PRK
   (`HMAC(salt, ikm)`) inline and that PRK *is* `handshake_secret` directly — one
   HMAC, no deferred recomputation needed. The §4 `CapturedSecrets::V1_3`
   struct is unchanged and correct.

4. **(Nit) §4/§10.1 framing of "the PRK is wrapped in an opaque
   `HkdfExpander`".** True, but irrelevant: the wrapper never needs to read
   rustls's PRK because it recomputes the identical value from the
   `extract_from_secret` arguments it *does* see. The open question §10.1 can be
   marked resolved (wrapper viable).

## 8. Files created / modified

Created:
- `crates/spikes/tls13-secret-capture/Cargo.toml`
- `crates/spikes/tls13-secret-capture/src/main.rs` — entry point, PASS/FAIL summary, exit code.
- `crates/spikes/tls13-secret-capture/src/capture.rs` — `CapturingHkdf`, `CapturingExpander`, `CaptureLog`, `KeyLogCapture`.
- `crates/spikes/tls13-secret-capture/src/harness.rs` — provider assembly, fixture wiring, §3.2 analysis.
- `crates/spikes/tls13-secret-capture/src/verify.rs` — RustCrypto key-schedule recomputation, `HkdfLabel` encode/parse, RFC 8448 self-check.
- `specs/spikes/tls13-secret-capture-RESULTS.md` — this report.

Modified (the only allowed edit outside the new crate):
- `Cargo.toml` — added `crates/spikes/tls13-secret-capture` to workspace `members`.

No existing crate was modified.

## 9. Success criteria

Spec §6: success iff all §3.2 assertions pass **or** a precise blocker is
documented with a sized fork fallback. **All §3.2 assertions pass** ⇒
**SUCCESS**. The wrapper approach is accepted with evidence.
