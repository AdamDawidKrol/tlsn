# Task: `KeySchedule13` — TLS 1.3 key-schedule graph in `hmac-sha256`

Parent spec: `specs/tls13-proxy.md` §5 (read it first; §3 for the security
rationale). Work-breakdown item 2.
Scope: `crates/components/hmac-sha256` ONLY. Additive change — do not modify
the existing `Prf`, `hmac.rs` internals, or public TLS 1.2 API behavior.
The derivation math in §3 below was validated end-to-end against rustls's
keylog by the spike in `specs/spikes/tls13-secret-capture-RESULTS.md`.

## 1. Goal

A new public type `KeySchedule13` that evaluates the TLS 1.3 key schedule
(RFC 8446 §7.1, SHA-256 suite only) inside an `mpz` VM, from a caller-supplied
`handshake_secret` reference down to the application-traffic AES-128-GCM key/IV
references. It will run in the QuickSilver ZK VM in proxy mode (prover knows
the secret, verifier is blind), but must be VM-agnostic like `Prf` (tests use
`IdealVm`).

## 2. Public API

Mirror the `Prf` driver pattern exactly (`src/prf.rs`): allocate-then-drive
with `wants_flush()` / `flush(vm)` / setters, state machine with
`Initialized / Setup / Complete / Error`.

```rust
/// TLS 1.3 key schedule (RFC 8446 §7.1), SHA-256-based suites.
pub struct KeySchedule13 { /* state machine */ }

/// Output references of the TLS 1.3 key schedule.
#[derive(Debug, Clone, Copy)]
pub struct ScheduleOutput13 {
    /// Application traffic keys.
    pub keys: SessionKeys13,
    /// Client handshake traffic secret (intended for public decode by the
    /// caller — this is the disclosure mechanism, see parent spec §5).
    pub c_hs: Array<U8, 32>,
    /// Server handshake traffic secret (ditto).
    pub s_hs: Array<U8, 32>,
}

/// TLS 1.3 application-epoch session keys (note 12-byte IVs, unlike the
/// 4-byte IVs of the TLS 1.2 `SessionKeys`).
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys13 {
    pub client_write_key: Array<U8, 16>,
    pub server_write_key: Array<U8, 16>,
    pub client_iv: Array<U8, 12>,
    pub server_iv: Array<U8, 12>,
}

impl KeySchedule13 {
    pub fn new() -> Self;

    /// Allocates the full derivation graph.
    ///
    /// `hs` is the TLS 1.3 handshake_secret. The caller controls its
    /// visibility (private for the prover / blind for the verifier) before
    /// calling, exactly like `Prf::alloc_ms`.
    pub fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        hs: Array<U8, 32>,
    ) -> Result<ScheduleOutput13, PrfError>;

    /// Sets h2 = SHA-256(ClientHello..ServerHello).
    /// Unblocks the c_hs / s_hs expansions.
    pub fn set_sh_hash(&mut self, hash: [u8; 32]) -> Result<(), PrfError>;

    /// Sets h3 = SHA-256(ClientHello..server Finished).
    /// Unblocks the application traffic secrets and keys.
    pub fn set_sf_hash(&mut self, hash: [u8; 32]) -> Result<(), PrfError>;

    pub fn wants_flush(&self) -> bool;
    pub fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError>;
}
```

Reuse `PrfError` (add variants only if genuinely needed). Export the new types
from `lib.rs` and update the crate-level doc comment (currently says the crate
only computes the TLS 1.2 PRF).

`NetworkMode` does NOT apply: every node below is a single un-iterated HMAC,
so there is no Reduced/Normal trade-off. Do not thread `PrfConfig` through.

## 3. Derivation graph

All nodes are HMAC-SHA256. Key facts:

- `HKDF-Extract(salt, ikm) = HMAC(key = salt, msg = ikm)`.
- `HKDF-Expand-Label(secret, label, ctx, L)` with `L ≤ 32` is a single
  HMAC block: `HMAC(key = secret, msg = HkdfLabel || 0x01)`, truncated to `L`.
- `HkdfLabel = u16_be(L) || u8(len) || "tls13 " ++ label || u8(len(ctx)) || ctx`.

Graph (visibility of the HMAC *message* in parentheses; every HMAC *key* is a
VM reference):

```
input:  HS = handshake_secret            Array<U8, 32>, caller-visibility

c_hs    = Expand-Label(HS, "c hs traffic", h2, 32)     (msg public, h2 set at runtime)
s_hs    = Expand-Label(HS, "s hs traffic", h2, 32)     (msg public, h2 set at runtime)
derived = Expand-Label(HS, "derived", H(""), 32)       (msg public CONSTANT)
MS      = Extract(salt = derived, ikm = 0^32)          (msg public constant = 32 zero bytes)
c_ap    = Expand-Label(MS, "c ap traffic", h3, 32)     (msg public, h3 set at runtime)
s_ap    = Expand-Label(MS, "s ap traffic", h3, 32)     (msg public, h3 set at runtime)
client_write_key = Expand-Label(c_ap, "key", "", 16)   (msg public constant)
client_write_iv  = Expand-Label(c_ap, "iv",  "", 12)   (msg public constant)
server_write_key = Expand-Label(s_ap, "key", "", 16)   (msg public constant)
server_write_iv  = Expand-Label(s_ap, "iv",  "", 12)   (msg public constant)
```

`H("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
(hard-code as a public constant).

Notes:

- The `derived → MS` chain and the four `key`/`iv` expansions have constant
  messages; only `h2` and `h3` arrive at runtime via the setters. Progress
  rules: nodes keyed by `HS` other than c_hs/s_hs can complete on the first
  flush; c_hs/s_hs wait for `set_sh_hash`; c_ap/s_ap (and the key/iv nodes
  downstream, whose *keys* are c_ap/s_ap) wait for `set_sf_hash`.
- Each HMAC whose key is a VM reference needs the padded-key states: reuse
  `compute_partial(vm, key, OPAD/IPAD)` (`src/prf.rs`) to build
  `outer_partial` / `inner_partial` `Sha256` states, then the
  inner-hash-update / `hmac_sha256(outer_partial, inner_local)` flow used by
  `prf/function/normal.rs` — that module already implements deferred message
  assignment with the `wants_flush`-driven lifecycle; crib its structure
  rather than inventing a new one.
- Truncation to 16/12 bytes: take the 32-byte HMAC output and slice via the
  existing `merge_outputs`-style approach (see `get_session_keys` in
  `src/prf.rs` for the pattern of splitting a `Vector<U8>` into typed arrays).
- Do NOT decode anything inside the component. `c_hs`/`s_hs` are returned as
  references; the caller decides what to decode (in proxy mode their public
  decode is the disclosure step).

## 4. Tests (all in this crate)

1. **RFC 8448 vectors** (mandatory): from RFC 8448 §3 "Simple 1-RTT
   Handshake", take the server-side `{server} extract secret "handshake"`
   value as `HS`, the transcript hashes implied by the `derive secret`
   entries, and assert every node above against the listed vectors:
   `c hs traffic`, `s hs traffic`, `derived`, `extract secret "master"`,
   `c ap traffic`, `s ap traffic`, and the server `key`/`iv` expansions.
   (RFC 8448 §3 lists all of these explicitly; transcribe them as constants
   with a comment citing the section.)
2. **Random property test**: random `HS`, random `h2`/`h3`; compare all
   outputs against a cleartext reference implementation. Put the reference
   (plain `HKDF-Expand-Label` over RustCrypto `hmac`/`sha2` or the `hkdf`
   crate) in `test_utils.rs`; new dev-dependencies are fine, normal
   dependencies are NOT.
3. **Two-party harness**: follow the existing test shape
   (`test_st_context(8)` + two `IdealVm`s, leader/follower, flush loop —
   see `src/prf.rs` tests and `src/lib.rs` tests). At least one test must
   exercise the realistic visibility split: leader `mark_private` +
   `assign` HS, follower `mark_blind` HS, then both decode `c_hs`/`s_hs`
   and the session-key refs and assert equality with the reference.
4. **Driver-order test**: assert the two-phase flow works —
   `alloc` → flush (constants progress) → `set_sh_hash` → flush →
   c_hs/s_hs decodable → `set_sf_hash` → flush → keys decodable — and that
   setters in the wrong state return errors rather than panicking.

## 5. Acceptance criteria

- `cargo test -p hmac-sha256` passes (all existing tests still green).
- `cargo clippy -p hmac-sha256` clean; `cargo fmt` applied.
- No changes outside `crates/components/hmac-sha256` (dev-dependencies in its
  `Cargo.toml` are allowed).
- Public items documented (crate denies `missing_docs`).
- A short summary of structural choices (what was reused from
  `prf/function/normal.rs`, node/state layout) — in the final report, not as
  a doc file.
