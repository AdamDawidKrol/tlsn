# Task: TLS 1.3 plaintext-proof suffix handling + range math (`tlsn`)

Parent spec: `specs/tls13-proxy.md` §7.3 (and §6.4 for record framing, §10
open-question 5 for the padding-disclosure decision). Work-breakdown item 7.
Scope: `crates/tlsn/src/transcript_internal/auth.rs` (primary), with minimal
call-site adaptation in `src/prover/prove.rs` and `src/verifier/verify.rs`.

**Depends on** item 3 (`tlsn-cipher` XOR-nonce primitive — DONE) and item 5
(`tlsn-core` 1.3 `Record` framing — DONE). The full `SessionKeys` IV-width
plumbing (open-question §4) is **item 8**; this task defines the internal API
assuming a 12-byte IV reference is available and keeps the 1.2 call sites
compiling.

## 0. How the TLS 1.2 proof works today (read first)

`crates/tlsn/src/transcript_internal/auth.rs`:

- `prove_plaintext(vm, key: Array<U8,16>, iv: Array<U8,4>, plaintext, records, reveal, commit)`
  and its verifier twin `verify_plaintext(.., ciphertext, ..)`.
- `records` is the app-data records iterator
  (`tls_transcript.sent().iter().filter(|r| r.typ == ApplicationData)`).
- `RecordParams { explicit_nonce: Vec<u8>, len: usize }`, where
  `len = record.ciphertext.len()`.
- `reveal` / `commit` are `RangeSet<usize>` over **application-transcript byte
  positions** (the concatenation of `record.plaintext` across app-data records,
  i.e. `transcript.sent()` / `transcript.received()`).
- `alloc_keystream` walks records accumulating `pos += record.len`, lazily
  allocating only the AES blocks that cover the requested ranges. `alloc_block`
  calls the `AES128` circuit with `(key, iv(4), explicit_nonce(8), ctr(4))`,
  `START_CTR = 2`. The software reference `aes_ctr_apply_keystream` builds
  `full_iv = iv(4) || explicit_nonce(8)` and seeks to `START_CTR * 16`.
- `verify/verify.rs::collect_ciphertext` concatenates `record.ciphertext` for
  app-data records; `verify` asserts `transcript.len_*() == ciphertext_*.len()`.

**The TLS 1.2 invariant that breaks in 1.3:** `record.ciphertext.len()` equals
the application **content** length (1.2 has no inner type/padding), so
application-transcript coordinates and record-ciphertext coordinates coincide
1:1. In TLS 1.3 they do not (see §1).

## 1. The two coordinate systems (the core problem)

Per item 5, a TLS 1.3 app-data `Record` has:

```
record.ciphertext = inner_plaintext = content || type_byte(0x17) || padding(0x00 * p)
record.ciphertext.len() = content_len + 1 + p          // "inner length"
record.explicit_nonce  = []                             // empty
record.plaintext (prover) = content                     // content only, length content_len
```

- **Transcript coordinates** (what `reveal`/`commit`/`Transcript`/
  `PartialTranscript` use): concatenation of **content** bytes across app-data
  records only. Length per record = `content_len`.
- **Record-ciphertext coordinates** (what AES-CTR and the wire ciphertext use):
  the full inner plaintext per record. Length per record = `content_len + 1 + p`.

The AEAD keystream covers the **entire** inner plaintext (content + type +
padding); the wire ciphertext (`record.ciphertext`) is exactly that XOR the
keystream. So the ciphertext-consistency proof must run in record-ciphertext
coordinates, while the commitment/reveal logic runs in transcript coordinates.
Item 7 builds the bridge.

## 2. Design

### 2.1 Version-tagged cipher params

Replace the `(key, iv)` parameters of `prove_plaintext`/`verify_plaintext` with
an enum carrying the IV width (do not add a separate version flag — derive it):

```rust
pub(crate) enum CipherParams {
    V1_2 { key: Array<U8, 16>, iv: Array<U8, 4> },
    V1_3 { key: Array<U8, 16>, iv: Array<U8, 12> },
}
```

The 1.2 path is unchanged behaviorally. The 1.3 path uses the 12-byte IV and
the seq-derived nonce (§2.3).

### 2.2 `RecordParams` for 1.3

Extend with the data the 1.3 paths need:

```rust
struct RecordParams {
    // 1.2: the 8-byte explicit nonce; ignored for 1.3.
    explicit_nonce: Vec<u8>,
    // 1.3: per-epoch sequence number (for the nonce). Unused for 1.2.
    seq: u64,
    // Full inner-plaintext length = record.ciphertext.len().
    inner_len: usize,
    // 1.3 only: content length (inner_len - 1 - padding). For 1.2, content_len == inner_len.
    content_len: usize,
}
```

- **Prover**: `content_len = record.plaintext.len()` (it decrypted; content is
  known). `inner_len = record.ciphertext.len()`.
- **Verifier**: `content_len` is **learned from the disclosed suffix** (§2.4) —
  the verifier does not know it a priori. Compute it after the suffix bytes are
  decoded/validated, or have the prover convey it as part of the proof and
  re-derive it from the suffix as a check (the suffix proof makes lying
  detectable). Keep `content_len` authoritative = `inner_len - 1 - p` where `p`
  is the number of trailing zero padding bytes.

### 2.3 1.3 nonce in `alloc_block` / software reference

The 1.3 AEAD nonce is `nonce12 = iv12 XOR (0^4 || seq_be64)` (RFC 8446 §5.3),
the AES input block is `nonce12 || ctr_be32`, `START_CTR = 2` unchanged.

- **In-VM** (`alloc_block` 1.3 branch): compute
  `nonce12 = xor(96)(iv12, seq_pad)` where `seq_pad: Vector<U8>(12)` is the
  public `[0u8;4] ++ seq.to_be_bytes()` (alloc + `mark_public` + assign +
  commit, like `alloc_explicit_nonce`). Then call the existing `AES128` circuit
  with `(key, nonce12.get(0..4), nonce12.get(4..12), ctr)`. This is the exact
  slice-into-`AES128_POST_KS` technique validated in item 3
  (`crates/components/cipher/src/aes/mod.rs`); `auth.rs` already imports
  `mpz_circuits::circuits::xor` and `AES128`. The per-record nonce is shared
  across that record's blocks, so allocate `seq_pad`/`nonce12` once per record
  (mirror the existing `explicit_nonce` caching in `alloc_keystream`).
- **Software** (`aes_ctr_apply_keystream` 1.3 variant): `full_iv = nonce12`
  (the 12-byte XOR result), `Ctr32BE::<Aes128>`, seek `START_CTR * 16`.

> You may instead reuse `tlsn_cipher::aes::Aes128::{set_iv_tls13,
> alloc_keystream_tls13}` from item 3. Trade-off: that allocates a full-record
> keystream, losing `auth.rs`'s lazy per-range block allocation. Recommended:
> keep the lazy local allocator and add the inline 1.3 nonce; use item 3's
> NIST-KAT'd math as the correctness reference.

### 2.4 Suffix disclosure (`type || padding`)

For each 1.3 app-data record, the trailing `type_byte || padding` is **public**
and must be proven against the wire ciphertext (parent §7.3; open-question §5
accepts the padding-length disclosure since the verifier already relays the
connection):

1. Always include the suffix range `[content_len .. inner_len)` (in
   record-ciphertext coords) in the keystream/ciphertext-consistency proof,
   marked **public** (disclosed), in addition to the revealed/committed content
   ranges.
2. Assign the suffix plaintext bytes publicly: `type_byte = 0x17`
   (`ApplicationData`) followed by `p` zero bytes. Prove `suffix XOR keystream
   == record.ciphertext[content_len..]` via the same XOR-decode mechanism used
   for the ZK content path (`ProofInner::WithZk`). A mismatch ⇒
   `InvalidPlaintext`.
3. Verifier checks: the single non-zero byte is `0x17` at position
   `inner_len - 1 - p`, all `p` trailing bytes are zero ⇒ this both authenticates
   the inner content type as `application_data` and fixes `content_len`. Any
   other inner type among the records filtered as app-data is a hard error
   (NST/alerts were filtered out upstream by `typ == ApplicationData`; see §3).

This makes the content/suffix boundary verifier-checkable rather than
prover-asserted.

### 2.5 Range translation (transcript ↔ record-ciphertext coords)

Add a translation step so the existing range-driven keystream allocator
operates in record-ciphertext coordinates:

- Build a per-record offset table: transcript-position base `t_base` (sum of
  `content_len` of prior app-data records) and record-ciphertext base `c_base`
  (sum of `inner_len` of prior app-data records).
- Map each transcript range `[a, b)` (content coords) to its record(s) and
  shift into record-ciphertext coords: within a record, a content offset `o`
  (`0 ≤ o < content_len`) maps to record-ciphertext offset `o` (content is the
  prefix), i.e. `c = c_base + (a - t_base)`. Ranges never cross into the suffix
  (content ranges are `< content_len`); suffix ranges are added separately
  (§2.4).
- The returned `ReferenceMap` (`plaintext_refs`) must stay keyed in
  **transcript coordinates** (content only) — downstream `commit::hash` and
  `TranscriptRefs` index by transcript position. Only the internal
  keystream/`alloc_ciphertext` step uses record-ciphertext coords.

For 1.2, `content_len == inner_len` and `t_base == c_base`, so the translation
is the identity — keep the 1.2 path on the existing fast path.

### 2.6 Length checks / `collect_ciphertext`

In `verify/verify.rs`, the `transcript.len_*() == ciphertext_*.len()` assertion
holds for 1.2 only. For 1.3, `collect_ciphertext` (inner lengths) is larger
than the content-only transcript length. Adjust for 1.3: compare the
transcript length against the **sum of `content_len`** across app-data records
(derived from the records after suffix validation), not the raw ciphertext
length. Keep the full ciphertext for the consistency proof. Document the new
invariant. (This file is item-8-adjacent; make the minimal change needed for
correctness and leave a note for item 8's finalize wiring.)

## 3. NST / alerts / non-app-data records

`prove_plaintext`/`verify_plaintext` already receive records filtered to
`typ == ContentType::ApplicationData`. In 1.3 the inner type is only known
after decryption:

- **Prover** sets `Record.typ` to the true inner type (item 5, prover path), so
  the filter correctly excludes NST(`Handshake`)/alerts.
- **Verifier** does not know inner types until this proof. For v1, rely on the
  prover's record list + the per-record suffix proof: the suffix proof asserts
  `type == 0x17` for every record presented as app-data, and item 6
  (`verify_tags`) independently proves **every** app-epoch record's tag
  (including NST/alerts) keeping the seq sequence contiguous. A record the
  prover mislabels (e.g. hiding an app-data record as NST) cannot change the
  authenticated byte stream the verifier reconstructs, and the suffix/type
  proof prevents passing a non-app-data record through the app-data path.
  Document this argument inline; it is the v1 security rationale for the
  verifier-side classification.

## 4. Call-site adaptation (minimal)

- `prover/prove.rs` and `verifier/verify.rs`: build `CipherParams::V1_2 { .. }`
  from `keys.client_write_key/iv` etc. so the crate keeps compiling. Do **not**
  widen `mpc_tls::SessionKeys` or wire the 12-byte IV here — that is item 8
  (open-question §4). Add a `// TODO(item 8): V1_3 SessionKeys` marker at the
  call sites.
- Keep the public-ish `pub(crate)` signatures stable except for the
  `CipherParams` change.

## 5. Tests

Extend the `#[cfg(test)] mod tests` in `auth.rs` (it already has an `IdealVm`
harness, `build_vm`, `expected_aes_ctr`, and rstest cases):

1. **`test_alloc_keystream_tls13`**: like `test_alloc_keystream` but with a
   12-byte IV, `seq`-derived nonce, and records whose `inner_len = content_len
   + 1 + p`. Assert the in-VM keystream equals a software reference
   (`full_iv = iv12 XOR (0^4||seq)`, `Ctr32BE`, seek `2*16`) over
   record-ciphertext coordinates.
2. **`test_verify_plaintext_with_key_tls13`** (or the WithZk path): build
   inner plaintexts `content || 0x17 || 0^p`, encrypt with the 1.3 nonce,
   prove; assert success, and that a tampered content byte, a non-`0x17` type
   byte, or non-zero padding each fail with `InvalidPlaintext`.
3. **`test_range_translation`**: a unit test of the transcript↔record
   coordinate mapping for multiple records with mixed content/padding lengths
   and partial reveal/commit ranges (mirror the
   `multiple_records_partial` rstest case), asserting the resulting
   record-ciphertext ranges and that `plaintext_refs` stay in transcript
   coordinates.
4. Existing 1.2 tests pass unchanged (now via `CipherParams::V1_2`).

## 6. Acceptance criteria

- `cargo test -p tlsn` (or the crate hosting `transcript_internal`) passes,
  including new 1.3 tests and unchanged 1.2 tests; `cargo clippy` clean;
  `cargo fmt` applied.
- 1.3 plaintext proofs run in record-ciphertext coordinates with the
  `seq`-derived XOR nonce and `START_CTR = 2`; the `type || padding` suffix is
  proven public per app-data record (type `== 0x17`, padding all-zero), fixing
  `content_len`.
- `plaintext_refs` / `TranscriptRefs` remain keyed in transcript (content)
  coordinates; commitment/hash logic is untouched.
- TLS 1.2 behavior is byte-for-byte unchanged (identity coordinate map).
- No `SessionKeys` widening / finalize-flow wiring (item 8) and no changes to
  `tlsn-core` framing (item 5) — leave clear `TODO(item 8)` markers at the call
  sites and a note on the §2.6 length-check invariant.
```
