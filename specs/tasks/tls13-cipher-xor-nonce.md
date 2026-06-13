# Task: TLS 1.3 XOR-nonce CTR block variant in `cipher`

Parent spec: `specs/tls13-proxy.md` §7.1. Work-breakdown item 3.
Scope: `crates/components/cipher` only (`src/aes/mod.rs`, possibly `src/lib.rs`).
Independent of items 5/6/7; can be built in parallel with item 5.

## 1. Problem

The `Aes128` cipher (`src/aes/mod.rs`) is hardcoded to the TLS 1.2 AEAD nonce
layout. Its CTR-block circuit builds the 16-byte AES input as

```
iv(4, secret) || explicit_nonce(8, public) || counter(4, public)
```

via `AES128_POST_KS(ks, iv, explicit_nonce, counter)` (the four args are
concatenated in order to form the AES input block).

TLS 1.3 (RFC 8446 §5.3) has no explicit per-record nonce. The 96-bit AEAD
nonce is

```
nonce = write_iv(12) XOR (0x00_00_00_00 || seq_be64(8))
```

and the AES input block is `nonce(12) || counter(4)`. The `write_iv` is the
12-byte secret IV produced by the ZK key schedule
(`hmac_sha256::SessionKeys13.{client,server}_iv: Array<U8, 12>`), and the
`seq_pad = 0^4 || seq_be64` is public per record.

We need a CTR-block / keystream variant whose AES input is
`(iv12 XOR seq_pad12) || counter4`, with `iv12` secret and `seq_pad12`,
`counter4` public.

## 2. Approach: VM-level XOR + reuse `AES128_POST_KS`

Do **not** author a new circuit in `mpz_circuits` (external crate). Instead:

1. Allocate two public per-record inputs: `seq_pad: Array<U8, 12>` and
   `counter: Array<U8, 4>` (`vm.alloc` + `vm.mark_public`).
2. Compute `nonce12 = xor(iv12, seq_pad)` in the VM using
   `mpz_circuits::circuits::xor(96)` (96 = 12 bytes · 8 bits). XOR against a
   public operand is essentially free in the circuit representation. This
   yields a `Vector<U8>` of length 12 — exactly the pattern already used in
   `Keystream::apply` (`src/lib.rs`) and `prf.rs`.
3. Call `AES128_POST_KS(ks, nonce12[0..4], nonce12[4..12], counter)`. The
   circuit concatenates its args, so feeding the XORed nonce as the existing
   `iv`(4) + `explicit_nonce`(8) argument slots reproduces the AES input
   `nonce12 || counter`. Passing `Vector<U8>` slices into arg slots that the
   1.2 path fills with `Array<U8, 4>` / `Array<U8, 8>` is sound: `Call`
   matches args by bit-length, and `Keystream::apply` already mixes
   `Array`-typed and `Vector`-slice args into the same circuit.

If, against expectation, passing `Vector` slices into `AES128_POST_KS` arg
slots does not typecheck, the fallback is to flatten `nonce12 || counter` into
a single 16-byte `Vector` and feed it as one block to an ECB-style call
(`alloc_block` takes `Array<U8, 16>`); reconcile types via `flatten_blocks`
in `src/lib.rs`. Prefer the direct slice approach first.

## 3. API

Add a 12-byte IV field and TLS 1.3 inherent methods to `Aes128`. Leave the
existing `Cipher` trait impl and 1.2 methods untouched (the trait's associated
types `Iv = Array<U8, 4>` / `Nonce = Array<U8, 8>` stay 1.2-shaped).

```rust
pub struct Aes128 {
    key: Option<Array<U8, 16>>,
    key_schedule: Option<KeySchedule>,
    iv: Option<Array<U8, 4>>,        // TLS 1.2
    iv13: Option<Array<U8, 12>>,     // TLS 1.3 write IV (secret)
}

impl Aes128 {
    /// Sets the 12-byte TLS 1.3 write IV.
    pub fn set_iv_tls13(&mut self, iv: Array<U8, 12>);

    /// Allocates a single TLS 1.3 CTR-mode block. The AES input is
    /// `(iv13 XOR seq_pad) || counter`, where `seq_pad` (12B) and `counter`
    /// (4B) are public per-record inputs assigned later via
    /// `Keystream`/`CtrBlock` assignment helpers.
    pub fn alloc_ctr_block_tls13(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<CtrBlock<Array<U8, 12>, Array<U8, 4>, Array<U8, 16>>, AesError>;

    /// Allocates a TLS 1.3 keystream of `len` bytes (counter increments per
    /// block, nonce shared across the record).
    pub fn alloc_keystream_tls13(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
    ) -> Result<Keystream<Array<U8, 12>, Array<U8, 4>, Array<U8, 16>>, AesError>;
}
```

### Reuse `CtrBlock` / `Keystream` unchanged

The existing generic `CtrBlock<N, C, O>` / `Keystream<N, C, O>` (`src/lib.rs`)
work as-is with `N = Array<U8, 12>`:

- Store the **public `seq_pad`** reference in `CtrBlock.explicit_nonce` (the
  `N` slot now means "sequence-number pad", not "explicit nonce"). The XORed
  `nonce12` is an internal node derived from `iv13` + `explicit_nonce`; it is
  not stored in the struct.
- `Keystream::assign(vm, seq_pad: [u8; 12], ctr)` then assigns the same
  `seq_pad` to every block and increments the counter — exactly the TLS 1.3
  per-record keystream (single nonce, counter 2,3,4,…).
- `apply`, `consume`, `to_vector` need no changes (generic over `N, C, O`).

No public-API change to `CtrBlock`/`Keystream`. Only `Aes128` gains the new
field and methods.

## 4. Counter conventions (callers, for context — not in this task)

- `verify_tags` (item 6): `alloc_ctr_block_tls13`, assign
  `seq_pad = [0u8; 4] ++ seq.to_be_bytes()`, `counter = 1u32.to_be_bytes()`
  (J0 for the tag).
- Plaintext keystream proofs (item 7): `alloc_keystream_tls13`, counter starts
  at `AES_GCM_START_COUNTER = 2`.

This task only provides the allocation primitives; do not modify callers.

## 5. Tests

Add to the `#[cfg(test)] mod tests` in `src/aes/mod.rs`, mirroring
`test_aes_ctr` / `test_aes_ecb` (two `IdealVm`s, gen + ev, decode and assert
equality, then assert against a software reference).

1. **`test_aes_ctr_tls13`**: pick `key[16]`, `iv12`, `seq: u64`,
   `start_counter = 2`. Allocate a TLS 1.3 keystream, assign
   `seq_pad = [0,0,0,0] ++ seq.to_be_bytes()`, apply to a random message,
   decode on both VMs and assert equal. Cross-check against a software
   reference: compute `nonce = iv12 XOR seq_pad`, build the AES-CTR (32-bit
   big-endian counter, `ctr` crate `Ctr32BE::<Aes128>`) with
   `full_iv = nonce`, `seek(start_counter * 16)`, and assert the keystream
   output matches. (Adapt the existing `aes_apply_keystream` helper to accept a
   12-byte nonce directly instead of `iv(4) || explicit_nonce(8)`.)

2. **`test_aes_j0_tls13`**: single `alloc_ctr_block_tls13`, assign
   `seq_pad` for some seq and `counter = 1`, decode `output` on both VMs and
   assert equal; assert it equals the software J0 = `AES_K(nonce || 0x00000001)`
   (single ECB block over the 16-byte input).

3. **Known-answer (recommended)**: use RFC 8448 "simple 1-RTT handshake"
   server application traffic key/iv and verify the first keystream block of a
   record decrypts the published ciphertext, or at minimum that J0 matches a
   value computed by the `aes`/`aes-gcm` crates for the same nonce. A
   self-consistency test (1 + 2) is the minimum bar; the KAT raises confidence.

4. Existing `test_aes_ctr` / `test_aes_ecb` keep passing unchanged.

## 6. Acceptance criteria

- `cargo test -p cipher` passes (including the new TLS 1.3 tests and the
  unchanged 1.2 tests).
- `cargo clippy -p cipher` clean; `#![deny(missing_docs, unreachable_pub,
  unused_must_use)]` satisfied (new public methods/fields documented).
- `cargo fmt` applied.
- No changes outside `crates/components/cipher`.
- No changes to the `Cipher` trait or to `CtrBlock` / `Keystream` public APIs.
- New methods documented with the nonce-construction contract
  (`(iv13 XOR seq_pad) || counter`, `seq_pad = 0^4 || seq_be64`) so item 6/7
  callers can rely on it.
```
