# Task: `verify_tags` TLS 1.3 branch in `tlsn`

Parent spec: `specs/tls13-proxy.md` §7.2. Work-breakdown item 6.
Scope: `crates/tlsn/src/tag.rs` only.

**Depends on item 3** (`Aes128::set_iv_tls13` / `alloc_ctr_block_tls13`,
`specs/tasks/tls13-cipher-xor-nonce.md`) and item 4 (`make_tls13_aad`, already
DONE in `tls-core`). Build after item 3 lands.

## 1. What exists today (TLS 1.2 only)

`verify_tags` (`src/tag.rs`) allocates an AES-128 cipher from a
`(Array<U8, 16>, Array<U8, 4>)` key/IV, computes one J0 block per record from
the record's 8-byte `explicit_nonce` (counter = 1), decodes J0 + the GHASH
key, and `TagProof::verify` recomputes each tag as
`GHASH(make_tls12_aad(seq, typ, vers, ciphertext_len), ciphertext) XOR J0`.

The current `vers` match has a dead arm:

```rust
let vers = match tls_version {
    TlsVersion::V1_2 => ProtocolVersion::TLSv1_2,
    TlsVersion::V1_3 => ProtocolVersion::TLSv1_3, // wrong for AAD; see below
};
```

This is incorrect for TLS 1.3: the 1.3 record AAD uses the wire constant
`0x0303` and a different shape entirely (`make_tls13_aad`), and the nonce is
derived from `seq`, not an explicit nonce.

## 2. Changes

### 2.1 Key/IV input becomes version-tagged

The 1.3 write IV is 12 bytes, not 4. Replace the `key_iv` tuple with an enum
so the IV width and version are carried together. Drop the separate
`tls_version` parameter and derive it from the variant (avoids inconsistent
combinations).

```rust
/// Cipher key material for tag verification.
pub(crate) enum TagKeyIv {
    V1_2 { key: Array<U8, 16>, iv: Array<U8, 4> },
    V1_3 { key: Array<U8, 16>, iv: Array<U8, 12> },
}

pub(crate) fn verify_tags(
    vm: &mut dyn Vm<Binary>,
    key_iv: TagKeyIv,
    mac_key: Array<U8, 16>,
    records: Vec<Record>,
) -> Result<TagProof, TagProofError>;
```

`TagProof` keeps a `tls_version: TlsVersion` field (set from the variant) for
the AAD branch in `verify`.

> The single caller (`crates/tlsn/src/proxy/verifier.rs` via the record-proof
> path) is updated in item 8 to pass the 12-byte IV for 1.3 — note the
> signature change there but do not implement the finalize-flow wiring in this
> task. Keep TLS 1.2 call sites compiling by adapting them to the
> `TagKeyIv::V1_2` variant.

### 2.2 J0 block construction (allocation phase)

Branch in `verify_tags`:

- **V1_2** (unchanged): `aes.set_iv(iv)`, `aes.alloc_ctr_block(vm)`, assign the
  record's 8-byte `explicit_nonce`, `counter = 1u32.to_be_bytes()`.
- **V1_3**: `aes.set_iv_tls13(iv)`, `aes.alloc_ctr_block_tls13(vm)`, assign
  `seq_pad = [0u8; 4] ++ rec.seq.to_be_bytes()` (12 bytes) to
  `block.explicit_nonce` (the `seq_pad` slot, per item 3) and
  `counter = 1u32.to_be_bytes()`. For V1_3, `rec.explicit_nonce` is empty and
  must not be read; assert/ignore it.

Both branches `vm.decode(block.output)` into the `j0s` vector exactly as today.

### 2.3 AAD construction (`TagProof::verify`)

Branch on `tls_version`:

- **V1_2** (unchanged):
  `make_tls12_aad(rec.seq, rec.typ.into(), ProtocolVersion::TLSv1_2, rec.ciphertext.len())`.
- **V1_3**: `make_tls13_aad(rec.ciphertext.len() + 16)`. `Record.ciphertext`
  excludes the 16-byte tag, and `make_tls13_aad`'s `len` argument **includes**
  the tag, hence `+ 16`. The `rec.typ` / `rec.seq` are not used in the 1.3 AAD
  (type is the constant `application_data`, seq is in the nonce).

Remove the dead `TlsVersion::V1_3 => ProtocolVersion::TLSv1_3` arm.

### 2.4 GHASH / tag comparison

Unchanged: `ghash(aad, &rec.ciphertext, &mac_key)` then compare
`rec.tag == ghash_tag XOR j0` byte-wise. GHASH key derivation
(`H = AES_K(0^16)`) is identical across versions and is computed by the caller
(item 8), not here.

## 3. Tests

Add a `#[cfg(test)]` module (or extend an existing test harness) using two
`IdealVm`s like the `cipher`/`hmac-sha256` tests. For the 1.3 path:

1. **`test_verify_tags_tls13_ok`**: take a real AES-128-GCM TLS 1.3 record
   (key, iv12, seq, ciphertext, tag) — RFC 8448 "simple 1-RTT handshake"
   server records are ideal known-answer inputs, or generate one with the
   `aes-gcm` crate (nonce = `iv12 XOR (0^4||seq)`, aad =
   `make_tls13_aad(ct_len + 16)`). Allocate key/iv/mac_key refs in both VMs,
   call `verify_tags` with `TagKeyIv::V1_3`, run the VMs, and assert
   `TagProof::verify()` returns `Ok`.
2. **`test_verify_tags_tls13_bad_tag`**: flip a byte of `rec.tag`; assert
   `verify()` returns `ErrorRepr::InvalidTag`.
3. **`test_verify_tags_tls13_multi_seq`**: two records with seq 0 and 1 (same
   key/iv, different nonce via seq); assert both verify, confirming the
   `seq_pad` nonce derivation is wired correctly.
4. Existing TLS 1.2 tag tests keep passing (adapted to `TagKeyIv::V1_2`).

The `mac_key` (GHASH key `H`) for the test is `AES_K(0^16)`; compute it with
the `aes` crate for the chosen key and feed it as the decoded `mac_key`.

## 4. Acceptance criteria

- `cargo test -p tlsn` (or the crate hosting `tag.rs`) passes, including the
  new 1.3 tests and the unchanged 1.2 tests.
- `cargo clippy` clean for the crate; `cargo fmt` applied.
- Changes confined to `crates/tlsn/src/tag.rs` plus the minimal call-site
  signature adaptation needed to keep the crate compiling (full finalize-flow
  wiring is item 8).
- The 1.3 AAD uses `make_tls13_aad(ciphertext.len() + 16)` and the J0 nonce
  uses `seq_pad = 0^4 || seq_be64` with `counter = 1`, matching item 3's
  contract.
```
