# Task: `make_tls13_aad` in `tls-core`

Parent spec: `specs/tls13-proxy.md` §7.2. Work-breakdown item 4. Small,
self-contained task.
Scope: `crates/tls-core/src/cipher.rs` only.

## 1. Goal

Add the TLS 1.3 record AAD constructor next to the existing `make_tls12_aad`.

Per RFC 8446 §5.2, the additional data for AEAD in TLS 1.3 is the 5-byte
`TLSCiphertext` header:

```
additional_data = opaque_type(1) || legacy_record_version(2) || length(2)
```

where, for every protected record:

- `opaque_type` is always `application_data` = `0x17`,
- `legacy_record_version` is always `0x0303` (TLS 1.2 wire constant),
- `length` is the length of `TLSCiphertext.encrypted_record`, i.e. the
  AEAD output: inner plaintext (content || content-type byte || padding)
  plus the 16-byte tag.

## 2. API

In `crates/tls-core/src/cipher.rs`:

```rust
/// AAD for a protected TLS 1.3 record (RFC 8446 §5.2).
///
/// `len` is the length of the encrypted record body on the wire, i.e.
/// ciphertext INCLUDING the AEAD tag.
pub fn make_tls13_aad(len: usize) -> [u8; 5] {
    [
        0x17, // ContentType::ApplicationData
        0x3,  // ProtocolVersion::TLSv1_2 major
        0x3,  // ProtocolVersion::TLSv1_2 minor
        (len >> 8) as u8,
        len as u8,
    ]
}
```

Notes:

- No `seq`, `typ`, or `vers` parameters: unlike TLS 1.2, the sequence number
  goes into the nonce (not the AAD), the outer type is constant, and the wire
  version is fixed. Keep the signature minimal — callers must not be able to
  construct a non-conformant AAD.
- Prefer using the existing enums for the constants if it reads cleanly
  (`ContentType::ApplicationData.get_u8()`,
  `ProtocolVersion::TLSv1_2.get_u16()`); otherwise raw bytes with the comment
  above are fine. Match the style of `make_tls12_aad` directly above.

## 3. Tests

Add a `#[cfg(test)]` module in `cipher.rs`:

1. `make_tls13_aad(0x0123)` ⇒ `[0x17, 0x03, 0x03, 0x01, 0x23]`.
2. A real-world-shaped case: plaintext of 100 bytes ⇒ inner plaintext 101
   (content-type byte, no padding) ⇒ wire length 117 with tag ⇒
   `make_tls13_aad(117)` ends with `[0x00, 0x75]`.
3. Sanity-check `make_tls12_aad` is untouched (existing behavior keeps
   compiling; no test changes needed beyond what exists).

Optionally cross-check assertion values against RFC 8446 §5.2 by hand in a
comment.

## 4. Acceptance criteria

- `cargo test -p tls-core` passes; `cargo clippy -p tls-core` clean;
  `cargo fmt` applied.
- No changes outside `crates/tls-core/src/cipher.rs`.
- Doc comment states the `len` convention (includes the tag) unambiguously —
  downstream `verify_tags` code will rely on it.
