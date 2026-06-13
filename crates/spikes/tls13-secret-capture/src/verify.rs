//! The §3.2 verification chain, recomputed with RustCrypto (NOT the rustls
//! delegate). All math cross-checked against RFC 8446 §7.1 and one RFC 8448
//! test vector.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Build the `HkdfLabel` `info` for `HKDF-Expand-Label`, exactly as TLS 1.3
/// encodes it (RFC 8446 §7.1):
///
/// ```text
/// struct {
///     uint16 length;
///     opaque label<7..255>   = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
pub fn hkdf_label_info(length: u16, label: &str, context: &[u8]) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

/// Parse a captured `HkdfLabel` `info` blob back into `(length, label, context)`.
/// `label` includes the `"tls13 "` prefix. Returns `None` on malformed input.
pub fn parse_hkdf_label(info: &[u8]) -> Option<(u16, String, Vec<u8>)> {
    if info.len() < 3 {
        return None;
    }
    let length = u16::from_be_bytes([info[0], info[1]]);
    let label_len = info[2] as usize;
    let label_end = 3 + label_len;
    if info.len() < label_end + 1 {
        return None;
    }
    let label = String::from_utf8(info[3..label_end].to_vec()).ok()?;
    let ctx_len = info[label_end] as usize;
    let ctx_start = label_end + 1;
    let ctx_end = ctx_start + ctx_len;
    if info.len() < ctx_end {
        return None;
    }
    let context = info[ctx_start..ctx_end].to_vec();
    Some((length, label, context))
}

/// `Derive-Secret(Secret, Label, Context) = HKDF-Expand-Label(Secret, Label,
/// Context, Hash.length)`, output truncated to one SHA-256 block (32 bytes).
///
/// Note: `context` is the *transcript hash* (already hashed by the caller), not
/// the raw messages.
pub fn derive_secret(secret: &[u8], label: &str, context: &[u8]) -> [u8; 32] {
    let info = hkdf_label_info(32, label, context);
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("PRK length >= HashLen");
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 bytes is within bounds");
    okm
}

/// `HKDF-Extract(salt, ikm)` returning the 32-byte PRK.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// `SHA-256("")`.
pub fn sha256_empty() -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(b""));
    out
}

/// Self-check of [`derive_secret`] / [`hkdf_label_info`] against the RFC 8448
/// "simple 1-RTT handshake" vectors, independent of any live connection.
///
/// - early_secret = HKDF-Extract(0, 0) (RFC 8448 §3, "early secret").
/// - derived      = Derive-Secret(early_secret, "derived", "").
pub fn rfc8448_self_check() -> Result<(), String> {
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let expected_early =
        hex_lit("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    if early != expected_early.as_slice() {
        return Err(format!(
            "RFC 8448 early_secret mismatch: got {}",
            hex::encode(early)
        ));
    }

    let derived = derive_secret(&early, "derived", &sha256_empty());
    let expected_derived =
        hex_lit("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
    if derived != expected_derived.as_slice() {
        return Err(format!(
            "RFC 8448 derived mismatch: got {}",
            hex::encode(derived)
        ));
    }
    Ok(())
}

fn hex_lit(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex literal")
}
