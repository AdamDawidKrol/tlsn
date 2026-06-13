//! Cleartext TLS 1.3 handshake crypto helpers.
//!
//! These implement the small slice of the RFC 8446 key schedule and record
//! protection that both proxy-mode parties need to decrypt and verify the
//! handshake flight *in the clear* (no ZK): HKDF-Expand-Label, handshake/
//! application traffic-key derivation, AES-128-GCM record decryption, and the
//! Finished `verify_data` MAC.
//!
//! Only the `TLS13_AES_128_GCM_SHA256` suite is supported (parent spec §1),
//! hence SHA-256 (32-byte secrets), 16-byte keys and 12-byte IVs throughout.

use aead::Payload as AeadPayload;
use aes_gcm::{Aes128Gcm, NewAead, aead::Aead, aead::generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tls_core::cipher::make_tls13_aad;

use super::TlsTranscriptError;

/// SHA-256 output / traffic-secret length.
const HASH_LEN: usize = 32;
/// AES-128 key length.
const KEY_LEN: usize = 16;
/// TLS 1.3 record IV (and AEAD nonce) length.
const IV_LEN: usize = 12;
/// AES-128-GCM authentication tag length.
const TAG_LEN: usize = 16;
/// Prefix of every HkdfLabel `label` field (RFC 8446 §7.1).
const LABEL_PREFIX: &[u8] = b"tls13 ";

type HmacSha256 = Hmac<Sha256>;

/// HKDF-Expand-Label (RFC 8446 §7.1).
///
/// `HkdfLabel = u16(length) || u8(len)("tls13 "+label) || u8(len)(context)`,
/// and `HKDF-Expand` with `out_len <= 32` is a single block
/// `T(1) = HMAC(secret, HkdfLabel || 0x01)` truncated to `out_len`
/// (RFC 5869 §2.3). All call sites here use `out_len <= 32`.
pub(crate) fn hkdf_expand_label(
    secret: &[u8; HASH_LEN],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> Vec<u8> {
    debug_assert!(out_len <= HASH_LEN, "single-block HKDF-Expand only");

    let mut info = Vec::with_capacity(2 + 1 + LABEL_PREFIX.len() + label.len() + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push((LABEL_PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&info);
    mac.update(&[0x01]);
    let block = mac.finalize().into_bytes();

    block[..out_len].to_vec()
}

/// Derives `(write_key[16], write_iv[12])` from a traffic secret
/// (RFC 8446 §7.3).
pub(crate) fn traffic_keys(secret: &[u8; HASH_LEN]) -> ([u8; KEY_LEN], [u8; IV_LEN]) {
    let key = hkdf_expand_label(secret, b"key", b"", KEY_LEN);
    let iv = hkdf_expand_label(secret, b"iv", b"", IV_LEN);
    (
        key.try_into().expect("key is 16 bytes"),
        iv.try_into().expect("iv is 12 bytes"),
    )
}

/// `finished_key = HKDF-Expand-Label(secret, "finished", "", 32)`
/// (RFC 8446 §4.4.4).
pub(crate) fn finished_key(secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    hkdf_expand_label(secret, b"finished", b"", HASH_LEN)
        .try_into()
        .expect("finished key is 32 bytes")
}

/// `verify_data = HMAC-SHA256(finished_key, transcript_hash)`
/// (RFC 8446 §4.4.4).
pub(crate) fn verify_data(
    finished_key: &[u8; HASH_LEN],
    transcript_hash: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut mac = HmacSha256::new_from_slice(finished_key).expect("HMAC accepts any key length");
    mac.update(transcript_hash);
    mac.finalize().into_bytes().into()
}

/// Decrypts one TLS 1.3 record body into the inner plaintext, returning
/// `(inner_content_type, content_bytes)`.
///
/// `record_body` is the on-the-wire record payload, i.e. `ciphertext ||
/// 16-byte tag` (no 5-byte record header). The nonce is
/// `iv XOR (0^4 || seq_be64)`, the AAD is [`make_tls13_aad`] over the full
/// body length (tag included), and the inner content type is the last
/// non-zero byte of the decrypted plaintext (zero padding follows it,
/// RFC 8446 §5.2). A tag mismatch is a hard error (parent §6.5).
pub(crate) fn decrypt_record(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    seq: u64,
    record_body: &[u8],
) -> Result<(u8, Vec<u8>), TlsTranscriptError> {
    if record_body.len() < TAG_LEN {
        return Err(TlsTranscriptError::crypto(
            "TLS 1.3 encrypted record shorter than the AEAD tag",
        ));
    }

    // nonce = iv XOR (0^4 || seq_be64).
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for (n, s) in nonce[IV_LEN - 8..].iter_mut().zip(seq_bytes.iter()) {
        *n ^= *s;
    }

    let aad = make_tls13_aad(record_body.len());

    let cipher = Aes128Gcm::new_from_slice(key).expect("key is 16 bytes");
    let mut plaintext = cipher
        .decrypt(
            GenericArray::from_slice(&nonce),
            AeadPayload {
                msg: record_body,
                aad: &aad,
            },
        )
        .map_err(|_| TlsTranscriptError::crypto("TLS 1.3 record AEAD tag verification failed"))?;

    // Strip trailing zero padding; the last non-zero byte is the inner type.
    let type_pos = plaintext
        .iter()
        .rposition(|&b| b != 0)
        .ok_or_else(|| TlsTranscriptError::crypto("TLS 1.3 inner plaintext is all zero padding"))?;
    let inner_type = plaintext[type_pos];
    plaintext.truncate(type_pos);

    Ok((inner_type, plaintext))
}

/// RFC 8448 §3 "Simple 1-RTT Handshake" vectors, shared by the crypto
/// known-answer tests below and the builder integration tests
/// (`super::builder`). All `const`s are whitespace-tolerant hex.
#[cfg(test)]
pub(crate) mod rfc8448 {
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        ::hex::decode(s).unwrap()
    }

    pub(crate) fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    /// Builds a complete TLS record `type || 0x0303 || u16(len) || body` from a
    /// record body. The record-header version is irrelevant to 1.3 parsing
    /// (handshake transcript and AAD ignore it), so a uniform `0x0303` is used.
    pub(crate) fn record(typ: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![
            typ,
            0x03,
            0x03,
            (body.len() >> 8) as u8,
            (body.len() & 0xff) as u8,
        ];
        out.extend_from_slice(body);
        out
    }

    /// `{server} extract secret "handshake"`.
    pub(crate) const HS: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    /// h2 = H(ClientHello..ServerHello).
    pub(crate) const H2: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
    /// client handshake traffic secret.
    pub(crate) const C_HS: &str =
        "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    /// server handshake traffic secret.
    pub(crate) const S_HS: &str =
        "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    /// client application traffic secret.
    pub(crate) const C_AP: &str =
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    /// server application traffic secret.
    pub(crate) const S_AP: &str =
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    /// `{server} derive secret for master "tls13 derived"`.
    pub(crate) const DERIVED: &str =
        "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4";

    /// SHA-256 of the empty string (the "derived" label context).
    pub(crate) const EMPTY_HASH: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // ClientHello handshake message (the record payload, 196 octets).
    pub(crate) const CLIENT_HELLO_MSG: &str = "\
        01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d \
        99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 \
        00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 \
        1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 \
        24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 \
        3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 \
        05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 \
        02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

    // ServerHello handshake message (the record payload, 90 octets).
    pub(crate) const SERVER_HELLO_MSG: &str = "\
        02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 \
        cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 \
        c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 \
        b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

    // "{server} send handshake record" body: ciphertext || tag (674 octets),
    // i.e. the complete record with the 5-byte header `17 03 03 02 a2` removed.
    pub(crate) const SERVER_FLIGHT_RECORD: &str = "\
        d1 ff 33 4a 56 f5 bf f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 \
        5e df 78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45 cb 96 0b \
        40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3 89 28 0f 52 61 34 aa dc \
        7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 \
        5c 7c 79 02 07 16 cf b9 b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 \
        22 a4 cf 51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d 2e d6 \
        5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55 cc 74 41 10 c4 53 ba \
        a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f d9 91 f0 6a a6 24 82 04 79 7e 36 a6 \
        a7 3b 70 a2 55 9c 09 ea d6 86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 \
        a8 94 41 ac 66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea 52 \
        0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e a5 e2 2f 44 15 cf \
        95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6 54 0c 84 83 8d 89 f7 2c 24 46 1a \
        ad 6d 26 f5 9e ca ba 9a cb bb 31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce \
        34 31 17 b6 59 62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e \
        92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af 36 87 90 18 e3 \
        f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37 8b f3 02 44 da 8c 87 c8 43 f5 \
        e5 6e b4 c5 e8 28 0a 2b 48 05 2c f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 \
        d4 61 e6 6f 99 88 2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa \
        80 f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69 18 a3 96 fa \
        48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99 2f 67 f8 af e6 7f 76 91 3f \
        a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11 c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf \
        10 dc 35 ae 69 f5 51 56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb \
        ba 42 f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f 60 f0 50 \
        4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd d5 02 78 40 16 e4 b3 be \
        7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af 93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 \
        31 ed e4 2c 17 19 bf da bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b";

    // The published plaintext of the server flight (657 octets): the
    // EncryptedExtensions || Certificate || CertificateVerify || Finished
    // handshake messages (without the trailing inner content-type byte).
    pub(crate) const SERVER_FLIGHT_PLAINTEXT: &str = "\
        08 00 00 24 00 22 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 \
        01 03 01 04 00 1c 00 02 40 01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 \
        82 01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d 01 \
        01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 1e 17 0d 31 36 \
        30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36 30 37 33 30 30 31 32 33 35 39 5a \
        30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 \
        86 f7 0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30 \
        3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d \
        e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 \
        e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 \
        08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 \
        ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01 a3 1a 30 18 \
        30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03 02 05 a0 30 0d \
        06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 \
        8c 65 f7 3a 72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 \
        f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72 60 96 fd \
        33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63 a4 2a 99 be 5c 3e b7 10 \
        7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 \
        2d cc 0c c8 f8 96 12 29 ac 91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a \
        74 7c 5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3 ff 52 \
        f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86 53 fa 6b ef 78 0c 5e \
        a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 \
        ac 02 76 71 45 9e 46 44 5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 \
        be 15 2a 3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3 14 00 00 \
        20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff \
        ee 54 54 b7 8f 07 18";

    // "{client} send handshake record" body: client Finished, 53 octets
    // (complete record with the `17 03 03 00 35` header removed).
    pub(crate) const CLIENT_FINISHED_RECORD: &str = "\
        75 ec 4d c2 38 cc e6 0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b \
        fc 44 d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7 26 c4 05 \
        46";

    // "{server} send session ticket record" body: NewSessionTicket, 222 octets
    // (complete record with the `17 03 03 00 de` header removed).
    pub(crate) const SERVER_TICKET_RECORD: &str = "\
        3a 6b 8f 90 41 4a 97 d6 95 9c 34 87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95 \
        d4 1d 6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a 01 59 40 25 2f 55 71 3e 06 \
        1d c1 3e 07 88 91 a3 8e fb cf 57 53 ad 8e f1 70 ad 3c 73 53 d1 6d 9d a7 73 b9 \
        ca 7f 2b 9f a1 b6 c0 d4 a3 d0 3f 75 e0 9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 \
        be 63 43 9b 29 99 ce 13 06 46 15 13 98 91 d5 e4 c5 b4 06 f1 6e 3f c1 81 a7 7c \
        a4 75 84 00 25 db 2f 0a 77 f8 1b 5a b0 5b 94 c0 13 46 75 5f 69 23 2c 86 51 9d \
        86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6 50 db 4d 02 3e 70 e9 52 ca 49 fe \
        51 37 12 1c 74 bc 26 97 68 7e 24 87 46 d6 df 35 30 05 f3 bc e1 86 96 12 9c 81 \
        53 55 6b 3b 6c 67 79 b3 7b f1 59 85 68 4f";

    // "{client} send application_data record" body: 67 octets (complete record
    // with the `17 03 03 00 43` header removed). Inner plaintext is
    // `00 01 .. 31` (50 octets) || 0x17.
    pub(crate) const CLIENT_APP_RECORD: &str = "\
        a2 3f 70 54 b6 2c 94 d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab \
        3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 \
        70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4";
}

#[cfg(test)]
mod tests {
    use super::rfc8448::*;
    use super::*;

    #[test]
    fn hkdf_expand_label_matches_rfc8448() {
        let hs = hex_arr::<32>(HS);
        let h2 = hex(H2);

        // c_hs / s_hs = Expand-Label(HS, "c|s hs traffic", h2, 32).
        assert_eq!(hkdf_expand_label(&hs, b"c hs traffic", &h2, 32), hex(C_HS));
        assert_eq!(hkdf_expand_label(&hs, b"s hs traffic", &h2, 32), hex(S_HS));

        // derived = Expand-Label(HS, "derived", H(""), 32).
        assert_eq!(
            hkdf_expand_label(&hs, b"derived", &hex(EMPTY_HASH), 32),
            hex(DERIVED)
        );
    }

    #[test]
    fn traffic_keys_match_rfc8448() {
        // Server handshake write key/iv.
        let (key, iv) = traffic_keys(&hex_arr::<32>(S_HS));
        assert_eq!(key.to_vec(), hex("3fce516009c21727d0f2e4e86ee403bc"));
        assert_eq!(iv.to_vec(), hex("5d313eb2671276ee13000b30"));

        // Server application write key/iv.
        let (key, iv) = traffic_keys(&hex_arr::<32>(S_AP));
        assert_eq!(key.to_vec(), hex("9f02283b6c9c07efc26bb9f2ac92e356"));
        assert_eq!(iv.to_vec(), hex("cf782b88dd83549aadf1e984"));
    }

    #[test]
    fn finished_key_matches_rfc8448() {
        assert_eq!(
            finished_key(&hex_arr::<32>(S_HS)).to_vec(),
            hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")
        );
    }

    /// Decrypts the RFC 8448 server handshake-flight record and checks the
    /// recovered inner type, plaintext, and that the server Finished
    /// `verify_data` matches.
    #[test]
    fn decrypt_record_and_verify_data_rfc8448() {
        let (s_key, s_iv) = traffic_keys(&hex_arr::<32>(S_HS));

        // "{server} send handshake record" complete record (header stripped).
        let record_body = hex(SERVER_FLIGHT_RECORD);
        let (inner_type, content) = decrypt_record(&s_key, &s_iv, 0, &record_body).unwrap();

        // Inner type is handshake (0x16) and the plaintext is the published
        // 657-octet EncryptedExtensions..Finished flight.
        assert_eq!(inner_type, 0x16);
        assert_eq!(content, hex(SERVER_FLIGHT_PLAINTEXT));

        // The flight is EE(40) || Cert(445) || CertVerify(136) || Finished(36).
        let cv_end = 40 + 445 + 136;
        let cert_verify = &content[..cv_end];
        let finished = &content[cv_end..];
        assert_eq!(finished.len(), 36);

        // Server Finished verify_data == HMAC(finished_key(s_hs),
        // H(CH..CertificateVerify)).
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(hex(CLIENT_HELLO_MSG));
        hasher.update(hex(SERVER_HELLO_MSG));
        hasher.update(cert_verify);
        let cv_transcript_hash: [u8; 32] = hasher.finalize().into();

        let fk = finished_key(&hex_arr::<32>(S_HS));
        let vd = verify_data(&fk, &cv_transcript_hash);
        // Finished message body (drop the 4-byte handshake header).
        assert_eq!(&vd[..], &finished[4..]);
    }

    #[test]
    fn decrypt_record_rejects_tampered_tag() {
        let (s_key, s_iv) = traffic_keys(&hex_arr::<32>(S_HS));
        let mut record_body = hex(SERVER_FLIGHT_RECORD);
        // Flip a bit in the trailing tag.
        let last = record_body.len() - 1;
        record_body[last] ^= 0x01;
        assert!(decrypt_record(&s_key, &s_iv, 0, &record_body).is_err());
    }

    #[test]
    fn decrypt_record_rejects_wrong_secret() {
        // Decrypting with the client (wrong) handshake secret must fail the tag.
        let (c_key, c_iv) = traffic_keys(&hex_arr::<32>(C_HS));
        let record_body = hex(SERVER_FLIGHT_RECORD);
        assert!(decrypt_record(&c_key, &c_iv, 0, &record_body).is_err());
    }
}
