use crate::msgs::enums::{ContentType, ProtocolVersion};

pub fn make_tls12_aad(seq: u64, typ: ContentType, vers: ProtocolVersion, len: usize) -> [u8; 13] {
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8] = typ.get_u8();
    aad[9..11].copy_from_slice(&vers.get_u16().to_be_bytes());
    aad[11..13].copy_from_slice(&(len as u16).to_be_bytes());
    aad
}

/// AAD for a protected TLS 1.3 record (RFC 8446 §5.2).
///
/// `len` is the length of the encrypted record body on the wire, i.e. the
/// ciphertext INCLUDING the AEAD tag.
///
/// The outer content type is always `application_data` (0x17) and the legacy
/// record version is always 0x0303 for protected TLS 1.3 records, and the
/// sequence number goes into the nonce rather than the AAD, so `len` is the
/// only input.
pub fn make_tls13_aad(len: usize) -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[0] = ContentType::ApplicationData.get_u8();
    aad[1..3].copy_from_slice(&ProtocolVersion::TLSv1_2.get_u16().to_be_bytes());
    aad[3..5].copy_from_slice(&(len as u16).to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_aad_known_value() {
        // opaque_type 0x17 || legacy_record_version 0x0303 || length 0x0123
        assert_eq!(make_tls13_aad(0x0123), [0x17, 0x03, 0x03, 0x01, 0x23]);
    }

    #[test]
    fn tls13_aad_real_world_length() {
        // 100 bytes of plaintext + 1 content-type byte (no padding) = 101
        // bytes of inner plaintext; + 16-byte AEAD tag = 117 (0x0075) on the
        // wire.
        let aad = make_tls13_aad(117);
        assert_eq!(aad[3..5], [0x00, 0x75]);
    }

    #[test]
    fn tls12_aad_untouched() {
        let aad = make_tls12_aad(
            1,
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            42,
        );
        assert_eq!(aad, [0, 0, 0, 0, 0, 0, 0, 1, 0x17, 0x03, 0x03, 0x00, 0x2a]);
    }
}
