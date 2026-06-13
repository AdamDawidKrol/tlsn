//! TLS record tag verification.

use crate::ghash::ghash;

use cipher::{Cipher, aes::Aes128};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    DecodeFutureTyped,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, prelude::*};
use tls_core::{
    cipher::{make_tls12_aad, make_tls13_aad},
    msgs::enums::ProtocolVersion,
};
use tlsn_core::{connection::TlsVersion, transcript::Record};

/// Cipher key material for tag verification.
///
/// The variant determines both the IV width and the TLS version used for the
/// j0 nonce and AAD construction, ensuring the two cannot be combined
/// inconsistently.
pub(crate) enum TagKeyIv {
    /// TLS 1.2: 4-byte implicit write IV. The per-record nonce is completed by
    /// the record's 8-byte explicit nonce.
    V1_2 {
        /// AES-128 key.
        key: Array<U8, 16>,
        /// Implicit write IV.
        iv: Array<U8, 4>,
    },
    /// TLS 1.3: 12-byte write IV. The per-record nonce is the IV XORed with the
    /// sequence-number pad (RFC 8446 §5.3); there is no explicit nonce.
    V1_3 {
        /// AES-128 key.
        key: Array<U8, 16>,
        /// Write IV.
        iv: Array<U8, 12>,
    },
}

impl TagKeyIv {
    /// The TLS version implied by the key/IV variant.
    fn tls_version(&self) -> TlsVersion {
        match self {
            TagKeyIv::V1_2 { .. } => TlsVersion::V1_2,
            TagKeyIv::V1_3 { .. } => TlsVersion::V1_3,
        }
    }
}

/// Proves the verification of tags of the given `records`,
/// returning a proof.
///
/// The TLS version (and thus the j0 nonce and AAD construction) is derived from
/// the `key_iv` variant.
///
/// # Arguments
///
/// * `vm` - Virtual machine.
/// * `key_iv` - Cipher key and IV, tagged with the TLS version.
/// * `mac_key` - MAC key.
/// * `records` - Records for which the verification is to be proven.
pub(crate) fn verify_tags(
    vm: &mut dyn Vm<Binary>,
    key_iv: TagKeyIv,
    mac_key: Array<U8, 16>,
    records: Vec<Record>,
) -> Result<TagProof, TagProofError> {
    let tls_version = key_iv.tls_version();

    let mut aes = Aes128::default();
    match key_iv {
        TagKeyIv::V1_2 { key, iv } => {
            aes.set_key(key);
            aes.set_iv(iv);
        }
        TagKeyIv::V1_3 { key, iv } => {
            aes.set_key(key);
            aes.set_iv_tls13(iv);
        }
    }

    // Compute j0 blocks.
    let j0s = records
        .iter()
        .map(|rec| {
            // The explicit-nonce slot and its assigned value differ by version,
            // but the counter and output references are identical, so they are
            // bound after the branch.
            let (counter, output) = match tls_version {
                TlsVersion::V1_2 => {
                    let block = aes.alloc_ctr_block(vm).map_err(TagProofError::vm)?;

                    let explicit_nonce: [u8; 8] = rec.explicit_nonce.clone().try_into().map_err(
                        |explicit_nonce: Vec<_>| ErrorRepr::ExplicitNonceLength {
                            expected: 8,
                            actual: explicit_nonce.len(),
                        },
                    )?;

                    vm.assign(block.explicit_nonce, explicit_nonce)
                        .map_err(TagProofError::vm)?;
                    vm.commit(block.explicit_nonce).map_err(TagProofError::vm)?;

                    (block.counter, block.output)
                }
                TlsVersion::V1_3 => {
                    let block = aes.alloc_ctr_block_tls13(vm).map_err(TagProofError::vm)?;

                    // TLS 1.3 records carry no explicit nonce; the public nonce
                    // component is the sequence-number pad `0^4 || seq_be64`,
                    // assigned to the `seq_pad` slot exposed as `explicit_nonce`.
                    let mut seq_pad = [0u8; 12];
                    seq_pad[4..].copy_from_slice(&rec.seq.to_be_bytes());

                    vm.assign(block.explicit_nonce, seq_pad)
                        .map_err(TagProofError::vm)?;
                    vm.commit(block.explicit_nonce).map_err(TagProofError::vm)?;

                    (block.counter, block.output)
                }
            };

            // j0's counter is set to 1.
            vm.assign(counter, 1u32.to_be_bytes())
                .map_err(TagProofError::vm)?;
            vm.commit(counter).map_err(TagProofError::vm)?;

            let j0 = vm.decode(output).map_err(TagProofError::vm)?;

            Ok(j0)
        })
        .collect::<Result<Vec<_>, TagProofError>>()?;

    let mac_key = vm.decode(mac_key).map_err(TagProofError::vm)?;

    Ok(TagProof {
        tls_version,
        j0s,
        records,
        mac_key,
    })
}

/// Proof of tag verification.
#[derive(Debug)]
#[must_use]
pub(crate) struct TagProof {
    tls_version: TlsVersion,
    /// The j0 block for each record.
    j0s: Vec<DecodeFutureTyped<BitVec, [u8; 16]>>,
    records: Vec<Record>,
    /// The MAC key for tag computation.
    mac_key: DecodeFutureTyped<BitVec, [u8; 16]>,
}

impl TagProof {
    /// Verifies the proof.
    pub(crate) fn verify(self) -> Result<(), TagProofError> {
        let Self {
            tls_version,
            j0s,
            mut mac_key,
            records,
        } = self;

        let mac_key = mac_key
            .try_recv()
            .map_err(TagProofError::vm)?
            .ok_or_else(|| ErrorRepr::NotDecoded)?;

        for (mut j0, rec) in j0s.into_iter().zip(records) {
            let j0 = j0
                .try_recv()
                .map_err(TagProofError::vm)?
                .ok_or_else(|| ErrorRepr::NotDecoded)?;

            // The AAD shape differs by version: TLS 1.2 binds seq/type/version
            // explicitly, whereas TLS 1.3 uses the wire constants and the body
            // length including the 16-byte tag (`Record.ciphertext` excludes
            // the tag).
            let ghash_tag = match tls_version {
                TlsVersion::V1_2 => {
                    let aad = make_tls12_aad(
                        rec.seq,
                        rec.typ.into(),
                        ProtocolVersion::TLSv1_2,
                        rec.ciphertext.len(),
                    );
                    ghash(aad.as_ref(), &rec.ciphertext, &mac_key)
                }
                TlsVersion::V1_3 => {
                    let aad = make_tls13_aad(rec.ciphertext.len() + 16);
                    ghash(aad.as_ref(), &rec.ciphertext, &mac_key)
                }
            };

            let record_tag = match rec.tag.as_ref() {
                Some(tag) => tag,
                None => {
                    // This will never happen, since we only call this method
                    // for proofs where the records' tags are known.
                    return Err(ErrorRepr::UnknownTag.into());
                }
            };

            if *record_tag
                != ghash_tag
                    .into_iter()
                    .zip(j0)
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>()
            {
                return Err(ErrorRepr::InvalidTag.into());
            }
        }

        Ok(())
    }
}

/// Error for [`J0Proof`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct TagProofError(#[from] ErrorRepr);

impl TagProofError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("j0 proof error: {0}")]
enum ErrorRepr {
    #[error("value was not decoded")]
    NotDecoded,
    #[error("VM error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("tag does not match expected")]
    InvalidTag,
    #[error("tag is not known")]
    UnknownTag,
    #[error("invalid explicit nonce length: expected {expected}, got {actual}")]
    ExplicitNonceLength { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::{
        Aes128 as AesCipher,
        cipher::{BlockEncrypt, KeyInit as _},
    };
    use aes_gcm::{
        Aes128Gcm, Key, Nonce,
        aead::{Aead, NewAead, Payload},
    };
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::Execute;
    use tlsn_core::transcript::ContentType;

    // Test key/IV material, reused across the cases.
    const KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const IV12: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
    ];
    const IV4: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    /// GHASH key `H = AES_K(0^16)`.
    fn ghash_key(key: [u8; 16]) -> [u8; 16] {
        let mut block = [0u8; 16].into();
        let cipher = AesCipher::new(&key.into());
        cipher.encrypt_block(&mut block);
        block.into()
    }

    /// Seals `plaintext` with AES-128-GCM, returning `(ciphertext, tag)` with
    /// the 16-byte tag split out.
    fn gcm_seal(
        key: [u8; 16],
        nonce12: [u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let cipher = Aes128Gcm::new(Key::from_slice(&key));
        let mut out = cipher
            .encrypt(
                Nonce::from_slice(&nonce12),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("gcm encryption succeeds");
        let tag = out.split_off(out.len() - 16);
        (out, tag)
    }

    /// Builds a real TLS 1.3 application-data record for sequence `seq`.
    fn make_tls13_record(key: [u8; 16], iv12: [u8; 12], seq: u64, plaintext: &[u8]) -> Record {
        // nonce = write_iv XOR (0^4 || seq_be64).
        let mut nonce = iv12;
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }

        let aad = make_tls13_aad(plaintext.len() + 16);
        let (ciphertext, tag) = gcm_seal(key, nonce, aad.as_ref(), plaintext);

        Record {
            seq,
            typ: ContentType::ApplicationData,
            plaintext: None,
            explicit_nonce: Vec::new(),
            ciphertext,
            tag: Some(tag),
        }
    }

    /// Builds a real TLS 1.2 application-data record for sequence `seq`.
    fn make_tls12_record(
        key: [u8; 16],
        iv4: [u8; 4],
        explicit_nonce: [u8; 8],
        seq: u64,
        plaintext: &[u8],
    ) -> Record {
        // nonce = implicit_iv(4) || explicit_nonce(8).
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv4);
        nonce[4..].copy_from_slice(&explicit_nonce);

        let typ = ContentType::ApplicationData;
        let aad = make_tls12_aad(seq, typ.into(), ProtocolVersion::TLSv1_2, plaintext.len());
        let (ciphertext, tag) = gcm_seal(key, nonce, aad.as_ref(), plaintext);

        Record {
            seq,
            typ,
            plaintext: None,
            explicit_nonce: explicit_nonce.to_vec(),
            ciphertext,
            tag: Some(tag),
        }
    }

    /// Allocates and commits a public array reference in `vm`.
    fn alloc_public<const N: usize>(vm: &mut IdealVm, value: [u8; N]) -> Array<U8, N> {
        let r: Array<U8, N> = vm.alloc().unwrap();
        vm.mark_public(r).unwrap();
        vm.assign(r, value).unwrap();
        vm.commit(r).unwrap();
        r
    }

    /// Drives two `IdealVm`s (the 2PC garbler/evaluator pair) through the tag
    /// proof and returns the verifier-side verification result, mirroring the
    /// production `verify_tags` + `execute_all` + `verify` flow.
    async fn run<F>(records: Vec<Record>, mut setup: F) -> Result<(), TagProofError>
    where
        F: FnMut(&mut IdealVm, Vec<Record>) -> Result<TagProof, TagProofError>,
    {
        let (mut ctx_a, mut ctx_b) = test_st_context(1024);
        let mut gen_vm = IdealVm::new();
        let mut ev = IdealVm::new();

        let proof_gen = setup(&mut gen_vm, records.clone()).expect("prover-side setup");
        let proof_ev = setup(&mut ev, records).expect("verifier-side setup");

        tokio::try_join!(async { gen_vm.execute_all(&mut ctx_a).await }, async {
            ev.execute_all(&mut ctx_b).await
        },)
        .unwrap();

        // The prover discards its proof output (as in production); the
        // verifier-side result is the one under test.
        let _ = proof_gen.verify();
        proof_ev.verify()
    }

    fn setup_v1_3(
        vm: &mut IdealVm,
        mac_key: [u8; 16],
        records: Vec<Record>,
    ) -> Result<TagProof, TagProofError> {
        let key = alloc_public(vm, KEY);
        let iv = alloc_public(vm, IV12);
        let mac_key = alloc_public(vm, mac_key);
        verify_tags(vm, TagKeyIv::V1_3 { key, iv }, mac_key, records)
    }

    fn setup_v1_2(
        vm: &mut IdealVm,
        mac_key: [u8; 16],
        records: Vec<Record>,
    ) -> Result<TagProof, TagProofError> {
        let key = alloc_public(vm, KEY);
        let iv = alloc_public(vm, IV4);
        let mac_key = alloc_public(vm, mac_key);
        verify_tags(vm, TagKeyIv::V1_2 { key, iv }, mac_key, records)
    }

    #[tokio::test]
    async fn test_verify_tags_tls13_ok() {
        let mac_key = ghash_key(KEY);
        let record = make_tls13_record(KEY, IV12, 0, b"hello tls 1.3 record");

        run(vec![record], |vm, recs| setup_v1_3(vm, mac_key, recs))
            .await
            .expect("valid tls 1.3 tag verifies");
    }

    #[tokio::test]
    async fn test_verify_tags_tls13_bad_tag() {
        let mac_key = ghash_key(KEY);
        let mut record = make_tls13_record(KEY, IV12, 0, b"hello tls 1.3 record");

        // Flip a byte of the tag.
        record.tag.as_mut().unwrap()[0] ^= 0x01;

        let err = run(vec![record], |vm, recs| setup_v1_3(vm, mac_key, recs))
            .await
            .expect_err("tampered tag must fail verification");
        assert!(matches!(err.0, ErrorRepr::InvalidTag));
    }

    #[tokio::test]
    async fn test_verify_tags_tls13_multi_seq() {
        let mac_key = ghash_key(KEY);

        // Two records under the same key/IV but different sequence numbers, so
        // the j0 nonce must be derived from `seq` for both to verify.
        let rec0 = make_tls13_record(KEY, IV12, 0, b"first record, seq 0");
        let rec1 = make_tls13_record(KEY, IV12, 1, b"second record, seq 1 with a longer body!");

        run(vec![rec0, rec1], |vm, recs| setup_v1_3(vm, mac_key, recs))
            .await
            .expect("multi-seq tls 1.3 tags verify");
    }

    #[tokio::test]
    async fn test_verify_tags_tls12_ok() {
        let mac_key = ghash_key(KEY);
        let record = make_tls12_record(KEY, IV4, [0x11; 8], 0, b"hello tls 1.2 record");

        run(vec![record], |vm, recs| setup_v1_2(vm, mac_key, recs))
            .await
            .expect("valid tls 1.2 tag verifies");
    }
}
