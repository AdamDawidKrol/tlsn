use std::sync::Arc;

use aes::Aes128;
use ctr::{
    Ctr32BE,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
};
use mpz_circuits::{AES128, circuits::xor};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, CallableExt, Vm};
use rangeset::{iter::RangeIterator, ops::Set, set::RangeSet};
use tlsn_core::transcript::{ContentType, Record};

use crate::transcript_internal::ReferenceMap;

/// The TLS 1.3 application-data inner content type (RFC 8446 §5.1).
const APPLICATION_DATA: u8 = 0x17;

/// The TLS 1.3 inner content-type byte for a [`ContentType`] (RFC 8446 §5.1).
/// Used to derive each record's declared suffix type byte (parent
/// metadata-channel spec §4).
fn content_type_byte(typ: ContentType) -> u8 {
    match typ {
        ContentType::ChangeCipherSpec => 0x14,
        ContentType::Alert => 0x15,
        ContentType::Handshake => 0x16,
        ContentType::ApplicationData => 0x17,
        ContentType::Heartbeat => 0x18,
        ContentType::Unknown(id) => id,
    }
}
/// AES-CTR counter for the first keystream block (J0 = 1 is reserved for the
/// GHASH tag in both TLS 1.2 and 1.3, RFC 5288 / RFC 8446 §5.3).
const START_CTR: u32 = 2;
const BLOCK_SIZE: usize = 16;

/// Version-tagged AEAD key material.
///
/// The TLS version is *derived from the IV width* rather than carried as a
/// separate flag: TLS 1.2 records carry an 8-byte explicit nonce alongside a
/// 4-byte implicit IV, whereas TLS 1.3 derives the 12-byte per-record nonce
/// from the 12-byte IV and the record sequence number (RFC 8446 §5.3).
pub(crate) enum CipherParams {
    V1_2 {
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
    },
    V1_3 {
        key: Array<U8, 16>,
        iv: Array<U8, 12>,
    },
}

impl CipherParams {
    fn key(&self) -> Array<U8, 16> {
        match self {
            CipherParams::V1_2 { key, .. } | CipherParams::V1_3 { key, .. } => *key,
        }
    }

    fn is_v1_3(&self) -> bool {
        matches!(self, CipherParams::V1_3 { .. })
    }
}

pub(crate) fn prove_plaintext<'a>(
    vm: &mut dyn Vm<Binary>,
    cipher: CipherParams,
    plaintext: &[u8],
    records: impl IntoIterator<Item = &'a Record>,
    reveal: &RangeSet<usize>,
    commit: &RangeSet<usize>,
) -> Result<ReferenceMap, PlaintextAuthError> {
    let is_reveal_all = reveal == (0..plaintext.len());

    let alloc_ranges = if is_reveal_all {
        commit.clone()
    } else {
        // The plaintext is only partially revealed, so we need to authenticate in ZK.
        commit.union(reveal).into_set()
    };

    let plaintext_refs = alloc_plaintext(vm, &alloc_ranges)?;
    let records = RecordParams::from_records(&cipher, records).collect::<Vec<_>>();

    if is_reveal_all {
        drop(vm.decode(cipher.key()).map_err(PlaintextAuthError::vm)?);
        match &cipher {
            CipherParams::V1_2 { iv, .. } => {
                drop(vm.decode(*iv).map_err(PlaintextAuthError::vm)?);
            }
            CipherParams::V1_3 { iv, .. } => {
                drop(vm.decode(*iv).map_err(PlaintextAuthError::vm)?);
            }
        }

        for (range, slice) in plaintext_refs.iter() {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }
    } else {
        let private = commit.difference(reveal).into_set();
        for (_, slice) in plaintext_refs
            .index(&private)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_private(*slice).map_err(PlaintextAuthError::vm)?;
        }

        for (_, slice) in plaintext_refs
            .index(reveal)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
        }

        for (range, slice) in plaintext_refs.iter() {
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }

        // Translate the content references into record-ciphertext coordinates and
        // append the per-record `type || padding` suffix (TLS 1.3); identity for
        // TLS 1.2.
        let cipher_refs = build_cipher_refs(vm, &cipher, &plaintext_refs, &records)?;
        let ciphertext = alloc_ciphertext(vm, &cipher, cipher_refs, &records)?;
        for (_, slice) in ciphertext.iter() {
            drop(vm.decode(*slice).map_err(PlaintextAuthError::vm)?);
        }
    }

    Ok(plaintext_refs)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_plaintext<'a>(
    vm: &mut dyn Vm<Binary>,
    cipher: CipherParams,
    plaintext: &'a [u8],
    ciphertext: &'a [u8],
    records: impl IntoIterator<Item = &'a Record>,
    reveal: &RangeSet<usize>,
    commit: &RangeSet<usize>,
) -> Result<(ReferenceMap, PlaintextProof<'a>), PlaintextAuthError> {
    let is_reveal_all = reveal == (0..plaintext.len());

    let alloc_ranges = if is_reveal_all {
        commit.clone()
    } else {
        // The plaintext is only partially revealed, so we need to authenticate in ZK.
        commit.union(reveal).into_set()
    };

    let plaintext_refs = alloc_plaintext(vm, &alloc_ranges)?;
    let records = RecordParams::from_records(&cipher, records).collect::<Vec<_>>();

    let plaintext_proof = if is_reveal_all {
        let key = vm.decode(cipher.key()).map_err(PlaintextAuthError::vm)?;
        let iv = match &cipher {
            CipherParams::V1_2 { iv, .. } => {
                IvDecode::V1_2(vm.decode(*iv).map_err(PlaintextAuthError::vm)?)
            }
            CipherParams::V1_3 { iv, .. } => {
                IvDecode::V1_3(vm.decode(*iv).map_err(PlaintextAuthError::vm)?)
            }
        };

        for (range, slice) in plaintext_refs.iter() {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }

        PlaintextProof(ProofInner::WithKey {
            key,
            iv,
            records,
            plaintext,
            ciphertext,
        })
    } else {
        let private = commit.difference(reveal).into_set();
        for (_, slice) in plaintext_refs
            .index(&private)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_blind(*slice).map_err(PlaintextAuthError::vm)?;
        }

        for (range, slice) in plaintext_refs
            .index(reveal)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
        }

        for (_, slice) in plaintext_refs.iter() {
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }

        let cipher_refs = build_cipher_refs(vm, &cipher, &plaintext_refs, &records)?;
        let ciphertext_map = alloc_ciphertext(vm, &cipher, cipher_refs, &records)?;

        // The decoded in-VM ciphertext (content XOR keystream plus, for TLS 1.3,
        // the public `type || padding` suffix XOR keystream) is compared against
        // the wire ciphertext in record-ciphertext coordinates. A suffix whose
        // type byte differs from the record's declared inner type, whose padding
        // is non-zero, or whose content boundary the prover misdeclared
        // therefore fails as `InvalidPlaintext` (locked classification, §5).
        let mut ciphertexts = Vec::new();
        for (range, chunk) in ciphertext_map.iter() {
            ciphertexts.push((
                &ciphertext[range],
                vm.decode(*chunk).map_err(PlaintextAuthError::vm)?,
            ));
        }

        PlaintextProof(ProofInner::WithZk { ciphertexts })
    };

    Ok((plaintext_refs, plaintext_proof))
}

fn alloc_plaintext(
    vm: &mut dyn Vm<Binary>,
    ranges: &RangeSet<usize>,
) -> Result<ReferenceMap, PlaintextAuthError> {
    let len = ranges.len();

    if len == 0 {
        return Ok(ReferenceMap::default());
    }

    let plaintext = vm.alloc_vec::<U8>(len).map_err(PlaintextAuthError::vm)?;

    let mut pos = 0;
    Ok(ReferenceMap::from_iter(ranges.iter().map(move |range| {
        let chunk = plaintext
            .get(pos..pos + range.len())
            .expect("length was checked");
        pos += range.len();
        (range.start, chunk)
    })))
}

/// Translates the content `plaintext_refs` (transcript coordinates) into
/// record-ciphertext coordinates and, for TLS 1.3, appends the per-record
/// `type || padding` suffix references.
///
/// For TLS 1.2 `content_len == inner_len` and the transcript base equals the
/// record-ciphertext base for every record, so the mapping is the identity and
/// the original references are returned unchanged. For TLS 1.3 each content
/// reference is split at record boundaries and shifted by the running gap
/// between transcript coordinates (sum of `content_len`) and record-ciphertext
/// coordinates (sum of `inner_len`). The returned map references the *same* VM
/// slices for content (so commitments stay consistent) but is keyed in
/// record-ciphertext coordinates for the keystream/consistency proof; the
/// caller keeps `plaintext_refs` for transcript-coordinate commitment logic.
fn build_cipher_refs(
    vm: &mut dyn Vm<Binary>,
    cipher: &CipherParams,
    plaintext_refs: &ReferenceMap,
    records: &[RecordParams],
) -> Result<ReferenceMap, PlaintextAuthError> {
    if !cipher.is_v1_3() {
        return Ok(plaintext_refs.clone());
    }

    let mut entries: Vec<(usize, Vector<U8>)> = Vec::new();
    let mut t_base = 0;
    let mut c_base = 0;
    for record in records {
        // Only application-data records contribute content to the transcript
        // coordinate space (`plaintext_refs`); non-app-data records (NST /
        // KeyUpdate / alert, parent spec §5) keep their content blind and only
        // have their `type || padding` suffix proven, so `t_base` does not
        // advance for them.
        if record.is_app_data {
            // Content lives at the start of the inner plaintext, so a transcript
            // offset `o` maps to record-ciphertext offset `o` within the record.
            for (range, _) in plaintext_refs.iter() {
                let start = range.start.max(t_base);
                let end = range.end.min(t_base + record.content_len);
                if start < end {
                    let slice = plaintext_refs
                        .get(start..end)
                        .expect("content range is within an allocated reference");
                    entries.push((c_base + (start - t_base), slice));
                }
            }
            t_base += record.content_len;
        }

        // The trailing `type || padding` suffix is public and always proven,
        // for *every* app-epoch record (locked classification, parent spec §5):
        // the declared inner type is pinned by the suffix matching the wire
        // ciphertext.
        let suffix_len = record.inner_len - record.content_len;
        if suffix_len > 0 {
            let suffix = alloc_suffix(vm, suffix_len, record.inner_type)?;
            entries.push((c_base + record.content_len, suffix));
        }

        c_base += record.inner_len;
    }

    Ok(ReferenceMap::from_iter(entries))
}

/// Allocates and publicly assigns a TLS 1.3 record suffix `inner_type ||
/// 0x00*p` (the declared inner content type followed by zero padding, parent
/// spec §4). `inner_type` is `0x17` for application data, `0x16` for a
/// NewSessionTicket/KeyUpdate, `0x15` for an alert, etc. A mis-declared type
/// (or a content boundary that places this byte over real content/padding)
/// makes the disclosed suffix fail to match the wire ciphertext.
fn alloc_suffix(
    vm: &mut dyn Vm<Binary>,
    len: usize,
    inner_type: u8,
) -> Result<Vector<U8>, PlaintextAuthError> {
    let suffix = vm.alloc_vec::<U8>(len).map_err(PlaintextAuthError::vm)?;
    vm.mark_public(suffix).map_err(PlaintextAuthError::vm)?;
    let mut bytes = vec![0u8; len];
    bytes[0] = inner_type;
    vm.assign(suffix, bytes).map_err(PlaintextAuthError::vm)?;
    vm.commit(suffix).map_err(PlaintextAuthError::vm)?;

    Ok(suffix)
}

fn alloc_ciphertext(
    vm: &mut dyn Vm<Binary>,
    cipher: &CipherParams,
    plaintext: ReferenceMap,
    records: &[RecordParams],
) -> Result<ReferenceMap, PlaintextAuthError> {
    if plaintext.is_empty() {
        return Ok(ReferenceMap::default());
    }

    let ranges = RangeSet::from(plaintext.keys().collect::<Vec<_>>());

    let keystream = alloc_keystream(vm, cipher, &ranges, records)?;
    let mut builder = Call::builder(Arc::new(xor(ranges.len() * 8)));
    for (_, slice) in plaintext.iter() {
        builder = builder.arg(*slice);
    }
    for slice in keystream {
        builder = builder.arg(slice);
    }
    let call = builder.build().expect("call should be valid");

    let ciphertext: Vector<U8> = vm.call(call).map_err(PlaintextAuthError::vm)?;

    let mut pos = 0;
    Ok(ReferenceMap::from_iter(ranges.iter().map(move |range| {
        let chunk = ciphertext
            .get(pos..pos + range.len())
            .expect("length was checked");
        pos += range.len();
        (range.start, chunk)
    })))
}

/// Allocates the AES-CTR keystream covering `ranges`, expressed in
/// record-ciphertext coordinates (i.e. `record.inner_len` per record).
fn alloc_keystream(
    vm: &mut dyn Vm<Binary>,
    cipher: &CipherParams,
    ranges: &RangeSet<usize>,
    records: &[RecordParams],
) -> Result<Vec<Vector<U8>>, PlaintextAuthError> {
    let key = cipher.key();
    let mut keystream = Vec::new();

    let mut pos = 0;
    let mut range_iter = ranges.iter();
    let mut current_range = range_iter.next();
    for record in records {
        // The per-record nonce is shared across that record's blocks.
        let mut nonce: Option<(Vector<U8>, Vector<U8>)> = None;
        let mut current_block = None;
        loop {
            let Some(range) = current_range.take().or_else(|| range_iter.next()) else {
                return Ok(keystream);
            };

            let record_range = pos..pos + record.inner_len;
            if range.start >= record_range.end {
                current_range = Some(range);
                break;
            }

            // Range with record offset applied.
            let offset_range = range.start - pos..range.end - pos;

            let (iv_part, nonce_part) = if let Some(nonce) = nonce {
                nonce
            } else {
                let parts = alloc_nonce(vm, cipher, record)?;
                nonce = Some(parts);
                parts
            };

            let block_num = offset_range.start / BLOCK_SIZE;
            let block = if let Some((current_block_num, block)) = current_block.take()
                && current_block_num == block_num
            {
                block
            } else {
                let block = alloc_block(vm, key, iv_part, nonce_part, block_num)?;
                current_block = Some((block_num, block));
                block
            };

            // Range within the block.
            let block_range_start = offset_range.start % BLOCK_SIZE;
            let len =
                (range.end.min(record_range.end) - range.start).min(BLOCK_SIZE - block_range_start);
            let block_range = block_range_start..block_range_start + len;

            keystream.push(block.get(block_range).expect("range is checked"));

            // If the range extends past the block, process the tail.
            if range.start + len < range.end {
                current_range = Some(range.start + len..range.end);
            }
        }

        pos += record.inner_len;
    }

    Err(ErrorRepr::OutOfBounds.into())
}

/// Allocates the per-record AES input nonce, split into the 4-byte and 8-byte
/// slices the `AES128` circuit consumes (it concatenates `iv(4) || nonce(8) ||
/// ctr(4)` into the 16-byte input block).
///
/// * TLS 1.2: `(implicit_iv4, explicit_nonce8)`.
/// * TLS 1.3: `nonce12 = iv12 XOR (0^4 || seq_be64)` (RFC 8446 §5.3), sliced
///   into `nonce12[0..4]` and `nonce12[4..12]`. This is the same in-VM XOR /
///   slice-into-`AES128` technique validated in item 3
///   (`crates/components/cipher/src/aes/mod.rs`).
fn alloc_nonce(
    vm: &mut dyn Vm<Binary>,
    cipher: &CipherParams,
    record: &RecordParams,
) -> Result<(Vector<U8>, Vector<U8>), PlaintextAuthError> {
    match cipher {
        CipherParams::V1_2 { iv, .. } => {
            let explicit_nonce = alloc_explicit_nonce(vm, record.explicit_nonce.clone())?;
            Ok((Vector::from(*iv), explicit_nonce))
        }
        CipherParams::V1_3 { iv, .. } => {
            let nonce12 = alloc_tls13_nonce(vm, *iv, record.seq)?;
            let iv_part = nonce12.get(0..4).expect("nonce slice 0..4 is in bounds");
            let nonce_part = nonce12.get(4..12).expect("nonce slice 4..12 is in bounds");
            Ok((iv_part, nonce_part))
        }
    }
}

fn alloc_explicit_nonce(
    vm: &mut dyn Vm<Binary>,
    explicit_nonce: Vec<u8>,
) -> Result<Vector<U8>, PlaintextAuthError> {
    const EXPLICIT_NONCE_LEN: usize = 8;
    let nonce = vm
        .alloc_vec::<U8>(EXPLICIT_NONCE_LEN)
        .map_err(PlaintextAuthError::vm)?;
    vm.mark_public(nonce).map_err(PlaintextAuthError::vm)?;
    vm.assign(nonce, explicit_nonce)
        .map_err(PlaintextAuthError::vm)?;
    vm.commit(nonce).map_err(PlaintextAuthError::vm)?;

    Ok(nonce)
}

/// Computes the TLS 1.3 per-record AEAD nonce in the VM:
/// `nonce12 = iv12 XOR (0x00000000 || seq.to_be_bytes())`.
fn alloc_tls13_nonce(
    vm: &mut dyn Vm<Binary>,
    iv: Array<U8, 12>,
    seq: u64,
) -> Result<Vector<U8>, PlaintextAuthError> {
    let seq_pad: Array<U8, 12> = vm.alloc().map_err(PlaintextAuthError::vm)?;
    vm.mark_public(seq_pad).map_err(PlaintextAuthError::vm)?;
    vm.assign(seq_pad, tls13_seq_pad(seq))
        .map_err(PlaintextAuthError::vm)?;
    vm.commit(seq_pad).map_err(PlaintextAuthError::vm)?;

    let nonce12: Vector<U8> = vm
        .call(
            Call::builder(Arc::new(xor(96)))
                .arg(iv)
                .arg(seq_pad)
                .build()
                .expect("xor call should be valid"),
        )
        .map_err(PlaintextAuthError::vm)?;

    Ok(nonce12)
}

/// Builds the TLS 1.3 sequence-number pad `0x00000000 || seq.to_be_bytes()`.
fn tls13_seq_pad(seq: u64) -> [u8; 12] {
    let mut seq_pad = [0u8; 12];
    seq_pad[4..12].copy_from_slice(&seq.to_be_bytes());
    seq_pad
}

fn alloc_block(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Vector<U8>,
    nonce: Vector<U8>,
    block: usize,
) -> Result<Vector<U8>, PlaintextAuthError> {
    let ctr: Array<U8, 4> = vm.alloc().map_err(PlaintextAuthError::vm)?;
    vm.mark_public(ctr).map_err(PlaintextAuthError::vm)?;
    vm.assign(ctr, (START_CTR + block as u32).to_be_bytes())
        .map_err(PlaintextAuthError::vm)?;
    vm.commit(ctr).map_err(PlaintextAuthError::vm)?;

    // `Call` matches arguments by bit-length, so feeding `Vector<U8>` slices into
    // the iv(4) / nonce(8) slots the 1.2 path fills with `Array<U8, 4>` /
    // `Array<U8, 8>` is sound (see item 3's `AES128_POST_KS` usage).
    let block: Array<U8, 16> = vm
        .call(
            Call::builder(AES128.clone())
                .arg(key)
                .arg(iv)
                .arg(nonce)
                .arg(ctr)
                .build()
                .expect("call should be valid"),
        )
        .map_err(PlaintextAuthError::vm)?;

    Ok(Vector::from(block))
}

struct RecordParams {
    /// TLS 1.2 explicit nonce (8 bytes); empty/ignored for TLS 1.3.
    explicit_nonce: Vec<u8>,
    /// TLS 1.3 per-epoch sequence number used to derive the nonce; ignored for
    /// TLS 1.2.
    seq: u64,
    /// Full inner-plaintext length (`record.ciphertext.len()`).
    inner_len: usize,
    /// Application-content length. TLS 1.2: `content_len == inner_len`. TLS
    /// 1.3: `inner_len - 1 - padding`, i.e. the inner plaintext minus the
    /// 1-byte content type and trailing zero padding.
    content_len: usize,
    /// TLS 1.3 inner content-type byte assigned to this record's suffix (parent
    /// spec §4). `0x17` for TLS 1.2 (the suffix path is 1.3-only).
    inner_type: u8,
    /// Whether this record's content belongs to the application transcript
    /// (TLS 1.3 `application_data`, and always `true` for TLS 1.2).
    /// Non-app-data records (NST / KeyUpdate / alert) contribute no
    /// transcript content; only their `type || padding` suffix is proven
    /// (parent spec §5).
    is_app_data: bool,
}

impl RecordParams {
    /// Builds [`RecordParams`] from the app-epoch record list.
    ///
    /// `content_len` determination:
    /// * TLS 1.2: there is no inner type/padding, so `content_len ==
    ///   inner_len`.
    /// * TLS 1.3: prefer the framed [`Record::content_len`] (set by the prover
    ///   from the decrypted content, and by the verifier from the prover-
    ///   declared metadata — validated by the suffix proof). Fall back to the
    ///   decrypted `record.plaintext` length, then to `inner_len`.
    ///
    /// `inner_type`/`is_app_data` are derived from the framed [`Record::typ`]
    /// (the proven inner type, parent spec §5). For TLS 1.2 every record is
    /// treated as application data and the suffix path is unused.
    fn from_records<'a>(
        cipher: &CipherParams,
        records: impl IntoIterator<Item = &'a Record>,
    ) -> impl Iterator<Item = Self> {
        let is_v1_3 = cipher.is_v1_3();
        records.into_iter().map(move |record| {
            let inner_len = record.ciphertext.len();
            let (content_len, inner_type, is_app_data) = if is_v1_3 {
                let content_len = record
                    .content_len
                    .or_else(|| record.plaintext.as_ref().map(|p| p.len()))
                    .unwrap_or(inner_len);
                (
                    content_len,
                    content_type_byte(record.typ),
                    record.typ == ContentType::ApplicationData,
                )
            } else {
                (inner_len, APPLICATION_DATA, true)
            };
            Self {
                explicit_nonce: record.explicit_nonce.clone(),
                seq: record.seq,
                inner_len,
                content_len,
                inner_type,
                is_app_data,
            }
        })
    }
}

#[must_use]
pub(crate) struct PlaintextProof<'a>(ProofInner<'a>);

impl<'a> PlaintextProof<'a> {
    pub(crate) fn verify(self) -> Result<(), PlaintextAuthError> {
        match self.0 {
            ProofInner::WithKey {
                mut key,
                iv,
                records,
                plaintext,
                ciphertext,
            } => {
                let key = key
                    .try_recv()
                    .map_err(PlaintextAuthError::vm)?
                    .ok_or(ErrorRepr::MissingDecoding)?;
                let cipher = match iv {
                    IvDecode::V1_2(mut iv) => {
                        let iv = iv
                            .try_recv()
                            .map_err(PlaintextAuthError::vm)?
                            .ok_or(ErrorRepr::MissingDecoding)?;
                        SoftCipher::V1_2 { key, iv }
                    }
                    IvDecode::V1_3(mut iv) => {
                        let iv = iv
                            .try_recv()
                            .map_err(PlaintextAuthError::vm)?
                            .ok_or(ErrorRepr::MissingDecoding)?;
                        SoftCipher::V1_3 { key, iv }
                    }
                };

                verify_plaintext_with_key(&cipher, &records, plaintext, ciphertext)?;
            }
            ProofInner::WithZk { ciphertexts } => {
                for (expected, mut actual) in ciphertexts {
                    let actual = actual
                        .try_recv()
                        .map_err(PlaintextAuthError::vm)?
                        .ok_or(PlaintextAuthError(ErrorRepr::MissingDecoding))?;

                    if actual != expected {
                        return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Decoded write IV, version-tagged to match [`CipherParams`].
enum IvDecode {
    V1_2(DecodeFutureTyped<BitVec, [u8; 4]>),
    V1_3(DecodeFutureTyped<BitVec, [u8; 12]>),
}

enum ProofInner<'a> {
    WithKey {
        key: DecodeFutureTyped<BitVec, [u8; 16]>,
        iv: IvDecode,
        records: Vec<RecordParams>,
        plaintext: &'a [u8],
        ciphertext: &'a [u8],
    },
    WithZk {
        // (expected, actual)
        #[allow(clippy::type_complexity)]
        ciphertexts: Vec<(&'a [u8], DecodeFutureTyped<BitVec, Vec<u8>>)>,
    },
}

/// Decoded AEAD key material for the software (revealed-key) consistency check.
enum SoftCipher {
    V1_2 { key: [u8; 16], iv: [u8; 4] },
    V1_3 { key: [u8; 16], iv: [u8; 12] },
}

fn aes_ctr_apply_keystream(key: &[u8; 16], iv: &[u8; 4], explicit_nonce: &[u8], input: &mut [u8]) {
    let mut full_iv = [0u8; 16];
    full_iv[0..4].copy_from_slice(iv);
    full_iv[4..12].copy_from_slice(&explicit_nonce[..8]);

    let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
    cipher
        .try_seek(START_CTR * 16)
        .expect("start counter is less than keystream length");
    cipher.apply_keystream(input);
}

/// TLS 1.3 software keystream: `nonce = iv12 XOR (0^4 || seq_be64)`, then the
/// 16-byte CTR counter block is `nonce(12) || 0x00000000`, advanced to
/// `START_CTR`.
fn aes_ctr_apply_keystream_tls13(key: &[u8; 16], iv: &[u8; 12], seq: u64, input: &mut [u8]) {
    let seq_pad = tls13_seq_pad(seq);
    let mut full_iv = [0u8; 16];
    for i in 0..12 {
        full_iv[i] = iv[i] ^ seq_pad[i];
    }

    let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
    cipher
        .try_seek(START_CTR * 16)
        .expect("start counter is less than keystream length");
    cipher.apply_keystream(input);
}

/// Software consistency check used by the revealed-key (full-reveal) path.
///
/// `plaintext` is the application content (transcript coordinates,
/// `content_len` per application-data record); `ciphertext` is the wire
/// ciphertext (record-ciphertext coordinates, `inner_len` per record).
///
/// * TLS 1.2: each record's revealed content is re-encrypted and compared to
///   the wire ciphertext.
/// * TLS 1.3: the key is revealed, so the wire ciphertext is decrypted and the
///   `type || padding` suffix is checked against the record's declared
///   `inner_type` for **every** app-epoch record (locked classification, parent
///   spec §5). For application-data records the decrypted content must also
///   match the revealed transcript content; non-app-data records (NST /
///   KeyUpdate / alert) keep their content blind and only have their suffix
///   verified. A wrong content boundary, inner type, or non-zero padding all
///   surface as an `InvalidPlaintext` mismatch against the authenticated wire
///   ciphertext.
fn verify_plaintext_with_key(
    cipher: &SoftCipher,
    records: &[RecordParams],
    plaintext: &[u8],
    ciphertext: &[u8],
) -> Result<(), PlaintextAuthError> {
    let mut t_pos = 0;
    let mut c_pos = 0;
    let mut text = Vec::new();
    for record in records {
        match cipher {
            SoftCipher::V1_2 { key, iv } => {
                debug_assert_eq!(record.content_len, record.inner_len);
                text.clear();
                text.extend_from_slice(&plaintext[t_pos..t_pos + record.content_len]);
                aes_ctr_apply_keystream(key, iv, &record.explicit_nonce, &mut text);

                if text != ciphertext[c_pos..c_pos + record.inner_len] {
                    return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
                }
                t_pos += record.content_len;
            }
            SoftCipher::V1_3 { key, iv } => {
                // Recover the inner plaintext (`content || type || padding`) by
                // decrypting the wire ciphertext with the revealed key.
                let mut inner = ciphertext[c_pos..c_pos + record.inner_len].to_vec();
                aes_ctr_apply_keystream_tls13(key, iv, record.seq, &mut inner);

                // Validate the `type || padding` suffix against the declared
                // inner type (pins the inner type and the content boundary).
                if record.inner_len > record.content_len {
                    if inner[record.content_len] != record.inner_type {
                        return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
                    }
                    if inner[record.content_len + 1..record.inner_len]
                        .iter()
                        .any(|&b| b != 0)
                    {
                        return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
                    }
                }

                // Application-data content is part of the transcript and must
                // match what the prover revealed; non-app-data content stays
                // blind.
                if record.is_app_data {
                    if inner[..record.content_len] != plaintext[t_pos..t_pos + record.content_len] {
                        return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
                    }
                    t_pos += record.content_len;
                }
            }
        }

        c_pos += record.inner_len;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("plaintext authentication error: {0}")]
pub(crate) struct PlaintextAuthError(#[from] ErrorRepr);

impl PlaintextAuthError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("vm error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("plaintext out of bounds of records. This should never happen and is an internal bug.")]
    OutOfBounds,
    #[error("missing decoding")]
    MissingDecoding,
    #[error("plaintext does not match ciphertext")]
    InvalidPlaintext,
}

#[cfg(test)]
#[allow(clippy::all)]
mod tests {
    use super::*;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::prelude::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rstest::*;
    use std::ops::Range;

    fn build_vm(key: [u8; 16], iv: [u8; 4]) -> (IdealVm, CipherParams) {
        let mut vm = IdealVm::new();
        let key_ref = vm.alloc::<Array<U8, 16>>().unwrap();
        let iv_ref = vm.alloc::<Array<U8, 4>>().unwrap();

        vm.mark_public(key_ref).unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(key_ref).unwrap();
        vm.commit(iv_ref).unwrap();

        (
            vm,
            CipherParams::V1_2 {
                key: key_ref,
                iv: iv_ref,
            },
        )
    }

    fn build_vm_tls13(key: [u8; 16], iv: [u8; 12]) -> (IdealVm, CipherParams) {
        let mut vm = IdealVm::new();
        let key_ref = vm.alloc::<Array<U8, 16>>().unwrap();
        let iv_ref = vm.alloc::<Array<U8, 12>>().unwrap();

        vm.mark_public(key_ref).unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(key_ref).unwrap();
        vm.commit(iv_ref).unwrap();

        (
            vm,
            CipherParams::V1_3 {
                key: key_ref,
                iv: iv_ref,
            },
        )
    }

    fn expected_aes_ctr<'a>(
        key: [u8; 16],
        iv: [u8; 4],
        records: impl IntoIterator<Item = &'a RecordParams>,
        ranges: &RangeSet<usize>,
    ) -> Vec<u8> {
        let mut keystream = Vec::new();
        let mut pos = 0;
        for record in records {
            let mut record_keystream = vec![0u8; record.inner_len];
            aes_ctr_apply_keystream(&key, &iv, &record.explicit_nonce, &mut record_keystream);
            for mut range in ranges.iter() {
                range.start = range.start.max(pos);
                range.end = range.end.min(pos + record.inner_len);
                if range.start < range.end {
                    keystream
                        .extend_from_slice(&record_keystream[range.start - pos..range.end - pos]);
                }
            }
            pos += record.inner_len;
        }

        keystream
    }

    fn expected_aes_ctr_tls13<'a>(
        key: [u8; 16],
        iv: [u8; 12],
        records: impl IntoIterator<Item = &'a RecordParams>,
        ranges: &RangeSet<usize>,
    ) -> Vec<u8> {
        let mut keystream = Vec::new();
        let mut pos = 0;
        for record in records {
            let mut record_keystream = vec![0u8; record.inner_len];
            aes_ctr_apply_keystream_tls13(&key, &iv, record.seq, &mut record_keystream);
            for mut range in ranges.iter() {
                range.start = range.start.max(pos);
                range.end = range.end.min(pos + record.inner_len);
                if range.start < range.end {
                    keystream
                        .extend_from_slice(&record_keystream[range.start - pos..range.end - pos]);
                }
            }
            pos += record.inner_len;
        }

        keystream
    }

    #[rstest]
    #[case::single_record_empty([0], [])]
    #[case::multiple_empty_records_empty([0, 0], [])]
    #[case::multiple_records_empty([128, 64], [])]
    #[case::single_block_full([16], [0..16])]
    #[case::single_block_partial([16], [2..14])]
    #[case::partial_block_full([15], [0..15])]
    #[case::out_of_bounds([16], [0..17])]
    #[case::multiple_records_full([128, 63, 33, 15, 4], [0..243])]
    #[case::multiple_records_partial([128, 63, 33, 15, 4], [1..15, 16..17, 18..19, 126..130, 224..225, 242..243])]
    #[tokio::test]
    async fn test_alloc_keystream(
        #[case] record_lens: impl IntoIterator<Item = usize>,
        #[case] ranges: impl IntoIterator<Item = Range<usize>>,
    ) {
        let mut rng = StdRng::seed_from_u64(0);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 4];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        let mut total_len = 0;
        let records = record_lens
            .into_iter()
            .map(|len| {
                let mut explicit_nonce = [0u8; 8];
                rng.fill(&mut explicit_nonce);
                total_len += len;
                RecordParams {
                    explicit_nonce: explicit_nonce.to_vec(),
                    seq: 0,
                    inner_len: len,
                    content_len: len,
                    inner_type: APPLICATION_DATA,
                    is_app_data: true,
                }
            })
            .collect::<Vec<_>>();

        let ranges = RangeSet::from(ranges.into_iter().collect::<Vec<_>>());
        let is_out_of_bounds = ranges.end().unwrap_or(0) > total_len;

        let (mut ctx, _) = test_st_context(1024);
        let (mut vm, cipher) = build_vm(key, iv);

        let keystream = match alloc_keystream(&mut vm, &cipher, &ranges, &records) {
            Ok(_) if is_out_of_bounds => panic!("should be out of bounds"),
            Ok(keystream) => keystream,
            Err(PlaintextAuthError(ErrorRepr::OutOfBounds)) if is_out_of_bounds => {
                return;
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        vm.execute(&mut ctx).await.unwrap();

        let keystream: Vec<u8> = keystream
            .iter()
            .flat_map(|slice| vm.get(*slice).unwrap().unwrap())
            .collect();

        assert_eq!(keystream.len(), ranges.len());

        let expected = expected_aes_ctr(key, iv, &records, &ranges);

        assert_eq!(keystream, expected);
    }

    /// TLS 1.3 keystream over record-ciphertext coordinates: a 12-byte IV, a
    /// `seq`-derived XOR nonce, and records whose `inner_len = content_len + 1
    /// + p`. The in-VM keystream must equal the software reference.
    #[rstest]
    #[case::single_record_empty([(0, 0)], [])]
    #[case::single_block_full([(10, 5)], [0..16])]
    #[case::single_block_partial([(10, 5)], [2..14])]
    #[case::partial_block_full([(8, 6)], [0..15])]
    #[case::out_of_bounds([(10, 5)], [0..17])]
    #[case::multiple_records_full([(120, 7), (60, 2), (30, 2), (10, 4), (3, 0)], [0..255])]
    #[case::multiple_records_partial(
        [(120, 7), (60, 2), (30, 2), (10, 4), (3, 0)],
        [1..15, 16..17, 18..19, 126..130, 224..225, 254..255]
    )]
    #[tokio::test]
    async fn test_alloc_keystream_tls13(
        #[case] record_specs: impl IntoIterator<Item = (usize, usize)>,
        #[case] ranges: impl IntoIterator<Item = Range<usize>>,
    ) {
        let mut rng = StdRng::seed_from_u64(0);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        let mut total_len = 0;
        let records = record_specs
            .into_iter()
            .enumerate()
            .map(|(seq, (content_len, padding))| {
                // inner_len = content || type(1) || padding(p).
                let inner_len = content_len + 1 + padding;
                total_len += inner_len;
                RecordParams {
                    explicit_nonce: Vec::new(),
                    seq: seq as u64,
                    inner_len,
                    content_len,
                    inner_type: APPLICATION_DATA,
                    is_app_data: true,
                }
            })
            .collect::<Vec<_>>();

        let ranges = RangeSet::from(ranges.into_iter().collect::<Vec<_>>());
        let is_out_of_bounds = ranges.end().unwrap_or(0) > total_len;

        let (mut ctx, _) = test_st_context(1024);
        let (mut vm, cipher) = build_vm_tls13(key, iv);

        let keystream = match alloc_keystream(&mut vm, &cipher, &ranges, &records) {
            Ok(_) if is_out_of_bounds => panic!("should be out of bounds"),
            Ok(keystream) => keystream,
            Err(PlaintextAuthError(ErrorRepr::OutOfBounds)) if is_out_of_bounds => {
                return;
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        vm.execute(&mut ctx).await.unwrap();

        let keystream: Vec<u8> = keystream
            .iter()
            .flat_map(|slice| vm.get(*slice).unwrap().unwrap())
            .collect();

        assert_eq!(keystream.len(), ranges.len());

        let expected = expected_aes_ctr_tls13(key, iv, &records, &ranges);

        assert_eq!(keystream, expected);
    }

    #[rstest]
    #[case::single_record_empty([0])]
    #[case::single_record([32])]
    #[case::multiple_records([128, 63, 33, 15, 4])]
    #[case::multiple_records_with_empty([128, 63, 33, 0, 15, 4])]
    fn test_verify_plaintext_with_key(
        #[case] record_lens: impl IntoIterator<Item = usize>,
        #[values(false, true)] tamper: bool,
    ) {
        let mut rng = StdRng::seed_from_u64(0);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 4];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        let mut total_len = 0;
        let records = record_lens
            .into_iter()
            .map(|len| {
                let mut explicit_nonce = [0u8; 8];
                rng.fill(&mut explicit_nonce);
                total_len += len;
                RecordParams {
                    explicit_nonce: explicit_nonce.to_vec(),
                    seq: 0,
                    inner_len: len,
                    content_len: len,
                    inner_type: APPLICATION_DATA,
                    is_app_data: true,
                }
            })
            .collect::<Vec<_>>();

        let mut plaintext = vec![0u8; total_len];
        rng.fill(plaintext.as_mut_slice());

        let mut ciphertext = plaintext.clone();
        expected_aes_ctr(key, iv, &records, &(0..total_len).into())
            .iter()
            .zip(ciphertext.iter_mut())
            .for_each(|(key, pt)| {
                *pt ^= *key;
            });

        if tamper {
            plaintext.first_mut().map(|pt| *pt ^= 1);
        }

        let cipher = SoftCipher::V1_2 { key, iv };
        match verify_plaintext_with_key(&cipher, &records, &plaintext, &ciphertext) {
            Ok(_) if tamper && !plaintext.is_empty() => panic!("should be invalid"),
            Err(e) if !tamper => panic!("unexpected error: {:?}", e),
            _ => {}
        }
    }

    /// Negative kinds for the TLS 1.3 revealed-key consistency check.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Tls13Defect {
        None,
        /// Flip a content plaintext byte.
        Content,
        /// Encrypt an inner type byte other than `0x17`.
        BadType,
        /// Encrypt non-zero padding.
        BadPadding,
    }

    /// TLS 1.3 full inner plaintexts `content || 0x17 || 0^p` are encrypted
    /// with the seq-derived nonce; the revealed-key check must accept the
    /// honest case and reject a tampered content byte, a non-`0x17` inner
    /// type, or non-zero padding.
    #[rstest]
    #[case::single_record([(32, 3)])]
    #[case::multiple_records([(128, 0), (63, 7), (33, 1), (15, 4)])]
    #[case::multiple_records_with_empty([(128, 0), (0, 5), (15, 2)])]
    #[case::no_padding([(40, 0), (10, 0)])]
    fn test_verify_plaintext_with_key_tls13(
        #[case] record_specs: impl IntoIterator<Item = (usize, usize)>,
        #[values(
            Tls13Defect::None,
            Tls13Defect::Content,
            Tls13Defect::BadType,
            Tls13Defect::BadPadding
        )]
        defect: Tls13Defect,
    ) {
        let mut rng = StdRng::seed_from_u64(1);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        let records = record_specs
            .into_iter()
            .enumerate()
            .map(|(seq, (content_len, padding))| RecordParams {
                explicit_nonce: Vec::new(),
                seq: seq as u64,
                inner_len: content_len + 1 + padding,
                content_len,
                inner_type: APPLICATION_DATA,
                is_app_data: true,
            })
            .collect::<Vec<_>>();

        // Application content (transcript coordinates).
        let content_total = records.iter().map(|r| r.content_len).sum::<usize>();
        let mut plaintext = vec![0u8; content_total];
        rng.fill(plaintext.as_mut_slice());

        // Build the wire ciphertext from the honest (or deliberately defective)
        // inner plaintexts, then encrypt with the per-record nonce.
        let mut ciphertext = Vec::new();
        let mut t_pos = 0;
        for record in &records {
            let mut inner = Vec::with_capacity(record.inner_len);
            inner.extend_from_slice(&plaintext[t_pos..t_pos + record.content_len]);
            let type_byte = if defect == Tls13Defect::BadType {
                0x16 // handshake, not application_data
            } else {
                APPLICATION_DATA
            };
            inner.push(type_byte);
            inner.resize(record.inner_len, 0u8);
            if defect == Tls13Defect::BadPadding && record.inner_len > record.content_len + 1 {
                // Make the last padding byte non-zero.
                *inner.last_mut().unwrap() = 0xAA;
            }
            aes_ctr_apply_keystream_tls13(&key, &iv, record.seq, &mut inner);
            ciphertext.extend_from_slice(&inner);
            t_pos += record.content_len;
        }

        if defect == Tls13Defect::Content {
            // Flip a content byte (if any content exists).
            if let Some(b) = plaintext.first_mut() {
                *b ^= 1;
            }
        }

        // Whether this defect should be detectable for the given records.
        let expect_invalid = match defect {
            Tls13Defect::None => false,
            Tls13Defect::Content => content_total > 0,
            Tls13Defect::BadType => true,
            Tls13Defect::BadPadding => records.iter().any(|r| r.inner_len > r.content_len + 1),
        };

        let cipher = SoftCipher::V1_3 { key, iv };
        match verify_plaintext_with_key(&cipher, &records, &plaintext, &ciphertext) {
            Ok(_) if expect_invalid => panic!("should be invalid for defect {:?}", defect),
            Err(e) if !expect_invalid => panic!("unexpected error: {:?} for {:?}", e, defect),
            _ => {}
        }
    }

    /// Locked classification (parent spec §5): the suffix is proven for *every*
    /// app-epoch record. A NewSessionTicket (inner type `0x16`, `is_app_data =
    /// false`) carries no transcript content, yet its `type || padding` suffix
    /// is verified against the declared inner type — so an honest declaration
    /// passes while a mis-declared type or content boundary is rejected.
    #[test]
    fn test_verify_plaintext_with_key_tls13_nst() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        // Record 0: application_data (content 32 + pad 3); record 1: a
        // NewSessionTicket (content 20 + pad 2), excluded from the transcript.
        let mk = |seq, content_len, pad, inner_type, is_app_data| RecordParams {
            explicit_nonce: Vec::new(),
            seq,
            inner_len: content_len + 1 + pad,
            content_len,
            inner_type,
            is_app_data,
        };
        let records = vec![
            mk(0, 32, 3, APPLICATION_DATA, true),
            mk(1, 20, 2, 0x16, false),
        ];

        // The application transcript holds only the app-data record's content.
        let mut plaintext = vec![0u8; 32];
        rng.fill(plaintext.as_mut_slice());
        // The NST's "content" never enters the transcript.
        let nst_content: Vec<u8> = (0..20u8).collect();

        // Builds the wire ciphertext with a chosen NST inner type / boundary.
        let build_ct = |nst_type: u8, nst_boundary: usize| -> Vec<u8> {
            let mut ct = Vec::new();

            let mut inner0 = plaintext.clone();
            inner0.push(APPLICATION_DATA);
            inner0.resize(records[0].inner_len, 0u8);
            aes_ctr_apply_keystream_tls13(&key, &iv, 0, &mut inner0);
            ct.extend_from_slice(&inner0);

            let mut inner1 = nst_content[..nst_boundary].to_vec();
            inner1.push(nst_type);
            inner1.resize(records[1].inner_len, 0u8);
            aes_ctr_apply_keystream_tls13(&key, &iv, 1, &mut inner1);
            ct.extend_from_slice(&inner1);

            ct
        };

        let cipher = SoftCipher::V1_3 { key, iv };

        // Honest: NST inner type 0x16 at the declared boundary -> accepted.
        let ct = build_ct(0x16, 20);
        verify_plaintext_with_key(&cipher, &records, &plaintext, &ct).unwrap();

        // Mis-declared type: the record carries 0x17 but is declared 0x16.
        let ct_bad_type = build_ct(0x17, 20);
        assert!(verify_plaintext_with_key(&cipher, &records, &plaintext, &ct_bad_type).is_err());

        // Mis-declared boundary: the type byte sits one position early, so the
        // declared suffix position holds zero padding (0x00 != 0x16).
        let ct_bad_boundary = build_ct(0x16, 19);
        assert!(
            verify_plaintext_with_key(&cipher, &records, &plaintext, &ct_bad_boundary).is_err()
        );
    }

    /// The transcript -> record-ciphertext coordinate translation: content
    /// references shift by the running `inner_len - content_len` gap and never
    /// cross into a suffix, suffix references occupy `[content_len, inner_len)`
    /// per record, and `plaintext_refs` stay in transcript coordinates.
    #[tokio::test]
    async fn test_range_translation() {
        // (content_len, padding) per record; inner_len = content_len + 1 + p.
        let specs = [(128usize, 7usize), (63, 2), (33, 2), (15, 4), (4, 0)];
        let records = specs
            .iter()
            .enumerate()
            .map(|(seq, &(content_len, padding))| RecordParams {
                explicit_nonce: Vec::new(),
                seq: seq as u64,
                inner_len: content_len + 1 + padding,
                content_len,
                inner_type: APPLICATION_DATA,
                is_app_data: true,
            })
            .collect::<Vec<_>>();

        // Transcript (content) coordinate ranges, mirroring `multiple_records_partial`.
        // Content bases: 0, 128, 191, 224, 239 (total 243).
        let content_ranges = RangeSet::from(vec![
            1..15,    // record 0
            126..130, // spans record 0 (..128) and record 1 (128..)
            191..192, // start of record 2
            239..243, // record 4 (last)
        ]);

        let mut vm = IdealVm::new();
        let key_ref = vm.alloc::<Array<U8, 16>>().unwrap();
        let iv_ref = vm.alloc::<Array<U8, 12>>().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(key_ref, [0u8; 16]).unwrap();
        vm.assign(iv_ref, [0u8; 12]).unwrap();
        vm.commit(key_ref).unwrap();
        vm.commit(iv_ref).unwrap();
        let cipher = CipherParams::V1_3 {
            key: key_ref,
            iv: iv_ref,
        };

        let plaintext_refs = alloc_plaintext(&mut vm, &content_ranges).unwrap();

        // `plaintext_refs` keys are unchanged transcript coordinates.
        assert_eq!(
            plaintext_refs.keys().collect::<Vec<_>>(),
            content_ranges.iter().collect::<Vec<_>>(),
        );

        let cipher_refs = build_cipher_refs(&mut vm, &cipher, &plaintext_refs, &records).unwrap();

        // Record-ciphertext bases (inner_len = content_len + 1 + p):
        //   R0 [0..136), R1 [136..202), R2 [202..238), R3 [238..258), R4 [258..263).
        // Transcript (content) bases: R0 0, R1 128, R2 191, R3 224, R4 239.
        let cipher_keys = cipher_refs.keys().collect::<Vec<_>>();
        let expected = vec![
            // R0 content [1..15)   -> shift +0
            1..15,
            // R0 content [126..128) (head of [126..130)) -> shift +0
            126..128,
            // R0 suffix: content_len 128, inner_len 136 -> [128..136)
            128..136,
            // R1 content [128..130) (tail of [126..130)) -> shift +8 -> [136..138)
            136..138,
            // R1 suffix: c_base 136 + content_len 63 -> [199..202)
            199..202,
            // R2 content [191..192) -> c_base 202 + (191-191) -> [202..203)
            202..203,
            // R2 suffix: c_base 202 + content_len 33 -> [235..238)
            235..238,
            // R3 suffix (no content revealed): c_base 238 + content_len 15 -> [253..258)
            253..258,
            // R4 content [239..243) -> c_base 258 + (239-239) -> [258..262)
            258..262,
            // R4 suffix: c_base 258 + content_len 4 -> [262..263)
            262..263,
        ];

        assert_eq!(cipher_keys, expected);
    }
}
