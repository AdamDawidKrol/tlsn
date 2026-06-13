use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::set::RangeSet;
use tlsn_core::{
    ProverOutput,
    config::prove::ProveConfig,
    connection::TlsVersion,
    transcript::{
        ContentType, Direction, Record, TlsTranscript, Transcript, TranscriptCommitment,
        TranscriptSecret,
    },
};

use crate::{
    Error, Result,
    proxy::ProxyKeys,
    transcript_internal::{TranscriptRefs, auth::prove_plaintext, commit::hash::prove_hash},
};

pub(crate) async fn prove<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &ProxyKeys,
    transcript: &Transcript,
    tls_transcript: &TlsTranscript,
    config: &ProveConfig,
) -> Result<ProverOutput> {
    let mut output = ProverOutput {
        transcript_commitments: Vec::default(),
        transcript_secrets: Vec::default(),
    };

    let (reveal_sent, reveal_recv) = config.reveal().cloned().unwrap_or_default();
    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = config.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|((direction, idx), _)| match direction {
                Direction::Sent => commit_sent.union_mut(idx),
                Direction::Received => commit_recv.union_mut(idx),
            });
    }

    // TLS 1.3 proves the inner-type suffix of *every* app-epoch record (locked
    // classification, parent metadata-channel spec §5), so all records are
    // passed to the plaintext proof; TLS 1.2 filters to the application-data
    // records (excluding the Finished record), unchanged.
    let is_v1_3 = tls_transcript.version() == TlsVersion::V1_3;

    // The version-correct cipher params (4-byte IV for 1.2, 12-byte for 1.3)
    // come from `ProxyKeys`; the version dispatch lives there.
    let transcript_refs = TranscriptRefs {
        sent: prove_plaintext(
            vm,
            keys.sent_cipher_params(),
            transcript.sent(),
            proof_records(tls_transcript.sent(), is_v1_3),
            &reveal_sent,
            &commit_sent,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("proving failed during sent plaintext commitment")
                .with_source(e)
        })?,
        recv: prove_plaintext(
            vm,
            keys.recv_cipher_params(),
            transcript.received(),
            proof_records(tls_transcript.recv(), is_v1_3),
            &reveal_recv,
            &commit_recv,
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("proving failed during received plaintext commitment")
                .with_source(e)
        })?,
    };

    let hash_commitments = if let Some(commit_config) = config.transcript_commit()
        && commit_config.has_hash()
    {
        Some(
            prove_hash(
                vm,
                &transcript_refs,
                commit_config
                    .iter_hash()
                    .map(|((dir, idx), alg)| (*dir, idx.clone(), *alg)),
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("proving failed during hash commitment setup")
                    .with_source(e)
            })?,
        )
    } else {
        None
    };

    vm.execute_all(ctx).await.map_err(|e| {
        Error::internal()
            .with_msg("proving failed during zk execution")
            .with_source(e)
    })?;

    if let Some((hash_fut, hash_secrets)) = hash_commitments {
        let hash_commitments = hash_fut.try_recv().map_err(|e| {
            Error::internal()
                .with_msg("proving failed during hash commitment finalization")
                .with_source(e)
        })?;
        for (commitment, secret) in hash_commitments.into_iter().zip(hash_secrets) {
            output
                .transcript_commitments
                .push(TranscriptCommitment::Hash(commitment));
            output
                .transcript_secrets
                .push(TranscriptSecret::Hash(secret));
        }
    }

    Ok(output)
}

/// The records fed to the plaintext proof for one direction.
///
/// * TLS 1.3: **every** app-epoch record (their inner type is proven via the
///   suffix, parent spec §5).
/// * TLS 1.2: only the application-data records — this filters out the leading
///   Finished record, preserving the original behaviour byte-for-byte.
fn proof_records(records: &[Record], is_v1_3: bool) -> impl Iterator<Item = &Record> {
    records
        .iter()
        .filter(move |record| is_v1_3 || record.typ == ContentType::ApplicationData)
}
