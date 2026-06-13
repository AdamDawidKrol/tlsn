use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::set::RangeSet;
use tlsn_core::{
    ProverOutput,
    config::prove::ProveConfig,
    transcript::{
        ContentType, Direction, TlsTranscript, Transcript, TranscriptCommitment, TranscriptSecret,
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

    // The version-correct cipher params (4-byte IV for 1.2, 12-byte for 1.3)
    // come from `ProxyKeys`; the version dispatch lives there.
    let transcript_refs = TranscriptRefs {
        sent: prove_plaintext(
            vm,
            keys.sent_cipher_params(),
            transcript.sent(),
            tls_transcript
                .sent()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData),
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
            tls_transcript
                .recv()
                .iter()
                .filter(|record| record.typ == ContentType::ApplicationData),
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
