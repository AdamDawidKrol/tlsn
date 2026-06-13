use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::set::RangeSet;
use tlsn_core::{
    VerifierOutput,
    config::prove::ProveRequest,
    connection::{CertBinding, HandshakeData, ServerEphemKey, ServerName, TlsVersion},
    transcript::{
        ContentType, Direction, PartialTranscript, Record, TlsTranscript, TranscriptCommitment,
    },
    webpki::ServerCertVerifier,
};

use crate::{
    Error, Result,
    proxy::ProxyKeys,
    transcript_internal::{TranscriptRefs, auth::verify_plaintext, commit::hash::verify_hash},
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &ProxyKeys,
    cert_verifier: &ServerCertVerifier,
    tls_transcript: &TlsTranscript,
    request: ProveRequest,
    handshake: Option<(ServerName, HandshakeData)>,
    transcript: Option<PartialTranscript>,
) -> Result<VerifierOutput> {
    // TLS 1.3 proves the inner-type suffix of *every* app-epoch record (locked
    // classification, parent metadata-channel spec §5); TLS 1.2 considers only
    // the application-data records (the Finished record is excluded).
    let is_v1_3 = tls_transcript.version() == TlsVersion::V1_3;

    // Full wire ciphertext (record-ciphertext coordinates) for the consistency
    // proof: TLS 1.2 has `inner_len == content_len`, so this also equals the
    // application-content length. For TLS 1.3 it is larger (it includes each
    // record's inner `type || padding` suffix, and the NST/KeyUpdate/alert
    // records); the transcript-length check below must therefore compare
    // against the content length, not this.
    let ciphertext_sent = collect_ciphertext(tls_transcript.sent(), is_v1_3);
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv(), is_v1_3);

    // §2.6: application-content length per direction.
    let content_len_sent = content_len(tls_transcript.sent(), is_v1_3);
    let content_len_recv = content_len(tls_transcript.recv(), is_v1_3);

    let transcript = if let Some((auth_sent, auth_recv)) = request.reveal() {
        let Some(transcript) = transcript else {
            return Err(Error::internal().with_msg(
                "verification failed: prover requested to reveal data but did not send transcript",
            ));
        };

        if transcript.len_sent() != content_len_sent
            || transcript.len_received() != content_len_recv
        {
            return Err(
                Error::internal().with_msg("verification failed: transcript length mismatch")
            );
        }

        if transcript.sent_authed() != auth_sent {
            return Err(Error::internal().with_msg("verification failed: sent auth data mismatch"));
        }

        if transcript.received_authed() != auth_recv {
            return Err(
                Error::internal().with_msg("verification failed: received auth data mismatch")
            );
        }

        transcript
    } else {
        // The `PartialTranscript` is indexed in application-content coordinates.
        PartialTranscript::new(content_len_sent, content_len_recv)
    };

    let server_name = if let Some((name, cert_data)) = handshake {
        // The ephemeral key is part of the TLS 1.2 cert binding (signed key
        // exchange); in TLS 1.3 the server signs the handshake transcript hash
        // and there is no separate ephemeral key to bind (`None`).
        let server_ephemeral_key: Option<&ServerEphemKey> =
            match tls_transcript.certificate_binding() {
                CertBinding::V1_2(binding) => Some(&binding.server_ephemeral_key),
                // TLS 1.3 (and any future binding) signs the handshake
                // transcript hash; there is no separate ephemeral key to bind.
                _ => None,
            };
        cert_data
            .verify(
                cert_verifier,
                tls_transcript.time(),
                server_ephemeral_key,
                &name,
            )
            .map_err(|e| {
                Error::internal()
                    .with_msg("verification failed: certificate verification failed")
                    .with_source(e)
            })?;

        Some(name)
    } else {
        None
    };

    let (mut commit_sent, mut commit_recv) = (RangeSet::default(), RangeSet::default());
    if let Some(commit_config) = request.transcript_commit() {
        commit_config
            .iter_hash()
            .for_each(|(direction, idx, _)| match direction {
                Direction::Sent => commit_sent.union_mut(idx),
                Direction::Received => commit_recv.union_mut(idx),
            });
    }

    // The version-correct cipher params (4-byte IV for 1.2, 12-byte for 1.3)
    // come from `ProxyKeys`; the version dispatch lives there.
    let (sent_refs, sent_proof) = verify_plaintext(
        vm,
        keys.sent_cipher_params(),
        transcript.sent_unsafe(),
        &ciphertext_sent,
        proof_records(tls_transcript.sent(), is_v1_3),
        transcript.sent_authed(),
        &commit_sent,
    )
    .map_err(|e| {
        Error::internal()
            .with_msg("verification failed during sent plaintext verification")
            .with_source(e)
    })?;
    let (recv_refs, recv_proof) = verify_plaintext(
        vm,
        keys.recv_cipher_params(),
        transcript.received_unsafe(),
        &ciphertext_recv,
        proof_records(tls_transcript.recv(), is_v1_3),
        transcript.received_authed(),
        &commit_recv,
    )
    .map_err(|e| {
        Error::internal()
            .with_msg("verification failed during received plaintext verification")
            .with_source(e)
    })?;

    let transcript_refs = TranscriptRefs {
        sent: sent_refs,
        recv: recv_refs,
    };

    let mut transcript_commitments = Vec::new();
    let mut hash_commitments = None;
    if let Some(commit_config) = request.transcript_commit()
        && commit_config.has_hash()
    {
        hash_commitments = Some(
            verify_hash(vm, &transcript_refs, commit_config.iter_hash().cloned()).map_err(|e| {
                Error::internal()
                    .with_msg("verification failed during hash commitment setup")
                    .with_source(e)
            })?,
        );
    }

    vm.execute_all(ctx).await.map_err(|e| {
        Error::internal()
            .with_msg("verification failed during zk execution")
            .with_source(e)
    })?;

    sent_proof.verify().map_err(|e| {
        Error::internal()
            .with_msg("verification failed: sent plaintext proof invalid")
            .with_source(e)
    })?;
    recv_proof.verify().map_err(|e| {
        Error::internal()
            .with_msg("verification failed: received plaintext proof invalid")
            .with_source(e)
    })?;

    if let Some(hash_commitments) = hash_commitments {
        for commitment in hash_commitments.try_recv().map_err(|e| {
            Error::internal()
                .with_msg("verification failed during hash commitment finalization")
                .with_source(e)
        })? {
            transcript_commitments.push(TranscriptCommitment::Hash(commitment));
        }
    }

    Ok(VerifierOutput {
        server_name,
        transcript: request.reveal().is_some().then_some(transcript),
        transcript_commitments,
    })
}

/// The records fed to the plaintext proof for one direction.
///
/// * TLS 1.3: **every** app-epoch record (its inner type is proven via the
///   suffix, parent spec §5).
/// * TLS 1.2: only the application-data records — this filters out the leading
///   Finished record, preserving the original behaviour byte-for-byte.
fn proof_records(records: &[Record], is_v1_3: bool) -> impl Iterator<Item = &Record> {
    records
        .iter()
        .filter(move |record| is_v1_3 || record.typ == ContentType::ApplicationData)
}

/// The concatenated wire ciphertext (record-ciphertext coordinates) fed to the
/// consistency proof. Must match the record set of [`proof_records`]: every
/// app-epoch record for TLS 1.3, only application-data records for TLS 1.2.
fn collect_ciphertext(records: &[Record], is_v1_3: bool) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    proof_records(records, is_v1_3).for_each(|record| {
        ciphertext.extend_from_slice(&record.ciphertext);
    });
    ciphertext
}

/// Sum of application-content lengths across application-data records (§2.6).
///
/// The application transcript counts only inner **content** bytes of
/// application-data records, so the transcript-length check compares against
/// this rather than the raw wire ciphertext length ([`collect_ciphertext`]).
///
/// * TLS 1.2: there is no inner `type || padding`, so `content_len ==
///   ciphertext.len()` per record and this equals the wire ciphertext length.
/// * TLS 1.3: `content_len = inner_len - 1 - padding`, taken from the framed
///   [`Record::content_len`] (set from the prover-declared metadata and
///   validated by the per-record `type || padding` suffix proof in
///   `transcript_internal::auth`, parent spec §3/§5). Non-application-data
///   records (NST / KeyUpdate / alert) are excluded from the transcript.
fn content_len(records: &[Record], is_v1_3: bool) -> usize {
    records
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| {
            if is_v1_3 {
                record.content_len.unwrap_or(record.ciphertext.len())
            } else {
                record.ciphertext.len()
            }
        })
        .sum()
}
