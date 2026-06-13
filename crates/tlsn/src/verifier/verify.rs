use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use rangeset::set::RangeSet;
use tlsn_core::{
    VerifierOutput,
    config::prove::ProveRequest,
    connection::{CertBinding, HandshakeData, ServerEphemKey, ServerName},
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
    // Full wire ciphertext (record-ciphertext coordinates) for the consistency
    // proof: TLS 1.2 has `inner_len == content_len`, so this also equals the
    // application-content length. For TLS 1.3 it is larger (it includes each
    // record's inner `type || padding` suffix); the transcript-length check
    // below must therefore compare against the content length, not this.
    let ciphertext_sent = collect_ciphertext(tls_transcript.sent());
    let ciphertext_recv = collect_ciphertext(tls_transcript.recv());

    // §2.6: application-content length per direction.
    let content_len_sent = content_len(tls_transcript.sent());
    let content_len_recv = content_len(tls_transcript.recv());

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
        tls_transcript
            .sent()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
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
        tls_transcript
            .recv()
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData),
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

fn collect_ciphertext<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    records
        .into_iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .for_each(|record| {
            ciphertext.extend_from_slice(&record.ciphertext);
        });
    ciphertext
}

/// Sum of application-content lengths across app-data records (§2.6).
///
/// The application transcript counts only inner **content** bytes, so the
/// transcript-length check compares against this rather than the raw wire
/// ciphertext length ([`collect_ciphertext`]).
///
/// * TLS 1.2: there is no inner `type || padding`, so `content_len ==
///   ciphertext.len()` per record and this equals the wire ciphertext length.
/// * TLS 1.3 (TODO item 9): `content_len = inner_len - 1 - padding`, learned
///   from the per-record `type || padding` suffix proof in
///   `transcript_internal::auth` (§2.4). The verifier needs the prover-declared
///   per-record content length to compute this; that metadata channel is the
///   item-9 fixture work (open-question §5). Until then this returns the wire
///   length, which is exact for TLS 1.2 and an over-estimate for TLS 1.3.
fn content_len<'a>(records: impl IntoIterator<Item = &'a Record>) -> usize {
    records
        .into_iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| record.ciphertext.len())
        .sum()
}
