use rand::{Rng, SeedableRng, rngs::StdRng};
use rangeset::set::RangeSet;
use ring::{
    rand::SystemRandom,
    signature::{RSA_PSS_SHA256, RsaKeyPair},
};
use tlsn_attestation::{
    Attestation, AttestationConfig, CryptoProvider,
    presentation::{PresentationError, PresentationOutput},
    request::{Request, RequestConfig},
    signing::SignatureAlgId,
};
use tlsn_core::{
    connection::{
        CertBinding, CertBindingV1_3, ConnectionInfo, HandshakeData, ServerName, ServerSignature,
        SignatureAlgorithm, SignatureScheme13, TlsVersion,
    },
    fixtures::ConnectionFixture,
    hash::{Blake3, Blinder, HashAlgId},
    transcript::{
        Direction, Transcript, TranscriptCommitment, TranscriptSecret,
        hash::{PlaintextHash, PlaintextHashSecret, hash_plaintext},
    },
    webpki::{CertificateDer, RootCertStore, ServerCertVerifier},
};
use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};

/// Tests that the attestation protocol and verification work end-to-end
#[test]
fn test_api() {
    let mut rng = StdRng::seed_from_u64(0);
    let mut provider = CryptoProvider::default();

    // Configure signer for Notary
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();

    // At the end of the TLS connection the Prover holds the:
    let ConnectionFixture {
        server_name,
        connection_info,
        server_cert_data,
    } = ConnectionFixture::tlsnotary(transcript.length());

    let cert_binding = server_cert_data.binding.clone();

    // Create hash commitments
    let hasher = Blake3::default();
    let sent_blinder: Blinder = rng.random();
    let recv_blinder: Blinder = rng.random();

    let sent_idx = RangeSet::from(0..sent_len);
    let recv_idx = RangeSet::from(0..recv_len);

    let sent_hash_commitment = PlaintextHash {
        direction: Direction::Sent,
        idx: sent_idx.clone(),
        hash: hash_plaintext(&hasher, transcript.sent(), &sent_blinder),
    };

    let recv_hash_commitment = PlaintextHash {
        direction: Direction::Received,
        idx: recv_idx.clone(),
        hash: hash_plaintext(&hasher, transcript.received(), &recv_blinder),
    };

    let sent_hash_secret = PlaintextHashSecret {
        direction: Direction::Sent,
        idx: sent_idx,
        alg: HashAlgId::BLAKE3,
        blinder: sent_blinder,
    };

    let recv_hash_secret = PlaintextHashSecret {
        direction: Direction::Received,
        idx: recv_idx,
        alg: HashAlgId::BLAKE3,
        blinder: recv_blinder,
    };

    let request_config = RequestConfig::default();
    let mut request_builder = Request::builder(&request_config);

    request_builder
        .server_name(server_name.clone())
        .handshake_data(server_cert_data)
        .transcript(transcript)
        .transcript_commitments(
            vec![
                TranscriptSecret::Hash(sent_hash_secret),
                TranscriptSecret::Hash(recv_hash_secret),
            ],
            vec![
                TranscriptCommitment::Hash(sent_hash_commitment.clone()),
                TranscriptCommitment::Hash(recv_hash_commitment.clone()),
            ],
        );

    let (request, secrets) = request_builder.build(&provider).unwrap();

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    // Notary signs an attestation according to their view of the connection.
    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.clone())
        .unwrap();

    attestation_builder
        // Notary's view of the connection
        .connection_info(connection_info.clone())
        // Certificate binding Notary observed during the handshake
        .cert_binding(cert_binding)
        .transcript_commitments(vec![
            TranscriptCommitment::Hash(sent_hash_commitment),
            TranscriptCommitment::Hash(recv_hash_commitment),
        ]);

    let attestation = attestation_builder.build(&provider).unwrap();

    // Prover validates the attestation is consistent with its request.
    request.validate(&attestation, &provider).unwrap();

    let mut transcript_proof_builder = secrets.transcript_proof_builder();

    transcript_proof_builder
        .reveal(&(0..sent_len), Direction::Sent)
        .unwrap();
    transcript_proof_builder
        .reveal(&(0..recv_len), Direction::Received)
        .unwrap();

    let transcript_proof = transcript_proof_builder.build().unwrap();

    let mut builder = attestation.presentation_builder(&provider);

    builder.identity_proof(secrets.identity_proof());
    builder.transcript_proof(transcript_proof);

    let presentation = builder.build().unwrap();

    // Verifier verifies the presentation.
    let PresentationOutput {
        server_name: presented_server_name,
        connection_info: presented_connection_info,
        transcript: presented_transcript,
        ..
    } = presentation.verify(&provider).unwrap();

    assert_eq!(presented_server_name.unwrap(), server_name);
    assert_eq!(presented_connection_info, connection_info);

    let presented_transcript = presented_transcript.unwrap();

    assert_eq!(
        presented_transcript.sent_unsafe(),
        secrets.transcript().sent()
    );
    assert_eq!(
        presented_transcript.received_unsafe(),
        secrets.transcript().received()
    );
}

/// UNIX time within the fixture certificate's validity window
/// (`test-server.io`, valid Aug 2024 – Aug 2124).
const V1_3_TIME: u64 = 1_750_000_000;

/// Builds [`HandshakeData`] for a TLS 1.3 session against the in-repo server
/// fixture (`test-server.io`, chaining to `CA_CERT_DER`).
///
/// The CertificateVerify signature is produced over `signed_hash`, while the
/// stored [`CertBindingV1_3::cv_transcript_hash`] is set to `binding_hash`.
/// Passing equal hashes yields a valid handshake; differing hashes simulate a
/// tampered transcript hash.
fn v1_3_handshake_data(signed_hash: [u8; 32], binding_hash: [u8; 32]) -> HandshakeData {
    let key_pair = RsaKeyPair::from_pkcs8(SERVER_KEY_DER).unwrap();
    let rng = SystemRandom::new();

    // RFC 8446 §4.4.3 CertificateVerify signed message.
    let mut message = Vec::with_capacity(64 + 33 + 1 + 32);
    message.extend_from_slice(&[0x20; 64]);
    message.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    message.push(0x00);
    message.extend_from_slice(&signed_hash);

    let mut sig = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&RSA_PSS_SHA256, &rng, &message, &mut sig)
        .unwrap();

    HandshakeData {
        certs: vec![CertificateDer(SERVER_CERT_DER.to_vec())],
        sig: ServerSignature {
            alg: SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            sig,
        },
        binding: CertBinding::V1_3(CertBindingV1_3 {
            cv_transcript_hash: binding_hash,
            sig_scheme: SignatureScheme13::RsaPssRsaeSha256,
        }),
    }
}

/// Crypto provider trusting the fixture CA, with a notary signing key.
fn v1_3_provider() -> CryptoProvider {
    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(&[42u8; 32]).unwrap();
    provider.cert = ServerCertVerifier::new(&RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    })
    .unwrap();
    provider
}

/// Runs the full attestation + presentation flow for a TLS 1.3 session and
/// returns the verification result.
fn run_v1_3(server_cert_data: HandshakeData) -> Result<PresentationOutput, PresentationError> {
    let mut rng = StdRng::seed_from_u64(0);
    let provider = v1_3_provider();

    let transcript = Transcript::new(GET_WITH_HEADER, OK_JSON);
    let (sent_len, recv_len) = transcript.len();
    let transcript_length = transcript.length();

    let server_name = ServerName::Dns(SERVER_DOMAIN.try_into().unwrap());
    let cert_binding = server_cert_data.binding.clone();

    let hasher = Blake3::default();
    let sent_blinder: Blinder = rng.random();
    let recv_blinder: Blinder = rng.random();

    let sent_idx = RangeSet::from(0..sent_len);
    let recv_idx = RangeSet::from(0..recv_len);

    let sent_hash_commitment = PlaintextHash {
        direction: Direction::Sent,
        idx: sent_idx.clone(),
        hash: hash_plaintext(&hasher, transcript.sent(), &sent_blinder),
    };

    let recv_hash_commitment = PlaintextHash {
        direction: Direction::Received,
        idx: recv_idx.clone(),
        hash: hash_plaintext(&hasher, transcript.received(), &recv_blinder),
    };

    let sent_hash_secret = PlaintextHashSecret {
        direction: Direction::Sent,
        idx: sent_idx,
        alg: HashAlgId::BLAKE3,
        blinder: sent_blinder,
    };

    let recv_hash_secret = PlaintextHashSecret {
        direction: Direction::Received,
        idx: recv_idx,
        alg: HashAlgId::BLAKE3,
        blinder: recv_blinder,
    };

    let request_config = RequestConfig::default();
    let mut request_builder = Request::builder(&request_config);

    request_builder
        .server_name(server_name)
        .handshake_data(server_cert_data)
        .transcript(transcript)
        .transcript_commitments(
            vec![
                TranscriptSecret::Hash(sent_hash_secret),
                TranscriptSecret::Hash(recv_hash_secret),
            ],
            vec![
                TranscriptCommitment::Hash(sent_hash_commitment.clone()),
                TranscriptCommitment::Hash(recv_hash_commitment.clone()),
            ],
        );

    let (request, secrets) = request_builder.build(&provider).unwrap();

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs([SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    let mut attestation_builder = Attestation::builder(&attestation_config)
        .accept_request(request.clone())
        .unwrap();

    attestation_builder
        .connection_info(ConnectionInfo {
            time: V1_3_TIME,
            version: TlsVersion::V1_3,
            transcript_length,
        })
        .cert_binding(cert_binding)
        .transcript_commitments(vec![
            TranscriptCommitment::Hash(sent_hash_commitment),
            TranscriptCommitment::Hash(recv_hash_commitment),
        ]);

    let attestation = attestation_builder.build(&provider).unwrap();

    request.validate(&attestation, &provider).unwrap();

    let mut transcript_proof_builder = secrets.transcript_proof_builder();
    transcript_proof_builder
        .reveal(&(0..sent_len), Direction::Sent)
        .unwrap();
    transcript_proof_builder
        .reveal(&(0..recv_len), Direction::Received)
        .unwrap();
    let transcript_proof = transcript_proof_builder.build().unwrap();

    let mut builder = attestation.presentation_builder(&provider);
    builder.identity_proof(secrets.identity_proof());
    builder.transcript_proof(transcript_proof);
    let presentation = builder.build().unwrap();

    presentation.verify(&provider)
}

/// A proxy-mode notary can sign a TLS 1.3 attestation and the prover can build
/// a verifiable presentation from it (happy path).
#[test]
fn test_api_v1_3() {
    let cv_transcript_hash = [0x42u8; 32];
    let server_cert_data = v1_3_handshake_data(cv_transcript_hash, cv_transcript_hash);

    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = run_v1_3(server_cert_data).unwrap();

    assert_eq!(
        server_name.unwrap(),
        ServerName::Dns(SERVER_DOMAIN.try_into().unwrap())
    );
    assert_eq!(connection_info.version, TlsVersion::V1_3);

    let transcript = transcript.unwrap();
    assert_eq!(transcript.sent_unsafe(), GET_WITH_HEADER);
    assert_eq!(transcript.received_unsafe(), OK_JSON);
}

/// A tampered `cv_transcript_hash` (the attested/opened transcript hash differs
/// from the one the server actually signed) fails presentation verification.
#[test]
fn test_api_v1_3_tampered_transcript_hash() {
    let signed_hash = [0x42u8; 32];
    let mut tampered_hash = signed_hash;
    tampered_hash[0] ^= 0xff;

    // The handshake data the prover commits to (and the binding the notary
    // attests) both carry `tampered_hash`, so the anchor matches, but the
    // server's signature is over `signed_hash` and no longer verifies.
    let server_cert_data = v1_3_handshake_data(signed_hash, tampered_hash);

    assert!(run_v1_3(server_cert_data).is_err());
}
