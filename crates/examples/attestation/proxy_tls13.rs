//! Proxy-mode notary issuing a **signed attestation over a TLS 1.3 session**.
//!
//! This runs all three roles in-process — prover, proxy-mode notary, and
//! presentation verifier — against the in-repo server fixture pinned to TLS
//! 1.3. It mirrors the `proxy` example (proxy plumbing) and the
//! `attestation_prove` / `attestation_present` examples (attestation request,
//! notary, presentation), and demonstrates the version-agnostic certificate
//! binding: the notary attests the `CertBinding::V1_3` it observed and the
//! prover builds a verifiable presentation from it.
//!
//! It writes the same `*.attestation.tlsn` / `*.secrets.tlsn` /
//! `*.presentation.tlsn` artifacts as the other attestation examples, then
//! verifies the presentation.
//!
//! Run with:
//! ```shell
//! cargo run --example attestation_proxy_tls13
//! ```
//!
//! By default it talks to the local fixture. To point it at a real, public TLS
//! 1.3 endpoint instead, set `SERVER_HOST` (and optionally `SERVER_PORT`,
//! `SERVER_DOMAIN`, `REQUEST_PATH`); Mozilla roots are then used.

use std::{env, future::IntoFuture, net::SocketAddr};

use anyhow::{Context as _, Result};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;

use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        signing::Secp256k1Signer,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{
        CertBinding, ConnectionInfo, DnsName, HandshakeData, ServerName, TlsVersion,
        TranscriptLength,
    },
    prover::ProverOutput,
    transcript::{ContentType, Record, TranscriptCommitConfig},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore, ServerCertVerifier},
};
use tlsn_examples::ExampleType;
use tlsn_server_fixture::{TLS13_ONLY, bind_with_versions};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

/// Application headers sent against the in-repo fixture.
const FIXTURE_HEADERS: &[(&str, &str)] = &[("Accept", "*/*"), ("User-Agent", USER_AGENT)];

/// Default request path + headers for the public lvbet endpoint, mirroring the
/// interactive `proxy_real` example so this attestation example can target the
/// same endpoint (used when `SERVER_HOST` is set and no overrides are given).
const LVBET_PATH: &str = "/client-betslips/v3/details/NFRR7MTHMYG";
const LVBET_HEADERS: &[(&str, &str)] = &[
    ("device", "web (website)"),
    ("Referer", "https://lvbet.pl/"),
    ("Accept-Language", "pl-PL,pl;q=0.5"),
    ("Accept", "application/json, text/plain, */*"),
    ("Content-Type", "application/json"),
    ("Content-language", "pl"),
    (
        "User-Agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
    ),
];

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let server_host = env::var("SERVER_HOST").ok();
    let real_endpoint = server_host.is_some();

    // The notary dials `server_addr` in proxy mode. By default we spin up the
    // in-repo fixture (pinned to TLS 1.3) on a loopback port so the example is
    // self-contained and deterministic; with `SERVER_HOST` set we instead point
    // at a real endpoint (e.g. the public lvbet endpoint) using Mozilla roots.
    let (server_domain, root_store, server_addr, fixture_task) = if let Some(host) = server_host {
        let port: u16 = env::var("SERVER_PORT")
            .ok()
            .and_then(|port| port.parse().ok())
            .unwrap_or(443);
        let domain = env::var("SERVER_DOMAIN").unwrap_or_else(|_| host.clone());
        let addr = tokio::net::lookup_host((host.as_str(), port))
            .await
            .context("DNS resolution failed")?
            .next()
            .context("no address resolved")?;
        (domain, RootCertStore::mozilla(), addr, None)
    } else {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true)?;
            bind_with_versions(stream.compat(), TLS13_ONLY).await
        });
        (
            SERVER_DOMAIN.to_string(),
            RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            },
            addr,
            Some(task),
        )
    };

    // Default request path + headers mirror the interactive `proxy_real` example
    // when targeting a real endpoint, and the fixture's JSON route otherwise.
    let request_path = env::var("REQUEST_PATH").unwrap_or_else(|_| {
        if real_endpoint {
            LVBET_PATH.into()
        } else {
            "/formats/json".into()
        }
    });
    let extra_headers: &[(&str, &str)] = if real_endpoint {
        LVBET_HEADERS
    } else {
        FIXTURE_HEADERS
    };

    let (notary_socket, prover_socket) = tokio::io::duplex(1 << 23);

    let notary_root_store = root_store.clone();
    let notary_task =
        tokio::spawn(async move { notary(notary_socket, server_addr, notary_root_store).await });

    prover(
        prover_socket,
        server_domain,
        root_store,
        &request_path,
        extra_headers,
    )
    .await?;

    notary_task.await??;
    if let Some(task) = fixture_task {
        let _ = task.await?;
    }

    Ok(())
}

async fn prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    server_domain: String,
    root_store: RootCertStore,
    request_path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<()> {
    // Create a session with the notary.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Proxy mode: the notary forwards traffic to the server. The server_name
    // must match the certificate's DNS name.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server_domain.as_str())?)
                .build()?,
        )
        .await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(server_domain.as_str().try_into()?))
            .root_store(root_store.clone())
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let mut request_builder = Request::builder()
        .uri(request_path)
        .header("Host", server_domain.as_str())
        // "identity" instructs the server not to compress its response (TLSNotary
        // tooling does not support compression).
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .method("GET");
    for (name, value) in extra_headers {
        request_builder = request_builder.header(*name, *value);
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    info!("Starting connection with the server");

    let response = request_sender.send_request(request).await?;
    info!("Got a response from the server: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK, "unexpected HTTP status");

    // Drain the body so every received byte lands in the transcript before we
    // finalize.
    let _ = response.into_body().collect().await?.to_bytes();

    let mut prover = prover_task.await??;

    let tls_transcript = prover.tls_transcript().clone();
    assert_eq!(
        tls_transcript.version(),
        TlsVersion::V1_3,
        "expected a TLS 1.3 session"
    );
    assert!(
        matches!(tls_transcript.certificate_binding(), CertBinding::V1_3(_)),
        "expected a TLS 1.3 certificate binding"
    );

    // Commit to the whole transcript (no reveal at prove time — the notary
    // learns nothing about the application data).
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();

    let mut transcript_commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    transcript_commit_builder
        .commit_sent(&(0..sent_len))?
        .commit_recv(&(0..recv_len))?;
    let transcript_commit = transcript_commit_builder.build()?;

    let mut request_config_builder = RequestConfig::builder();
    request_config_builder.transcript_commit(transcript_commit);
    let request_config = request_config_builder.build()?;

    let mut prove_config_builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_config_builder.transcript_commit(config.clone());
    }
    let prove_config = prove_config_builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config).await?;

    let prover_transcript = prover.transcript().clone();
    prover.close().await?;

    // Build the attestation request. The withheld handshake data carries the
    // certificate chain, the CertificateVerify signature, and the (V1_3)
    // binding the prover observed.
    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(server_domain.as_str().try_into()?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = builder.build(&CryptoProvider::default())?;

    // Reclaim the raw socket and exchange the attestation over it.
    handle.close();
    let mut socket = driver_task.await??;

    let request_bytes = bincode::serialize(&request)?;
    socket.write_all(&request_bytes).await?;
    socket.close().await?;

    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    // The verification provider trusts the same roots as the TLS client.
    let mut provider = CryptoProvider::default();
    provider.cert = ServerCertVerifier::new(&root_store)?;

    // Check the attestation is consistent with the prover's view.
    request.validate(&attestation, &provider)?;

    // Persist the artifacts.
    let attestation_path = tlsn_examples::get_file_path(&ExampleType::Json, "attestation");
    let secrets_path = tlsn_examples::get_file_path(&ExampleType::Json, "secrets");
    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    // Build a presentation that discloses the full transcript and the server
    // identity, then verify it.
    let mut transcript_proof_builder = secrets.transcript_proof_builder();
    transcript_proof_builder
        .reveal_sent(&(0..sent_len))?
        .reveal_recv(&(0..recv_len))?;
    let transcript_proof = transcript_proof_builder.build()?;

    let mut presentation_builder = attestation.presentation_builder(&provider);
    presentation_builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    let presentation: Presentation = presentation_builder.build()?;

    let presentation_path = tlsn_examples::get_file_path(&ExampleType::Json, "presentation");
    tokio::fs::write(&presentation_path, bincode::serialize(&presentation)?).await?;

    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&provider)?;

    let server_name = server_name.context("server name not disclosed")?;
    let ServerName::Dns(disclosed_name) = &server_name;
    assert_eq!(disclosed_name.as_str(), server_domain);
    assert_eq!(connection_info.version, TlsVersion::V1_3);

    let transcript = transcript.context("transcript not disclosed")?;

    println!("Notarization and presentation verified successfully!");
    println!("Negotiated TLS version: {:?}", connection_info.version);
    println!("Authenticated server: {server_name}");
    println!(
        "The artifacts have been written to `{attestation_path}`, `{secrets_path}` and \
        `{presentation_path}`."
    );
    println!(
        "\n--- Disclosed sent ---\n{}",
        String::from_utf8_lossy(transcript.sent_unsafe())
    );
    println!(
        "\n--- Disclosed received ---\n{}",
        String::from_utf8_lossy(transcript.received_unsafe())
    );

    Ok(())
}

async fn notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    server_addr: SocketAddr,
    root_store: RootCertStore,
) -> Result<()> {
    // Create a session with the prover.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder().root_store(root_store).build()?;

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            verifier.reject(Some("expecting to use proxy-TLS")).await?;
            return Err(anyhow::anyhow!("expected proxy mode"));
        }
        VerifierCommitStart::Proxy(verifier) => {
            // In proxy mode the notary dials the server and relays bytes between
            // prover and server, recording the wire transcript.
            let client_socket = tokio::net::TcpStream::connect(server_addr).await?;
            client_socket.set_nodelay(true)?;
            verifier.accept().await?.run(client_socket.compat()).await?
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    assert_eq!(
        tls_transcript.version(),
        TlsVersion::V1_3,
        "expected a TLS 1.3 session"
    );
    assert!(
        matches!(tls_transcript.certificate_binding(), CertBinding::V1_3(_)),
        "expected a TLS 1.3 certificate binding"
    );

    // The attestation transcript length counts application **content** bytes.
    // For TLS 1.3 each record's wire ciphertext includes the inner
    // `type || padding` suffix (and NST/alert records are present too), so
    // summing `ciphertext.len()` would over-count; use the per-record content
    // length instead (mirrors `content_len` in `verifier/verify.rs`).
    let transcript_length = TranscriptLength {
        sent: content_len(tls_transcript.sent()),
        received: content_len(tls_transcript.recv()),
    };

    // Reclaim the raw socket and exchange the attestation over it.
    handle.close();
    let mut socket = driver_task.await??;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    // Load a dummy signing key.
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length,
        })
        .cert_binding(tls_transcript.certificate_binding().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    let attestation_bytes = bincode::serialize(&attestation)?;
    socket.write_all(&attestation_bytes).await?;
    socket.close().await?;

    Ok(())
}

/// Sum of application-content lengths across application-data records.
///
/// Mirrors the TLS 1.3 branch of `content_len` in
/// `crates/tlsn/src/verifier/verify.rs`: the per-record [`Record::content_len`]
/// (`inner_len - 1 - padding`) for application-data records, falling back to the
/// wire ciphertext length when it is unset (TLS 1.2).
fn content_len(records: &[Record]) -> u32 {
    records
        .iter()
        .filter(|record| record.typ == ContentType::ApplicationData)
        .map(|record| record.content_len.unwrap_or(record.ciphertext.len()))
        .sum::<usize>() as u32
}
