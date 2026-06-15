//! Proxy-mode notarization against a real, public TLS 1.3 endpoint.
//!
//! Unlike the `proxy` example (which talks to the local server-fixture), this
//! one points the prover/verifier at a real server over the public internet,
//! using Mozilla root certificates, and asserts the session genuinely
//! negotiated TLS 1.3.
//!
//! Run with:
//! ```shell
//! cargo run --release --example proxy_real
//! ```

use std::{future::IntoFuture, net::SocketAddr};

use anyhow::{Context as _, Result};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, DnsName, ServerName, TlsVersion},
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};

/// The endpoint under test.
const SERVER_DOMAIN: &str = "betslips.lvbet.pl";
const SERVER_PORT: u16 = 443;
const REQUEST_PATH: &str = "/client-betslips/v3/details/NFRR7MTHMYG";

/// Extra request headers (mirrors the provided `curl` invocation).
const HEADERS: &[(&str, &str)] = &[
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

    // Resolve the real server address (the verifier dials this in proxy mode).
    let server_addr: SocketAddr = tokio::net::lookup_host((SERVER_DOMAIN, SERVER_PORT))
        .await
        .context("DNS resolution failed")?
        .next()
        .context("no address resolved")?;

    // Connect prover and verifier over an in-memory duplex (same machine; in a
    // real deployment these are two separate processes/hosts).
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);

    let prover = prover(prover_socket);
    let verifier = verifier(verifier_socket, server_addr);
    let (_, (version, transcript)) = tokio::try_join!(prover, verifier)?;

    println!("\nSuccessfully verified https://{SERVER_DOMAIN}{REQUEST_PATH}");
    println!("Negotiated TLS version: {version:?}");
    println!(
        "\n--- Verified sent ---\n{}",
        String::from_utf8_lossy(transcript.sent_unsafe())
    );
    println!(
        "\n--- Verified received ---\n{}",
        String::from_utf8_lossy(transcript.received_unsafe())
    );

    Ok(())
}

#[instrument(skip(verifier_socket))]
async fn prover<T>(verifier_socket: T) -> Result<()>
where
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Send + Unpin + 'static,
{
    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Proxy mode: the verifier forwards traffic to the real server. The
    // server_name must match the certificate's DNS name.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(SERVER_DOMAIN)?)
                .build()?,
        )
        .await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            // Real, public roots instead of the fixture CA.
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let mut request = Request::builder()
        .uri(REQUEST_PATH)
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET");
    for (name, value) in HEADERS {
        request = request.header(*name, *value);
    }
    let request = request.body(Empty::<Bytes>::new())?;

    let response = request_sender.send_request(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "unexpected HTTP status");

    // Pull the whole body through so every received byte lands in the
    // transcript before we finalize.
    let _ = response.into_body().collect().await?.to_bytes();

    let mut prover = prover_task.await??;

    // Reveal the server identity and the full transcript (nothing redacted in
    // this smoke test).
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_sent(&(0..prover.transcript().sent().len()))?;
    builder.reveal_recv(&(0..prover.transcript().received().len()))?;
    let config = builder.build()?;

    prover.prove(&config).await?;
    prover.close().await?;

    handle.close();
    driver_task.await??;
    Ok(())
}

#[instrument(skip(prover_socket))]
async fn verifier<T>(
    prover_socket: T,
    server_addr: SocketAddr,
) -> Result<(TlsVersion, PartialTranscript)>
where
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Send + Unpin + 'static,
{
    let session = Session::new(prover_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(
        VerifierConfig::builder()
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;

    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(_) => anyhow::bail!("expected proxy mode"),
        VerifierCommitStart::Proxy(verifier) => {
            // In proxy mode the verifier dials the real server and relays bytes
            // between prover and server, recording the wire transcript.
            let client_socket = tokio::net::TcpStream::connect(server_addr).await?;
            client_socket.set_nodelay(true)?;
            verifier.accept().await?.run(client_socket.compat()).await?
        }
    };

    // The verifier learns the negotiated version from the wire bytes it
    // recorded itself.
    let version = verifier.tls_transcript().version();
    let cert_binding = verifier.tls_transcript().certificate_binding().clone();
    assert_eq!(version, TlsVersion::V1_3, "expected a TLS 1.3 session");
    assert!(
        matches!(cert_binding, CertBinding::V1_3(_)),
        "expected a TLS 1.3 certificate binding"
    );

    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() {
        let verifier = verifier.reject(Some("expecting the server name")).await?;
        verifier.close().await?;
        anyhow::bail!("prover did not reveal the server name");
    }

    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;
    verifier.close().await?;

    handle.close();
    driver_task.await??;

    let ServerName::Dns(server_name) = server_name.context("server name not revealed")?;
    assert_eq!(server_name.as_str(), SERVER_DOMAIN);

    let transcript = transcript.context("transcript not revealed")?;
    Ok((version, transcript))
}
