use tls_server_fixture::SERVER_DOMAIN;
use tlsn::{
    Session,
    config::{
        prover::ProverConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{CertBinding, DnsName, ServerName, TlsVersion},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::{
    SupportedProtocolVersion, TLS12_ONLY, TLS13_ONLY, bind, bind_with_versions,
};
use tlsn_server_fixture_certs::CA_CERT_DER;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, warn};

mod utils;
use utils::{VerifierObservation, finish_prover, run_prover_mpc, run_prover_proxy, run_verifier};

/// Drives a full proxy-mode prover↔verifier session against the fixture server,
/// pinning the server's offered TLS versions (the proxy client offers both, so
/// the server drives the negotiated version — parent spec §2).
///
/// Returns what the verifier observed: its output, the negotiated version, and
/// the certificate binding.
async fn run_proxy_e2e(
    server_versions: &'static [&'static SupportedProtocolVersion],
) -> VerifierObservation {
    let config = ProxyTlsConfig::builder()
        .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind_with_versions(server_socket.compat(), server_versions));

    let prover_fut = async {
        let prover = run_prover_proxy(config, prover).await;
        finish_prover(prover).await
    };

    let ((_full_transcript, _prover_output), verifier_obs) =
        tokio::join!(prover_fut, run_verifier(verifier, Some(client_socket)));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();

    verifier_obs
}

/// Asserts the canonical proxy-mode happy-path output: the server name is
/// revealed and the first 10 bytes of each direction were authenticated.
fn assert_happy_path(obs: &VerifierObservation) {
    let partial_transcript = obs.output.transcript.as_ref().unwrap();
    let ServerName::Dns(server_name) = obs.output.server_name.as_ref().unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
        0..10
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_mpc() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    // Maximum number of bytes that can be sent from prover to server
    const MAX_SENT_DATA: usize = 1 << 12;
    // Maximum number of application records sent from prover to server
    const MAX_SENT_RECORDS: usize = 4;
    // Maximum number of bytes that can be received by prover from server
    const MAX_RECV_DATA: usize = 1 << 14;
    // Maximum number of application records received by prover from server
    const MAX_RECV_RECORDS: usize = 6;

    let config = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_sent_records(MAX_SENT_RECORDS)
        .max_recv_data(MAX_RECV_DATA)
        .max_recv_records_online(MAX_RECV_RECORDS)
        .build()
        .unwrap();

    let (prover_socket, verifier_socket) = tokio::io::duplex(2 << 23);
    let mut session_p = Session::new(prover_socket.compat());
    let mut session_v = Session::new(verifier_socket.compat());

    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();
    let verifier = session_v
        .new_verifier(
            VerifierConfig::builder()
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
        )
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    let (session_v_driver, session_v_handle) = session_v.split();

    tokio::spawn(session_p_driver);
    tokio::spawn(session_v_driver);

    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover_fut = async {
        let prover = run_prover_mpc(config, prover, Some(client_socket)).await;
        finish_prover(prover).await
    };

    let ((_full_transcript, _prover_output), verifier_obs) =
        tokio::join!(prover_fut, run_verifier(verifier, None));

    session_p_handle.close();
    session_v_handle.close();

    let _ = server_task.await.unwrap();
    let partial_transcript = verifier_obs.output.transcript.unwrap();
    let ServerName::Dns(server_name) = verifier_obs.output.server_name.unwrap();

    assert_eq!(server_name.as_str(), SERVER_DOMAIN);
    assert!(!partial_transcript.is_complete());
    assert_eq!(
        partial_transcript.sent_authed().iter().next().unwrap(),
        0..10
    );
    assert_eq!(
        partial_transcript.received_authed().iter().next().unwrap(),
        0..10
    );
}

/// Proxy-mode TLS 1.2 e2e. The server is pinned **1.2-only** so that even
/// though the proxy client now offers both 1.3 and 1.2 (parent spec §1), this
/// keeps exercising the 1.2 finalize path (PRF + cf/sf verify-data).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    let obs = run_proxy_e2e(TLS12_ONLY).await;

    assert_eq!(obs.version, TlsVersion::V1_2);
    assert!(matches!(obs.cert_binding, CertBinding::V1_2(_)));
    assert_happy_path(&obs);
}

/// Proxy-mode TLS 1.3 e2e (the first live prover↔verifier 1.3 session). The
/// server is pinned **1.3-only** so the both-offering client negotiates 1.3.
/// Asserts the session is genuinely 1.3 (`CertBinding::V1_3` + transcript
/// version) and that the canonical happy-path output holds. A successful
/// verifier `accept()` (inside `run_verifier`) also retires the item-5 webpki
/// deferral: the real fixture cert chain validates against `CA_CERT_DER` and
/// the CertificateVerify signature checks out over the recomputed transcript
/// hash (parent spec §6.3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy_tls13() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    let obs = run_proxy_e2e(TLS13_ONLY).await;

    assert_eq!(obs.version, TlsVersion::V1_3);
    assert!(
        matches!(obs.cert_binding, CertBinding::V1_3(_)),
        "expected a TLS 1.3 certificate binding"
    );
    assert_happy_path(&obs);
}

/// Negotiation matrix: the proxy client offers both 1.3 and 1.2, and the
/// negotiated version is driven by the server's offered set (parent spec §2/§3).
/// Each session must complete and reveal correctly.
///
/// | server offers | expected negotiated |
/// |---------------|---------------------|
/// | 1.3 + 1.2     | 1.3 (client prefers 1.3) |
/// | 1.2 only      | 1.2                 |
/// | 1.3 only      | 1.3                 |
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn test_proxy_negotiation_matrix() {
    match tracing_subscriber::fmt::try_init() {
        Ok(_) => info!("set up tracing subscriber"),
        Err(_) => warn!("tracing subscriber already set up"),
    };

    let cases: &[(&'static [&'static SupportedProtocolVersion], TlsVersion)] = &[
        (tlsn_server_fixture::BOTH_VERSIONS, TlsVersion::V1_3),
        (TLS12_ONLY, TlsVersion::V1_2),
        (TLS13_ONLY, TlsVersion::V1_3),
    ];

    for (server_versions, expected) in cases {
        info!("negotiation matrix: expecting {:?}", expected);
        let obs = run_proxy_e2e(server_versions).await;

        assert_eq!(
            obs.version, *expected,
            "unexpected negotiated version for server set {server_versions:?}"
        );
        match expected {
            TlsVersion::V1_2 => assert!(matches!(obs.cert_binding, CertBinding::V1_2(_))),
            TlsVersion::V1_3 => assert!(matches!(obs.cert_binding, CertBinding::V1_3(_))),
        }
        assert_happy_path(&obs);
    }
}
