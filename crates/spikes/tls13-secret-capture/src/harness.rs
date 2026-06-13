//! Test harness: assemble the capturing `CryptoProvider`, run one TLS 1.3 HTTP
//! exchange against `tls_server_fixture`, then run the §3.2 verification chain.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use rustls::client::ClientConnection;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{CipherSuiteCommon, ClientConfig, RootCertStore, SupportedCipherSuite, Tls13CipherSuite};
use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::capture::{CaptureLog, CapturingHkdf, ExtractKind, KeyLogCapture};
use crate::verify;

pub struct Assertion {
    pub name: String,
    pub pass: bool,
    pub detail: Option<String>,
}

impl Assertion {
    fn new(name: impl Into<String>, pass: bool, detail: Option<String>) -> Self {
        Self {
            name: name.into(),
            pass,
            detail,
        }
    }
}

pub struct Outcome {
    pub assertions: Vec<Assertion>,
}

/// Build a `CryptoProvider` whose only TLS 1.3 suite routes HKDF through
/// [`CapturingHkdf`].
fn build_capturing_provider(log: Arc<Mutex<CaptureLog>>) -> rustls::crypto::CryptoProvider {
    // (a): wrap the `Hkdf` instance already referenced by ring's
    // TLS13_AES_128_GCM_SHA256 suite. Option (b) — `HkdfUsingHmac(&ring::hmac::
    // HMAC_SHA256)` — is NOT available: `rustls::crypto::ring::hmac` is
    // `pub(crate)` in 0.23.40 (see RESULTS.md "construction friction").
    let base: &'static Tls13CipherSuite = ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite");

    let capturing: &'static CapturingHkdf =
        Box::leak(Box::new(CapturingHkdf::new(base.hkdf_provider, log)));

    // We cannot write `Tls13CipherSuite { hkdf_provider, ..*base }`: the struct
    // contains a non-`Copy` `CipherSuiteCommon`, so the functional-update form
    // would try to move out of a `&'static` borrow. Reconstruct field-by-field
    // (every field is individually `Copy` or a `&'static` reference).
    let suite: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        hkdf_provider: capturing,
        aead_alg: base.aead_alg,
        quic: base.quic,
    }));

    let mut provider = ring::default_provider();
    provider.cipher_suites = vec![SupportedCipherSuite::Tls13(suite)];
    provider
}

fn build_client_config(
    log: Arc<Mutex<CaptureLog>>,
    key_log: Arc<KeyLogCapture>,
) -> Arc<ClientConfig> {
    let provider = build_capturing_provider(log);

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(CA_CERT_DER))
        .expect("fixture root CA parses");

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the ring provider")
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.key_log = key_log;
    Arc::new(config)
}

/// Drive a synchronous rustls 0.23 client over a blocking TCP socket. Runs on a
/// dedicated OS thread so it never blocks the tokio runtime hosting the server.
fn run_client(addr: std::net::SocketAddr, config: Arc<ClientConfig>) -> std::io::Result<Vec<u8>> {
    let server_name = ServerName::try_from(SERVER_DOMAIN).unwrap().to_owned();
    let mut conn = ClientConnection::new(config, server_name).expect("client connection");
    let mut sock = std::net::TcpStream::connect(addr)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let request =
        b"GET / HTTP/1.1\r\nHost: test-server.io\r\nConnection: close\r\n\r\n";
    tls.write_all(request)?;
    tls.flush()?;

    let mut response = Vec::new();
    // Read until the server closes. A clean close_notify yields Ok(0); an
    // unclean TCP close surfaces as an error after we already have the body.
    match tls.read_to_end(&mut response) {
        Ok(_) => {}
        Err(e) if !response.is_empty() => {
            eprintln!("(note) client read ended with {e} after {} bytes", response.len());
        }
        Err(e) => return Err(e),
    }
    Ok(response)
}

pub fn run() -> Outcome {
    let log: Arc<Mutex<CaptureLog>> = Arc::new(Mutex::new(CaptureLog::default()));
    let key_log = Arc::new(KeyLogCapture::default());

    let config = build_client_config(log.clone(), key_log.clone());

    // tokio runtime hosts the fixture HTTP server; the rustls 0.23 client runs
    // synchronously on a separate OS thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let response = rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            // The fixture's TLS server accepts TLS 1.3 with rustls defaults.
            let _ = bind_test_server_hyper(sock.compat()).await;
        });

        let client = std::thread::spawn(move || run_client(addr, config));
        let response = client.join().expect("client thread").expect("client io");
        server.abort();
        response
    });

    println!("--- transport ---");
    let head = String::from_utf8_lossy(&response);
    let first_line = head.lines().next().unwrap_or("<empty>");
    println!("HTTP response: {} ({} bytes)", first_line, response.len());

    analyze(&log.lock().unwrap(), &key_log)
}

fn analyze(log: &CaptureLog, key_log: &KeyLogCapture) -> Outcome {
    let mut assertions = Vec::new();

    // --- Diagnostics -------------------------------------------------------
    println!("\n--- capture summary ---");
    println!("extract calls: {}", log.extracts.len());
    for e in &log.extracts {
        println!(
            "  #{:<2} {:?}  salt={} ikm={}B prk={}",
            e.id,
            e.kind,
            e.salt
                .as_ref()
                .map(|s| format!("{}B", s.len()))
                .unwrap_or_else(|| "None".into()),
            e.ikm.len(),
            short(&e.prk),
        );
    }
    println!("expand calls: {}", log.expands.len());
    for ex in &log.expands {
        if let Some((len, label, ctx)) = verify::parse_hkdf_label(&ex.info) {
            println!(
                "  owner #{:<2} L={:<3} label={:?} ctx={}B",
                ex.owner_id,
                len,
                label,
                ctx.len()
            );
        } else {
            println!("  owner #{:<2} <unparsable info {}B>", ex.owner_id, ex.info.len());
        }
    }
    println!("keylog labels: {:?}", key_log.labels());

    // --- §3.2.0 RFC 8448 self-check (math sanity, no connection needed) ----
    match verify::rfc8448_self_check() {
        Ok(()) => assertions.push(Assertion::new(
            "RFC 8448 self-check (Derive-Secret + HkdfLabel)",
            true,
            None,
        )),
        Err(e) => assertions.push(Assertion::new(
            "RFC 8448 self-check (Derive-Secret + HkdfLabel)",
            false,
            Some(e),
        )),
    }

    // --- §3.2.1 Identify handshake_secret deterministically ----------------
    let chs = log
        .expands
        .iter()
        .find(|ex| label_of(&ex.info).as_deref() == Some("tls13 c hs traffic"));

    let Some(chs) = chs else {
        assertions.push(Assertion::new(
            "Identify handshake_secret via \"c hs traffic\" expansion",
            false,
            Some("no expansion with label \"tls13 c hs traffic\" was captured".into()),
        ));
        return Outcome { assertions };
    };

    let hs_record = log
        .extracts
        .iter()
        .find(|x| x.id == chs.owner_id)
        .expect("owner of the c-hs-traffic expander exists");

    let identified = hs_record.kind == ExtractKind::FromSecret;
    assertions.push(Assertion::new(
        "Identify handshake_secret via \"c hs traffic\" expansion (extract_from_secret)",
        identified,
        (!identified).then(|| format!("owner extract was {:?}, expected FromSecret", hs_record.kind)),
    ));

    let hs = hs_record.prk.clone();
    let (_, _, h2) = verify::parse_hkdf_label(&chs.info).expect("c hs traffic info parses");
    println!("\n--- identified secrets ---");
    println!("handshake_secret (HS) = {}", hex::encode(&hs));
    println!("h2 = H(CH..SH)        = {}", hex::encode(&h2));

    // --- §3.2.2 Handshake traffic secrets ----------------------------------
    check_against_keylog(
        &mut assertions,
        "Derive-Secret(HS, \"c hs traffic\", h2) == CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        verify::derive_secret(&hs, "c hs traffic", &h2),
        key_log.get("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
    );
    check_against_keylog(
        &mut assertions,
        "Derive-Secret(HS, \"s hs traffic\", h2) == SERVER_HANDSHAKE_TRAFFIC_SECRET",
        verify::derive_secret(&hs, "s hs traffic", &h2),
        key_log.get("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
    );

    // --- §3.2.2 Master secret + application traffic secrets ----------------
    let derived = verify::derive_secret(&hs, "derived", &verify::sha256_empty());
    let ms = verify::hkdf_extract(&derived, &[0u8; 32]);
    println!("derived (HS->MS salt) = {}", hex::encode(derived));
    println!("master_secret (MS)    = {}", hex::encode(ms));

    // Cross-check: the captured master-secret extract PRK must equal our MS.
    if let Some(ms_extract) = log
        .extracts
        .iter()
        .find(|x| x.kind == ExtractKind::FromZeroIkm && x.salt.as_deref() == Some(&derived[..]))
    {
        let ok = ms_extract.prk == ms;
        assertions.push(Assertion::new(
            "Captured master-secret extract PRK == recomputed MS",
            ok,
            (!ok).then(|| "captured MS PRK differs from RustCrypto recomputation".into()),
        ));
    }

    let h3 = log
        .expands
        .iter()
        .find(|ex| label_of(&ex.info).as_deref() == Some("tls13 c ap traffic"))
        .and_then(|ex| verify::parse_hkdf_label(&ex.info))
        .map(|(_, _, ctx)| ctx);

    let Some(h3) = h3 else {
        assertions.push(Assertion::new(
            "Extract h3 from \"c ap traffic\" expansion",
            false,
            Some("no expansion with label \"tls13 c ap traffic\" was captured".into()),
        ));
        return Outcome { assertions };
    };
    println!("h3 = H(CH..SF)        = {}", hex::encode(&h3));

    check_against_keylog(
        &mut assertions,
        "Derive-Secret(MS, \"c ap traffic\", h3) == CLIENT_TRAFFIC_SECRET_0",
        verify::derive_secret(&ms, "c ap traffic", &h3),
        key_log.get("CLIENT_TRAFFIC_SECRET_0"),
    );
    check_against_keylog(
        &mut assertions,
        "Derive-Secret(MS, \"s ap traffic\", h3) == SERVER_TRAFFIC_SECRET_0",
        verify::derive_secret(&ms, "s ap traffic", &h3),
        key_log.get("SERVER_TRAFFIC_SECRET_0"),
    );

    Outcome { assertions }
}

fn label_of(info: &[u8]) -> Option<String> {
    verify::parse_hkdf_label(info).map(|(_, label, _)| label)
}

fn check_against_keylog(
    assertions: &mut Vec<Assertion>,
    name: &str,
    computed: [u8; 32],
    keylog: Option<Vec<u8>>,
) {
    match keylog {
        Some(expected) => {
            let ok = expected == computed;
            assertions.push(Assertion::new(
                name,
                ok,
                (!ok).then(|| {
                    format!(
                        "computed={} keylog={}",
                        hex::encode(computed),
                        hex::encode(&expected)
                    )
                }),
            ));
        }
        None => assertions.push(Assertion::new(
            name,
            false,
            Some("keylog entry missing".into()),
        )),
    }
}

fn short(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    if h.len() > 16 {
        format!("{}…", &h[..16])
    } else {
        h
    }
}
