//! TLS 1.3 secret capture.
//!
//! Productionized from the validated spike
//! `crates/spikes/tls13-secret-capture` (see `specs/tls13-proxy.md` §4 and
//! `specs/spikes/tls13-secret-capture-RESULTS.md`).
//!
//! rustls's `KeyLog` only exposes *traffic* secrets, never the
//! `handshake_secret` that links the handshake epoch to the application epoch.
//! To recover it we install a custom [`rustls::crypto::tls13::Hkdf`]
//! implementation ([`CapturingHkdf`]) into the TLS 1.3 cipher suite's
//! `hkdf_provider`. The wrapper delegates all crypto to ring's existing
//! `&'static dyn Hkdf` (ring's own `hmac` module is `pub(crate)`, so we cannot
//! build our own) while recording, for every `HKDF-Extract`, the recomputed PRK
//! (`HMAC-SHA256(salt, ikm)`) and, for every expansion, the `info` bytes.
//!
//! `handshake_secret` is then identified **deterministically**: it is the PRK
//! of the unique `extract_from_secret` call whose returned expander is later
//! asked to expand with the label `"tls13 c hs traffic"` (RFC 8446 §7.1). No
//! call-order heuristics are needed.
//!
//! Because rustls requires the suite (`SupportedCipherSuite::Tls13`) and its
//! `hkdf_provider` to be `&'static`, each capturing instance must be leaked.
//! [`CapturePool`] recycles leaked (suite + wrapper) instances through a global
//! free list so the leak is `O(max concurrency)`, not `O(connections)`: the
//! only per-connection mutable state is the [`CaptureLog`] behind an
//! `Arc<Mutex>`, which is drained and reused between leases.

use std::sync::{Arc, Mutex, OnceLock};

use hmac::{Hmac, Mac};
use rustls::{
    CipherSuiteCommon, SupportedCipherSuite, Tls13CipherSuite,
    crypto::{
        ring,
        tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError},
    },
};
use sha2::Sha256;

/// Output length of HKDF-SHA256, the hash of the only supported TLS 1.3 suite
/// (`TLS13_AES_128_GCM_SHA256`).
const HASH_LEN: usize = 32;

/// HKDF-Expand-Label label that uniquely identifies the handshake-secret
/// extraction (RFC 8446 §7.1, prefixed with the mandatory `"tls13 "`).
const CLIENT_HS_TRAFFIC_LABEL: &str = "tls13 c hs traffic";

/// What kind of `Hkdf` call produced an expander.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtractKind {
    /// `Hkdf::extract_from_secret(salt, ikm)` — the handshake secret comes from
    /// here in a non-PSK client handshake.
    FromSecret,
    /// `Hkdf::extract_from_zero_ikm(salt)` (ikm is `HashLen` zero bytes) — the
    /// early secret and the master secret come from here.
    FromZeroIkm,
    /// `Hkdf::expander_for_okm(okm)` — not a true extract; the OKM *is* the
    /// PRK.
    ForOkm,
}

/// One recorded extract (or `expander_for_okm`) call.
///
/// The input keying material (e.g. the ECDHE shared secret) is intentionally
/// **not** retained: the recomputed [`prk`](Self::prk) is all the key schedule
/// needs, and is exactly `handshake_secret` for the handshake-secret extract.
#[derive(Debug, Clone)]
pub(crate) struct ExtractRecord {
    pub(crate) id: usize,
    pub(crate) kind: ExtractKind,
    /// Extract salt; used by the capture test to locate the master-secret
    /// extraction (the production `handshake_secret` recovery does not need
    /// it).
    #[allow(dead_code)]
    pub(crate) salt: Option<Vec<u8>>,
    /// `PRK = HMAC-SHA256(salt_or_zeros, ikm)`, recomputed locally; for
    /// `ForOkm` this is the OKM itself.
    pub(crate) prk: Vec<u8>,
}

/// One recorded `expand_block` / `expand_slice` call.
#[derive(Debug, Clone)]
pub(crate) struct ExpandRecord {
    /// Id of the extract/okm record that produced the expander.
    pub(crate) owner_id: usize,
    /// The `info` argument with its constituent slices concatenated. For TLS
    /// 1.3 this is exactly the `HkdfLabel` encoding (length, label,
    /// context).
    pub(crate) info: Vec<u8>,
}

/// Per-connection capture state shared with the leaked [`CapturingHkdf`].
#[derive(Debug, Default)]
pub(crate) struct CaptureLog {
    pub(crate) extracts: Vec<ExtractRecord>,
    pub(crate) expands: Vec<ExpandRecord>,
    next_id: usize,
}

impl CaptureLog {
    fn record_extract(&mut self, kind: ExtractKind, salt: Option<Vec<u8>>, prk: Vec<u8>) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.extracts.push(ExtractRecord {
            id,
            kind,
            salt,
            prk,
        });
        id
    }

    /// Resets the log so the owning (suite + wrapper) instance can be reused
    /// for another connection without carrying over secret material.
    fn clear(&mut self) {
        self.extracts.clear();
        self.expands.clear();
        self.next_id = 0;
    }

    /// Recovers the 32-byte `handshake_secret` captured during the handshake.
    ///
    /// Identification is deterministic: the handshake secret is the PRK of the
    /// unique `extract_from_secret` whose expander expanded the
    /// `"tls13 c hs traffic"` label.
    pub(crate) fn handshake_secret(&self) -> Option<[u8; HASH_LEN]> {
        let c_hs = self
            .expands
            .iter()
            .find(|ex| label_of(&ex.info).as_deref() == Some(CLIENT_HS_TRAFFIC_LABEL))?;
        let record = self
            .extracts
            .iter()
            .find(|x| x.id == c_hs.owner_id && x.kind == ExtractKind::FromSecret)?;
        record.prk.as_slice().try_into().ok()
    }
}

/// Capture state shared between a leaked [`CapturingHkdf`], its pool entry, and
/// the connection's `SecretLog`.
pub(crate) type SharedLog = Arc<Mutex<CaptureLog>>;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// `HKDF-Extract` PRK = `HMAC(salt_or_zeros, ikm)`, recomputed locally so we
/// never have to read inside rustls's opaque expander for the secret.
fn extract_prk(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zeros = [0u8; HASH_LEN];
    let salt = salt.unwrap_or(&zeros[..]);
    hmac_sha256(salt, ikm)
}

/// Parses a captured `HkdfLabel` `info` blob into `(label, context)`. `label`
/// includes the `"tls13 "` prefix. Returns `None` on malformed input.
pub(crate) fn parse_hkdf_label(info: &[u8]) -> Option<(String, Vec<u8>)> {
    if info.len() < 3 {
        return None;
    }
    let label_len = info[2] as usize;
    let label_end = 3 + label_len;
    if info.len() < label_end + 1 {
        return None;
    }
    let label = String::from_utf8(info[3..label_end].to_vec()).ok()?;
    let ctx_len = info[label_end] as usize;
    let ctx_start = label_end + 1;
    let ctx_end = ctx_start + ctx_len;
    if info.len() < ctx_end {
        return None;
    }
    Some((label, info[ctx_start..ctx_end].to_vec()))
}

fn label_of(info: &[u8]) -> Option<String> {
    parse_hkdf_label(info).map(|(label, _)| label)
}

/// `Hkdf` wrapper that delegates all crypto to the ring-backed provider while
/// recording every extract's PRK and (via [`CapturingExpander`]) every
/// expansion's `info` bytes.
struct CapturingHkdf {
    delegate: &'static dyn Hkdf,
    log: SharedLog,
}

impl CapturingHkdf {
    fn new(delegate: &'static dyn Hkdf, log: SharedLog) -> Self {
        Self { delegate, log }
    }
}

impl Hkdf for CapturingHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        // ring uses `HashLen` (= 32 for SHA-256) zero bytes as the ikm here.
        let ikm = [0u8; HASH_LEN];
        let prk = extract_prk(salt, &ikm);
        let id = self.log.lock().unwrap().record_extract(
            ExtractKind::FromZeroIkm,
            salt.map(|s| s.to_vec()),
            prk,
        );
        Box::new(CapturingExpander {
            owner_id: id,
            log: self.log.clone(),
            inner: self.delegate.extract_from_zero_ikm(salt),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let prk = extract_prk(salt, secret);
        let id = self.log.lock().unwrap().record_extract(
            ExtractKind::FromSecret,
            salt.map(|s| s.to_vec()),
            prk,
        );
        Box::new(CapturingExpander {
            owner_id: id,
            log: self.log.clone(),
            inner: self.delegate.extract_from_secret(salt, secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        let id = self.log.lock().unwrap().record_extract(
            ExtractKind::ForOkm,
            None,
            okm.as_ref().to_vec(),
        );
        Box::new(CapturingExpander {
            owner_id: id,
            log: self.log.clone(),
            inner: self.delegate.expander_for_okm(okm),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> rustls::crypto::hmac::Tag {
        self.delegate.hmac_sign(key, message)
    }

    fn fips(&self) -> bool {
        self.delegate.fips()
    }
}

/// `HkdfExpander` wrapper that records every `info` it is asked to expand and
/// delegates the actual crypto.
struct CapturingExpander {
    owner_id: usize,
    log: SharedLog,
    inner: Box<dyn HkdfExpander>,
}

fn concat(info: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for chunk in info {
        v.extend_from_slice(chunk);
    }
    v
}

impl HkdfExpander for CapturingExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.log.lock().unwrap().expands.push(ExpandRecord {
            owner_id: self.owner_id,
            info: concat(info),
        });
        self.inner.expand_slice(info, output)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        self.log.lock().unwrap().expands.push(ExpandRecord {
            owner_id: self.owner_id,
            info: concat(info),
        });
        self.inner.expand_block(info)
    }

    fn hash_len(&self) -> usize {
        self.inner.hash_len()
    }
}

/// Builds a leaked TLS 1.3 cipher suite whose HKDF provider is a capturing
/// wrapper around ring's, writing into `log`.
///
/// The returned [`SupportedCipherSuite`] is `&'static`; it (and its wrapper)
/// must outlive every connection that uses it, which is why [`CapturePool`]
/// recycles these instances instead of leaking one per connection.
fn build_capturing_suite(log: SharedLog) -> SupportedCipherSuite {
    // Wrap the `Hkdf` instance already referenced by ring's
    // TLS13_AES_128_GCM_SHA256 suite. We cannot build our own
    // `HkdfUsingHmac(&ring::hmac::HMAC_SHA256)` because `rustls::crypto::ring::
    // hmac` is `pub(crate)` (see RESULTS.md "construction friction").
    let base: &'static Tls13CipherSuite = ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .expect("TLS13_AES_128_GCM_SHA256 is a TLS 1.3 suite");

    let capturing: &'static CapturingHkdf =
        Box::leak(Box::new(CapturingHkdf::new(base.hkdf_provider, log)));

    // `Tls13CipherSuite { hkdf_provider, ..*base }` does not compile: `common`
    // is a non-`Copy` `CipherSuiteCommon`, so the functional-update form would
    // move out of a `&'static` borrow. Reconstruct field-by-field (every field
    // is individually `Copy` or a `&'static` reference; all are public).
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

    SupportedCipherSuite::Tls13(suite)
}

/// A leaked (suite + wrapper) instance together with the capture log it writes
/// into. Recycled through [`CapturePool`].
struct PoolEntry {
    suite: SupportedCipherSuite,
    log: SharedLog,
}

/// Process-global pool of leaked capturing TLS 1.3 suites.
///
/// rustls forces these to be `&'static`, so they can never be freed. The pool
/// keeps a free list and only leaks a new instance when no idle one is
/// available, bounding the leak to the peak number of concurrent connections.
pub(crate) struct CapturePool {
    idle: Mutex<Vec<PoolEntry>>,
}

impl CapturePool {
    fn global() -> &'static CapturePool {
        static POOL: OnceLock<CapturePool> = OnceLock::new();
        POOL.get_or_init(|| CapturePool {
            idle: Mutex::new(Vec::new()),
        })
    }

    /// Leases a capturing TLS 1.3 suite for one connection. The returned
    /// [`CaptureLease`] returns the instance to the pool when dropped.
    pub(crate) fn lease() -> CaptureLease {
        let pool = Self::global();
        let entry = pool
            .idle
            .lock()
            .expect("capture pool lock is not poisoned")
            .pop()
            .unwrap_or_else(|| {
                let log: SharedLog = Arc::new(Mutex::new(CaptureLog::default()));
                let suite = build_capturing_suite(log.clone());
                PoolEntry { suite, log }
            });

        // Start from a clean log; any previous tenant's secrets are dropped here
        // as well as on release.
        entry
            .log
            .lock()
            .expect("capture log lock is not poisoned")
            .clear();

        CaptureLease { entry: Some(entry) }
    }
}

/// Per-connection handle to a leased capturing suite. Returns the leaked
/// instance to the [`CapturePool`] on drop, after draining its secrets.
pub(crate) struct CaptureLease {
    entry: Option<PoolEntry>,
}

impl CaptureLease {
    /// The capturing TLS 1.3 cipher suite to install into the provider.
    pub(crate) fn suite(&self) -> SupportedCipherSuite {
        self.entry
            .as_ref()
            .expect("lease is live until dropped")
            .suite
    }

    /// A handle to the capture log this connection writes into.
    pub(crate) fn log(&self) -> SharedLog {
        self.entry
            .as_ref()
            .expect("lease is live until dropped")
            .log
            .clone()
    }
}

impl Drop for CaptureLease {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            if let Ok(mut log) = entry.log.lock() {
                log.clear();
            }
            if let Ok(mut idle) = CapturePool::global().idle.lock() {
                idle.push(entry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Proves the capture works for a real TLS 1.3 handshake even though the
    //! production proxy still negotiates only TLS 1.2. Ports the spike's
    //! harness/verify approach: a synchronous rustls 0.23 `ClientConnection`
    //! built from the capturing provider runs a real local handshake against
    //! `tls_server_fixture` (whose rustls-0.22 server accepts TLS 1.3), and the
    //! captured `handshake_secret` / handshake traffic secrets are checked
    //! against rustls's own `KeyLog` output via an independent RustCrypto
    //! recomputation of the RFC 8446 §7.1 key schedule.

    use std::{
        io::{Read, Write},
        sync::Arc,
    };

    use rustls::{
        ClientConfig, RootCertStore,
        client::{ClientConnection, Resumption},
        pki_types::{CertificateDer, ServerName},
    };
    use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;
    use crate::prover::client::proxy::keylog::{CapturedSecrets, SecretLog};

    /// `Derive-Secret(secret, label, context)` recomputed with RustCrypto, NOT
    /// the rustls delegate. For a single 32-byte block this is just
    /// `HMAC(secret, HkdfLabel(32, label, context) || 0x01)`.
    fn derive_secret(secret: &[u8], label: &str, context: &[u8]) -> [u8; 32] {
        let full_label = format!("tls13 {label}");
        let mut info = Vec::new();
        info.extend_from_slice(&32u16.to_be_bytes());
        info.push(full_label.len() as u8);
        info.extend_from_slice(full_label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        info.push(0x01);

        let okm = hmac_sha256(secret, &info);
        okm.as_slice().try_into().expect("hmac-sha256 is 32 bytes")
    }

    fn sha256_empty() -> [u8; 32] {
        use sha2::Digest;
        Sha256::digest(b"").into()
    }

    /// Math sanity check against the RFC 8448 "simple 1-RTT" vectors,
    /// independent of any live connection.
    #[test]
    fn rfc8448_self_check() {
        let early = extract_prk(Some(&[0u8; 32]), &[0u8; 32]);
        assert_eq!(
            early,
            hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
            "RFC 8448 early secret mismatch"
        );
        let derived = derive_secret(&early, "derived", &sha256_empty());
        assert_eq!(
            derived.to_vec(),
            hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"),
            "RFC 8448 derived-secret mismatch"
        );
    }

    #[test]
    fn captures_tls13_handshake_secrets() {
        let lease = CapturePool::lease();
        let secret_log = Arc::new(SecretLog::new(lease.log()));
        let config = build_tls13_client_config(&lease, secret_log.clone());

        run_handshake(config);

        // --- production path: SecretLog -> CapturedSecrets ------------------
        let captured = secret_log.take().expect("secrets captured");
        let CapturedSecrets::V1_3 {
            handshake_secret,
            client_hs_traffic_secret,
            server_hs_traffic_secret,
        } = captured
        else {
            panic!("expected a TLS 1.3 capture");
        };

        // --- pull h2 (the "c hs traffic" expansion context) from the log ----
        let log = lease.log();
        let log = log.lock().unwrap();
        let h2 = log
            .expands
            .iter()
            .find_map(|ex| {
                let (label, ctx) = parse_hkdf_label(&ex.info)?;
                (label == CLIENT_HS_TRAFFIC_LABEL).then_some(ctx)
            })
            .expect("c hs traffic expansion was captured");

        // The captured handshake_secret must expand to exactly the handshake
        // traffic secrets rustls reported via its own KeyLog.
        assert_eq!(
            derive_secret(&handshake_secret, "c hs traffic", &h2),
            client_hs_traffic_secret,
            "Derive-Secret(HS, \"c hs traffic\", h2) != CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        );
        assert_eq!(
            derive_secret(&handshake_secret, "s hs traffic", &h2),
            server_hs_traffic_secret,
            "Derive-Secret(HS, \"s hs traffic\", h2) != SERVER_HANDSHAKE_TRAFFIC_SECRET"
        );

        // Bonus cross-check: the master-secret extract captured in the log must
        // equal MS recomputed from the captured handshake_secret. This exercises
        // the full HS -> derived -> MS leg of the §5 key schedule.
        let derived = derive_secret(&handshake_secret, "derived", &sha256_empty());
        let ms = extract_prk(Some(&derived), &[0u8; 32]);
        let ms_extract = log
            .extracts
            .iter()
            .find(|x| x.kind == ExtractKind::FromZeroIkm && x.salt.as_deref() == Some(&derived[..]))
            .expect("master-secret extract was captured");
        assert_eq!(ms_extract.prk, ms, "captured MS PRK != recomputed MS");
    }

    fn build_tls13_client_config(
        lease: &CaptureLease,
        key_log: Arc<SecretLog>,
    ) -> Arc<ClientConfig> {
        // A 1.3-only provider that forces negotiation onto the capturing suite.
        let mut provider = ring::default_provider();
        provider.cipher_suites = vec![lease.suite()];

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
        config.resumption = Resumption::disabled();
        Arc::new(config)
    }

    /// Drives one HTTP exchange over a real TLS 1.3 handshake. The fixture HTTP
    /// server runs on a tokio task; the rustls 0.23 client runs synchronously
    /// on a dedicated OS thread (the fixture's own TLS server is rustls
    /// 0.22 via `futures-rustls`, a different crate instance, so it cannot
    /// be reused for the client — the two interoperate over the wire).
    fn run_handshake(config: Arc<ClientConfig>) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");

            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.expect("accept");
                let _ = bind_test_server_hyper(sock.compat()).await;
            });

            let client = std::thread::spawn(move || run_client(addr, config));
            client.join().expect("client thread").expect("client io");
            server.abort();
        });
    }

    fn run_client(addr: std::net::SocketAddr, config: Arc<ClientConfig>) -> std::io::Result<()> {
        let server_name = ServerName::try_from(SERVER_DOMAIN).unwrap().to_owned();
        let mut conn = ClientConnection::new(config, server_name).expect("client connection");
        let mut sock = std::net::TcpStream::connect(addr)?;
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        let request = b"GET / HTTP/1.1\r\nHost: test-server.io\r\nConnection: close\r\n\r\n";
        tls.write_all(request)?;
        tls.flush()?;

        let mut response = Vec::new();
        match tls.read_to_end(&mut response) {
            Ok(_) => {}
            // An unclean TCP close after we already have the handshake + body is
            // fine for this test; we only care about the captured secrets.
            Err(_) if !response.is_empty() => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
