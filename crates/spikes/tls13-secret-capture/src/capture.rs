//! The capturing `Hkdf` / `HkdfExpander` wrappers and the `KeyLog` capture.

use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use rustls::KeyLog;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use sha2::Sha256;

/// What kind of extract call produced an expander.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractKind {
    /// `Hkdf::extract_from_secret(salt, ikm)`.
    FromSecret,
    /// `Hkdf::extract_from_zero_ikm(salt)` (ikm is `HashLen` zero bytes).
    FromZeroIkm,
    /// `Hkdf::expander_for_okm(okm)` — not a true extract; the OKM *is* the PRK.
    ForOkm,
}

/// One recorded extract (or `expander_for_okm`) call.
#[derive(Debug, Clone)]
pub struct ExtractRecord {
    pub id: usize,
    pub kind: ExtractKind,
    pub salt: Option<Vec<u8>>,
    pub ikm: Vec<u8>,
    /// The pseudo-random key, recomputed with RustCrypto HMAC-SHA256
    /// (`PRK = HMAC(salt_or_zeros, ikm)`); for `ForOkm` this is the OKM itself.
    pub prk: Vec<u8>,
}

/// One recorded `expand_block` / `expand_slice` call.
#[derive(Debug, Clone)]
pub struct ExpandRecord {
    /// Id of the extract/okm record that produced the expander.
    pub owner_id: usize,
    /// The `info` argument, with its constituent slices concatenated. For TLS
    /// 1.3 this is exactly the `HkdfLabel` encoding.
    pub info: Vec<u8>,
    /// Requested output length (recorded for completeness; not used by the
    /// verification chain).
    #[allow(dead_code)]
    pub output_len: usize,
}

/// Shared capture state.
#[derive(Debug, Default)]
pub struct CaptureLog {
    pub extracts: Vec<ExtractRecord>,
    pub expands: Vec<ExpandRecord>,
    next_id: usize,
}

impl CaptureLog {
    fn record_extract(
        &mut self,
        kind: ExtractKind,
        salt: Option<Vec<u8>>,
        ikm: Vec<u8>,
        prk: Vec<u8>,
    ) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.extracts.push(ExtractRecord {
            id,
            kind,
            salt,
            ikm,
            prk,
        });
        id
    }
}

pub type SharedLog = Arc<Mutex<CaptureLog>>;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// `HKDF-Extract` PRK = `HMAC(salt_or_zeros, ikm)`, recomputed locally so the
/// spike never has to reach inside rustls's opaque expander for the secret.
fn extract_prk(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
    let zeros = [0u8; 32];
    let salt = salt.unwrap_or(&zeros[..]);
    hmac_sha256(salt, ikm)
}

/// `Hkdf` wrapper that delegates all crypto to the ring-backed provider while
/// recording every extract input + PRK and (via [`CapturingExpander`]) every
/// expansion's `info` bytes.
pub struct CapturingHkdf {
    delegate: &'static dyn Hkdf,
    log: SharedLog,
}

impl CapturingHkdf {
    pub fn new(delegate: &'static dyn Hkdf, log: SharedLog) -> Self {
        Self { delegate, log }
    }
}

impl Hkdf for CapturingHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        // ring uses `HashLen` (= 32 for SHA-256) zero bytes as the ikm here.
        let ikm = vec![0u8; 32];
        let prk = extract_prk(salt, &ikm);
        let id = self.log.lock().unwrap().record_extract(
            ExtractKind::FromZeroIkm,
            salt.map(|s| s.to_vec()),
            ikm,
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
            secret.to_vec(),
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
            output_len: output.len(),
        });
        self.inner.expand_slice(info, output)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        self.log.lock().unwrap().expands.push(ExpandRecord {
            owner_id: self.owner_id,
            info: concat(info),
            output_len: self.inner.hash_len(),
        });
        self.inner.expand_block(info)
    }

    fn hash_len(&self) -> usize {
        self.inner.hash_len()
    }
}

/// `KeyLog` that records *every* label together with the client random and the
/// secret. Mirrors (and extends) the pattern in
/// `crates/tlsn/src/prover/client/proxy/keylog.rs`.
#[derive(Debug, Default)]
pub struct KeyLogCapture {
    entries: Mutex<Vec<KeyLogEntry>>,
}

#[derive(Debug, Clone)]
pub struct KeyLogEntry {
    pub label: String,
    /// Captured per spec §3.1.3 ("all labels + client randoms"); the production
    /// `SecretLog` keys connections by this value, but the spike only validates
    /// against secrets, so it is not read here.
    #[allow(dead_code)]
    pub client_random: Vec<u8>,
    pub secret: Vec<u8>,
}

impl KeyLogCapture {
    pub fn get(&self, label: &str) -> Option<Vec<u8>> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.label == label)
            .map(|e| e.secret.clone())
    }

    pub fn labels(&self) -> Vec<String> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.label.clone())
            .collect()
    }
}

impl KeyLog for KeyLogCapture {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.entries.lock().unwrap().push(KeyLogEntry {
            label: label.to_string(),
            client_random: client_random.to_vec(),
            secret: secret.to_vec(),
        });
    }

    fn will_log(&self, _label: &str) -> bool {
        true
    }
}
