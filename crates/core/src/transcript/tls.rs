//! TLS transcript.

use crate::{
    connection::{CertBinding, ServerSignature, TlsVersion},
    transcript::{Direction, Transcript, tls::builder::SfHashInput},
    webpki::CertificateDer,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod builder;
mod tls13;
pub use builder::{TlsTranscriptBuilder, peek_tls_version_and_sh_hash};

/// A transcript of TLS records sent and received by the prover.
///
/// # Invariants
///
/// * First record of `TlsTranscript::sent` or `TlsTranscript::recv` is the
///   finished record.
/// * Records are ordered but records which are not of type
///   [`ContentType::ApplicationData`] can be missing.
/// * Handshake related fields may be absent.
/// * Plaintext of records may be absent.
#[derive(Debug, Clone)]
pub struct TlsTranscript {
    pub(crate) time: u64,
    pub(crate) version: TlsVersion,
    pub(crate) server_signature: Option<ServerSignature>,
    pub(crate) server_cert_chain: Option<Vec<CertificateDer>>,
    pub(crate) certificate_binding: CertBinding,
    pub(crate) sent: Vec<Record>,
    pub(crate) recv: Vec<Record>,
    pub(crate) cf_hash: Option<[u8; 32]>,
    pub(crate) session_hash: Option<[u8; 32]>,
    pub(crate) sf_hash: Option<SfHashInput>,
    /// TLS 1.3 only: `h2 = H(ClientHello..ServerHello)`, the `set_sh_hash`
    /// input of the ZK key schedule (parent spec §5). `None` for TLS 1.2.
    pub(crate) tls13_sh_hash: Option<[u8; 32]>,
    /// TLS 1.3 only: `h3 = H(ClientHello..server Finished)`, the `set_sf_hash`
    /// input of the ZK key schedule (parent spec §5). `None` for TLS 1.2.
    pub(crate) tls13_sf_hash: Option<[u8; 32]>,
}

impl TlsTranscript {
    /// Returns a builder for [`TlsTranscript`].
    pub fn builder<'a>() -> TlsTranscriptBuilder<'a> {
        TlsTranscriptBuilder::default()
    }

    /// Returns the start time of the connection.
    pub fn time(&self) -> u64 {
        self.time
    }

    /// Returns the TLS protocol version.
    pub fn version(&self) -> TlsVersion {
        self.version
    }

    /// Returns the signature of the server.
    pub fn server_signature(&self) -> Option<&ServerSignature> {
        self.server_signature.as_ref()
    }

    /// Returns the certificate chain.
    pub fn server_cert_chain(&self) -> Option<&[CertificateDer]> {
        self.server_cert_chain.as_deref()
    }

    /// Returns the certificate binding.
    pub fn certificate_binding(&self) -> &CertBinding {
        &self.certificate_binding
    }

    /// Returns the sent records.
    pub fn sent(&self) -> &[Record] {
        &self.sent
    }

    /// Returns the received records.
    pub fn recv(&self) -> &[Record] {
        &self.recv
    }

    /// Returns the client finished record.
    ///
    /// **TLS 1.2 only.** In TLS 1.2 the encrypted client Finished record sits
    /// at `sent[0]`. TLS 1.3 fully verifies the handshake flight in the clear
    /// (parent spec §6.2), so the Finished records are not present in
    /// `sent`/`recv` — calling this on a 1.3 transcript returns the first
    /// application-epoch record, which is not a Finished record.
    pub fn client_finished(&self) -> &Record {
        debug_assert_eq!(
            self.version,
            TlsVersion::V1_2,
            "client_finished() is TLS 1.2 only; transcript version is {:?}",
            self.version
        );
        self.sent()
            .first()
            .expect("client finished record should be present")
    }

    /// Returns the client finished verify data.
    ///
    /// **TLS 1.2 only** (see [`Self::client_finished`]).
    pub fn cf_vd(&self) -> Option<&[u8]> {
        let cf = self.client_finished();

        // Strips off the handshake message header.
        cf.plaintext.as_ref().and_then(|plain| plain.get(4..))
    }

    /// Returns the server finished record.
    ///
    /// **TLS 1.2 only** (see [`Self::client_finished`]).
    pub fn server_finished(&self) -> &Record {
        debug_assert_eq!(
            self.version,
            TlsVersion::V1_2,
            "server_finished() is TLS 1.2 only; transcript version is {:?}",
            self.version
        );
        self.recv()
            .first()
            .expect("server finished record should be present")
    }

    /// Returns the server finished verify data.
    ///
    /// **TLS 1.2 only** (see [`Self::client_finished`]).
    pub fn sf_vd(&self) -> Option<&[u8]> {
        let sf = self.server_finished();

        // Strips off the handshake message header.
        sf.plaintext.as_ref().and_then(|plain| plain.get(4..))
    }

    /// Returns the client finished hash.
    ///
    /// **TLS 1.2 only**; `None` for TLS 1.3 (the 1.3 key schedule uses
    /// `h2`/`h3` instead of `cf_hash`/`session_hash`/`sf_hash`).
    pub fn cf_hash(&self) -> Option<[u8; 32]> {
        self.cf_hash.as_ref().copied()
    }

    /// Returns the session hash.
    ///
    /// The session hash is the SHA-256 digest over the handshake messages
    /// from ClientHello up to and including ClientKeyExchange (RFC 7627).
    /// It is used to derive the extended master secret.
    ///
    /// **TLS 1.2 only**; `None` for TLS 1.3.
    pub fn session_hash(&self) -> Option<[u8; 32]> {
        self.session_hash.as_ref().copied()
    }

    /// Returns the server finished hash given the client finished verify
    /// data.
    ///
    /// **TLS 1.2 only**; `None` for TLS 1.3.
    pub fn sf_hash(&self, cf_vd: &[u8; 12]) -> Option<[u8; 32]> {
        let sf_hash = self.sf_hash.as_ref()?;
        let SfHashInput {
            sent_hs_bytes,
            recv_hs_bytes,
            sent_ch_end,
            recv_shd_end,
        } = sf_hash;

        let mut hasher = Sha256::new();
        hasher.update(&sent_hs_bytes[..*sent_ch_end]);
        hasher.update(&recv_hs_bytes[..*recv_shd_end]);
        hasher.update(&sent_hs_bytes[*sent_ch_end..]);

        // Append the reconstructed Client Finished handshake message.
        hasher.update([0x14, 0x00, 0x00, 0x0c]);
        hasher.update(cf_vd);
        hasher.update(&recv_hs_bytes[*recv_shd_end..]);

        let sf_hash = hasher.finalize().into();
        Some(sf_hash)
    }

    /// Returns the TLS 1.3 ServerHello transcript hash
    /// `h2 = H(ClientHello..ServerHello)`.
    ///
    /// **TLS 1.3 only** (`set_sh_hash` input of the ZK key schedule, parent
    /// spec §5); `None` for TLS 1.2.
    pub fn tls13_sh_hash(&self) -> Option<[u8; 32]> {
        self.tls13_sh_hash
    }

    /// Returns the TLS 1.3 server-Finished transcript hash
    /// `h3 = H(ClientHello..server Finished)`.
    ///
    /// **TLS 1.3 only** (`set_sf_hash` input of the ZK key schedule, parent
    /// spec §5); `None` for TLS 1.2.
    pub fn tls13_sf_hash(&self) -> Option<[u8; 32]> {
        self.tls13_sf_hash
    }

    /// Returns the prover→verifier per-record TLS 1.3 framing metadata for the
    /// app-epoch records of both directions (parent spec §6.1, open-question
    /// §5).
    ///
    /// **TLS 1.3 only.** The prover builds this from its decrypted records and
    /// sends it to the verifier, which cannot decrypt; the verifier re-frames
    /// its (plaintext-less) records from this metadata and *validates* it with
    /// the `type || padding` suffix proof.
    pub fn tls13_record_metadata(&self) -> Tls13Metadata {
        fn meta(record: &Record) -> Tls13RecordMeta {
            Tls13RecordMeta {
                typ: inner_type_byte(record.typ),
                // Falls back to the full inner length only if `content_len` was
                // never set; for a built 1.3 transcript it is always present.
                content_len: record.content_len.unwrap_or(record.ciphertext.len()) as u32,
            }
        }
        Tls13Metadata {
            sent: self.sent.iter().map(meta).collect(),
            recv: self.recv.iter().map(meta).collect(),
        }
    }

    /// Returns the application data transcript.
    pub fn to_transcript(&self) -> Result<Transcript, TlsTranscriptError> {
        let mut sent = Vec::new();
        let mut recv = Vec::new();

        for record in self
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(ErrorRepr::Incomplete {
                    direction: Direction::Sent,
                    seq: record.seq,
                })?
                .clone();
            sent.extend_from_slice(&plaintext);
        }

        for record in self
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
        {
            let plaintext = record
                .plaintext
                .as_ref()
                .ok_or(ErrorRepr::Incomplete {
                    direction: Direction::Received,
                    seq: record.seq,
                })?
                .clone();
            recv.extend_from_slice(&plaintext);
        }

        Ok(Transcript::new(sent, recv))
    }
}

/// A TLS record.
#[derive(Clone)]
pub struct Record {
    /// Sequence number.
    pub seq: u64,
    /// Content type.
    pub typ: ContentType,
    /// Plaintext.
    pub plaintext: Option<Vec<u8>>,
    /// Explicit nonce.
    pub explicit_nonce: Vec<u8>,
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
    /// Tag.
    pub tag: Option<Vec<u8>>,
    /// Application-content length, i.e. the number of leading
    /// [`ciphertext`](Self::ciphertext) bytes that are application content.
    ///
    /// `None` for TLS 1.2 (the whole record body is content; framing falls
    /// back to [`plaintext`](Self::plaintext)/`ciphertext.len()`). For TLS 1.3
    /// it is `inner_len - 1 - padding`, set by the prover from the decrypted
    /// content (`plaintext.len()`) and by the verifier from the prover-declared
    /// [`Tls13RecordMeta`] (validated by the `type || padding` suffix proof).
    pub content_len: Option<usize>,
}

opaque_debug::implement!(Record);

/// Per-record TLS 1.3 framing metadata declared by the prover to the verifier
/// (parent spec §6.1, open-question §5).
///
/// In TLS 1.3 every application-epoch record is wire-typed `application_data`;
/// the real inner type is the last non-zero byte of the decrypted inner
/// plaintext and the content length is hidden by padding. The verifier cannot
/// decrypt (its application keys are blind in ZK), so the prover declares this
/// per record. It is a *hint*: the `type || padding` suffix proof
/// (`transcript_internal::auth`) validates it against the wire ciphertext, so a
/// mis-declared type or content boundary fails the consistency proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls13RecordMeta {
    /// Inner content type (RFC 8446 §5.1): `0x17` application_data, `0x16`
    /// handshake (NewSessionTicket/KeyUpdate), `0x15` alert.
    pub typ: u8,
    /// Inner content length (`inner_len - 1 - padding`); the padding length is
    /// derived by the verifier from the wire (`ciphertext.len()`), not sent.
    pub content_len: u32,
}

/// The prover→verifier per-record TLS 1.3 framing metadata for both
/// directions, in record order (see [`Tls13RecordMeta`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tls13Metadata {
    /// App-epoch records, sent direction, in order.
    pub sent: Vec<Tls13RecordMeta>,
    /// App-epoch records, recv direction, in order.
    pub recv: Vec<Tls13RecordMeta>,
}

/// TLS record content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContentType {
    /// Change cipher spec protocol.
    ChangeCipherSpec,
    /// Alert protocol.
    Alert,
    /// Handshake protocol.
    Handshake,
    /// Application data protocol.
    ApplicationData,
    /// Heartbeat protocol.
    Heartbeat,
    /// Unknown protocol.
    Unknown(u8),
}

impl From<ContentType> for tls_core::msgs::enums::ContentType {
    fn from(content_type: ContentType) -> Self {
        match content_type {
            ContentType::ChangeCipherSpec => tls_core::msgs::enums::ContentType::ChangeCipherSpec,
            ContentType::Alert => tls_core::msgs::enums::ContentType::Alert,
            ContentType::Handshake => tls_core::msgs::enums::ContentType::Handshake,
            ContentType::ApplicationData => tls_core::msgs::enums::ContentType::ApplicationData,
            ContentType::Heartbeat => tls_core::msgs::enums::ContentType::Heartbeat,
            ContentType::Unknown(id) => tls_core::msgs::enums::ContentType::Unknown(id),
        }
    }
}

impl From<tls_core::msgs::enums::ContentType> for ContentType {
    fn from(content_type: tls_core::msgs::enums::ContentType) -> Self {
        match content_type {
            tls_core::msgs::enums::ContentType::ChangeCipherSpec => ContentType::ChangeCipherSpec,
            tls_core::msgs::enums::ContentType::Alert => ContentType::Alert,
            tls_core::msgs::enums::ContentType::Handshake => ContentType::Handshake,
            tls_core::msgs::enums::ContentType::ApplicationData => ContentType::ApplicationData,
            tls_core::msgs::enums::ContentType::Heartbeat => ContentType::Heartbeat,
            tls_core::msgs::enums::ContentType::Unknown(id) => ContentType::Unknown(id),
        }
    }
}

/// The TLS 1.3 inner content-type byte for a [`ContentType`] (RFC 8446 §5.1),
/// the inverse of `builder::inner_content_type`.
pub(crate) fn inner_type_byte(typ: ContentType) -> u8 {
    match typ {
        ContentType::ChangeCipherSpec => 0x14,
        ContentType::Alert => 0x15,
        ContentType::Handshake => 0x16,
        ContentType::ApplicationData => 0x17,
        ContentType::Heartbeat => 0x18,
        ContentType::Unknown(id) => id,
    }
}

/// Error type.
#[derive(Debug, thiserror::Error)]
#[error("TLS transcript error: {0}")]
pub struct TlsTranscriptError(#[from] ErrorRepr);

impl TlsTranscriptError {
    fn parse(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Parse(msg.into()))
    }

    fn missing(field: &'static str) -> Self {
        Self(ErrorRepr::Missing(field))
    }

    fn validation(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Validation(msg.into()))
    }

    fn crypto(msg: impl Into<String>) -> Self {
        Self(ErrorRepr::Crypto(msg.into()))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ErrorRepr {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("incomplete transcript ({direction}): seq {seq}")]
    Incomplete { direction: Direction, seq: u64 },
    #[error("validation error: {0}")]
    Validation(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}
