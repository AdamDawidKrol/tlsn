//! Builder type for [`TlsTranscript`].

use const_oid::db::rfc5912;
use rustls_pki_types as pki_types;
use sha2::{Digest, Sha256};
use spki::der::{Decode, oid::ObjectIdentifier};
use tls_core::msgs::{
    codec::Reader,
    enums::{
        CipherSuite, ContentType as TlsContentType, HandshakeType, NamedGroup, ProtocolVersion,
        SignatureScheme,
    },
    handshake::{HandshakeMessagePayload, HandshakePayload, KeyExchangeAlgorithm},
    message::OpaqueMessage,
};

use crate::{
    connection::{
        CertBinding, CertBindingV1_2, CertBindingV1_3, HandshakeData, KeyType, ServerEphemKey,
        ServerSignature, SignatureAlgorithm, SignatureScheme13, TlsVersion,
    },
    webpki::CertificateDer,
};

use super::{
    ContentType, Record, TlsTranscript, TlsTranscriptError,
    tls13::{decrypt_record, finished_key, traffic_keys, verify_data},
};

/// Builder for [`TlsTranscript`].
#[derive(Debug, Default)]
pub struct TlsTranscriptBuilder<'a> {
    time: Option<u64>,
    version: Option<TlsVersion>,
    tls_sent: Option<&'a [u8]>,
    tls_recv: Option<&'a [u8]>,
    app_sent: Option<&'a [u8]>,
    app_recv: Option<&'a [u8]>,
    records_sent: Option<Vec<Record>>,
    records_recv: Option<Vec<Record>>,
    server_signature: Option<ServerSignature>,
    server_cert_chain: Option<Vec<CertificateDer>>,
    certificate_binding: Option<CertBinding>,
    /// Disclosed TLS 1.3 handshake traffic secrets `(c_hs, s_hs)`, used to
    /// decrypt the handshake flight. Ignored for TLS 1.2.
    handshake_secrets: Option<([u8; 32], [u8; 32])>,
}

impl<'a> TlsTranscriptBuilder<'a> {
    /// Sets the time.
    pub fn time(mut self, time: u64) -> Self {
        self.time = Some(time);
        self
    }

    /// Sets the TLS version.
    pub fn version(mut self, version: TlsVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// Supplies the disclosed TLS 1.3 handshake traffic secrets used to
    /// decrypt and verify the handshake flight. Ignored for TLS 1.2.
    ///
    /// In proxy mode the prover passes its captured values and the verifier
    /// passes the values publicly decoded from the ZK key schedule (parent
    /// spec §5–§6); equality is established by that decode, not by trusting
    /// the prover.
    pub fn handshake_secrets(mut self, c_hs: [u8; 32], s_hs: [u8; 32]) -> Self {
        self.handshake_secrets = Some((c_hs, s_hs));
        self
    }

    /// Sets the tls data sent.
    pub fn tls_sent(mut self, data: &'a [u8]) -> Self {
        self.tls_sent = Some(data);
        self
    }

    /// Sets the tls data received.
    pub fn tls_recv(mut self, recv: &'a [u8]) -> Self {
        self.tls_recv = Some(recv);
        self
    }

    /// Sets the plaintext application data sent.
    pub fn app_sent(mut self, sent: &'a [u8]) -> Self {
        self.app_sent = Some(sent);
        self
    }

    /// Sets the plaintext application data received.
    pub fn app_recv(mut self, recv: &'a [u8]) -> Self {
        self.app_recv = Some(recv);
        self
    }

    /// Sets the sent records. First record must be client_finished record.
    pub fn records_sent(mut self, sent: Vec<Record>) -> Self {
        self.records_sent = Some(sent);
        self
    }

    /// Sets the received records. First record must be the server finished
    /// record.
    pub fn records_recv(mut self, recv: Vec<Record>) -> Self {
        self.records_recv = Some(recv);
        self
    }

    /// Sets the server signature.
    pub fn server_signature(mut self, sig: ServerSignature) -> Self {
        self.server_signature = Some(sig);
        self
    }

    /// Sets the server certificate chain.
    pub fn server_cert_chain(mut self, chain: Vec<CertificateDer>) -> Self {
        self.server_cert_chain = Some(chain);
        self
    }

    /// Sets the certificate binding.
    pub fn certificate_binding(mut self, binding: CertBinding) -> Self {
        self.certificate_binding = Some(binding);
        self
    }

    /// Builds a [`TlsTranscript`].
    ///
    /// Prefers available fields, but if missing tries to parse. The TLS
    /// version is detected from the ServerHello `supported_versions` extension
    /// (the `legacy_version` is `0x0303` even for TLS 1.3) and the
    /// version-specific path is selected accordingly.
    pub fn build(self) -> Result<TlsTranscript, TlsTranscriptError> {
        let time = self
            .time
            .ok_or_else(|| TlsTranscriptError::missing("time"))?;

        let sent_raw = if let Some(tls_sent) = self.tls_sent {
            Some(parse_raw_records(tls_sent)?)
        } else {
            None
        };

        let recv_raw = if let Some(tls_recv) = self.tls_recv {
            Some(parse_raw_records(tls_recv)?)
        } else {
            None
        };

        // Version detection keys off the ServerHello `supported_versions`
        // extension, falling back to an explicitly configured version.
        let version = match &recv_raw {
            Some(recv_raw) => detect_tls_version(recv_raw)?.or(self.version),
            None => self.version,
        };

        if version == Some(TlsVersion::V1_3) {
            self.build_v1_3(time, sent_raw, recv_raw)
        } else {
            self.build_v1_2(time, sent_raw, recv_raw)
        }
    }

    /// Builds a TLS 1.2 [`TlsTranscript`] (the original cleartext-handshake
    /// path). Byte-for-byte unchanged from the pre-TLS-1.3 builder.
    fn build_v1_2(
        mut self,
        time: u64,
        sent_raw: Option<Vec<OpaqueMessage>>,
        recv_raw: Option<Vec<OpaqueMessage>>,
    ) -> Result<TlsTranscript, TlsTranscriptError> {
        let (cf_hash, session_hash, sf_hash) = if let Some(sent_raw) = &sent_raw
            && let Some(recv_raw) = &recv_raw
        {
            let (cf_hash, session_hash, sf_hash) =
                self.parse_handshake_components(sent_raw, recv_raw)?;
            (Some(cf_hash), Some(session_hash), Some(sf_hash))
        } else {
            (None, None, None)
        };

        let sent = if let Some(records_sent) = self.records_sent {
            let client_finished = records_sent
                .first()
                .expect("client finished record should be available");
            validate_finished_record(client_finished)?;
            records_sent
        } else if let Some(sent_raw) = sent_raw {
            parse_records(&sent_raw, self.app_sent)?
        } else {
            return Err(TlsTranscriptError::missing("sent records"));
        };
        validate_seq(&sent)?;

        let recv = if let Some(records_recv) = self.records_recv {
            let server_finished = records_recv
                .first()
                .expect("server finished record should be available");
            validate_finished_record(server_finished)?;
            records_recv
        } else if let Some(recv_raw) = recv_raw {
            parse_records(&recv_raw, self.app_recv)?
        } else {
            return Err(TlsTranscriptError::missing("recv records"));
        };
        validate_seq(&recv)?;

        let version = self
            .version
            .ok_or_else(|| TlsTranscriptError::missing("version"))?;
        let certificate_binding = self
            .certificate_binding
            .ok_or_else(|| TlsTranscriptError::missing("certificate binding"))?;

        let transcript = TlsTranscript {
            time,
            version,
            server_signature: self.server_signature,
            server_cert_chain: self.server_cert_chain,
            certificate_binding,
            cf_hash,
            session_hash,
            sf_hash,
            sent,
            recv,
        };

        Ok(transcript)
    }

    /// Builds a TLS 1.3 [`TlsTranscript`].
    ///
    /// With `tls_sent`/`tls_recv` and [`handshake_secrets`](Self::handshake_secrets)
    /// available, decrypts and verifies the handshake flight in the clear
    /// (cert chain extraction, CertificateVerify and both Finished checks),
    /// derives [`CertBinding::V1_3`], and frames the application-epoch records.
    /// Otherwise it falls back to pre-supplied records + binding.
    fn build_v1_3(
        mut self,
        time: u64,
        sent_raw: Option<Vec<OpaqueMessage>>,
        recv_raw: Option<Vec<OpaqueMessage>>,
    ) -> Result<TlsTranscript, TlsTranscriptError> {
        self.version = Some(TlsVersion::V1_3);

        let (sent, recv) = if let (Some(sent_raw), Some(recv_raw), Some((c_hs, s_hs))) =
            (&sent_raw, &recv_raw, self.handshake_secrets)
        {
            let out = self.parse_handshake_components_v1_3(sent_raw, recv_raw, &c_hs, &s_hs)?;

            let sent = if let Some(records_sent) = self.records_sent.take() {
                records_sent
            } else {
                parse_records_tls13(sent_raw, self.app_sent, out.sent_app_start)?
            };
            let recv = if let Some(records_recv) = self.records_recv.take() {
                records_recv
            } else {
                parse_records_tls13(recv_raw, self.app_recv, out.recv_app_start)?
            };
            (sent, recv)
        } else {
            // Reconstruction path: the handshake was verified elsewhere; the
            // app-epoch records and the binding are supplied directly.
            let sent = self.records_sent.take().ok_or_else(|| {
                TlsTranscriptError::missing(
                    "sent records (TLS 1.3 needs tls_sent + handshake_secrets, or pre-built records)",
                )
            })?;
            let recv = self
                .records_recv
                .take()
                .ok_or_else(|| TlsTranscriptError::missing("recv records"))?;
            (sent, recv)
        };
        // Per-epoch sequence numbers start at 0; the "first record is Finished"
        // invariant is TLS 1.2 only (the 1.3 handshake records are verified in
        // the clear and are not part of `sent`/`recv`).
        validate_seq(&sent)?;
        validate_seq(&recv)?;

        let certificate_binding = self
            .certificate_binding
            .ok_or_else(|| TlsTranscriptError::missing("certificate binding"))?;

        Ok(TlsTranscript {
            time,
            version: TlsVersion::V1_3,
            server_signature: self.server_signature,
            server_cert_chain: self.server_cert_chain,
            certificate_binding,
            // TLS 1.3 feeds `h2`/`h3` into the ZK key schedule (item 8); the
            // TLS 1.2 handshake digests are unused.
            cf_hash: None,
            session_hash: None,
            sf_hash: None,
            sent,
            recv,
        })
    }

    /// Decrypts and verifies the TLS 1.3 handshake flight in the clear
    /// (parent spec §6.2) and populates the certificate binding, chain and
    /// signature. Returns where the application epoch begins in each
    /// direction.
    fn parse_handshake_components_v1_3(
        &mut self,
        sent_records: &[OpaqueMessage],
        recv_records: &[OpaqueMessage],
        c_hs: &[u8; 32],
        s_hs: &[u8; 32],
    ) -> Result<Handshake13Output, TlsTranscriptError> {
        // 1. Plaintext ClientHello / ServerHello (leading handshake records).
        let (ch_bytes, sent_hs_end) = leading_handshake_bytes(sent_records);
        let (sh_bytes, recv_hs_end) = leading_handshake_bytes(recv_records);
        if ch_bytes.is_empty() {
            return Err(TlsTranscriptError::parse("missing plaintext ClientHello"));
        }
        if sh_bytes.is_empty() {
            return Err(TlsTranscriptError::parse("missing plaintext ServerHello"));
        }

        // Validate ServerHello: TLS 1.3, supported suite, no PSK, no HRR.
        let server_hello = parse_single_handshake(&sh_bytes, "ServerHello")?;
        match &server_hello.payload {
            HandshakePayload::ServerHello(sh) => {
                if sh.cipher_suite != CipherSuite::TLS13_AES_128_GCM_SHA256 {
                    return Err(TlsTranscriptError::validation(format!(
                        "unsupported TLS 1.3 cipher suite: {:?} (only TLS13_AES_128_GCM_SHA256)",
                        sh.cipher_suite
                    )));
                }
                if sh.get_psk_index().is_some() {
                    return Err(TlsTranscriptError::validation(
                        "TLS 1.3 pre_shared_key (PSK) handshakes are not supported",
                    ));
                }
            }
            HandshakePayload::HelloRetryRequest(_) => {
                return Err(TlsTranscriptError::validation(
                    "TLS 1.3 HelloRetryRequest is not supported",
                ));
            }
            _ => {
                return Err(TlsTranscriptError::parse(
                    "first received handshake message is not ServerHello",
                ));
            }
        }

        // Sanity check the ClientHello.
        let client_hello = parse_single_handshake(&ch_bytes, "ClientHello")?;
        if !matches!(client_hello.payload, HandshakePayload::ClientHello(_)) {
            return Err(TlsTranscriptError::parse(
                "first sent handshake message is not ClientHello",
            ));
        }

        // 2. Decrypt the server handshake-epoch records with `s_hs` and
        // reassemble the EncryptedExtensions..Finished message stream. (h2 =
        // H(CH..SH) is not needed here; it is computed by the caller for the
        // ZK key schedule, parent spec §8.)
        let (s_key, s_iv) = traffic_keys(s_hs);
        let mut server_stream = Vec::new();
        let mut server_seq = 0u64;
        let mut recv_idx = skip_ccs(recv_records, recv_hs_end);
        loop {
            let record = recv_records.get(recv_idx).ok_or_else(|| {
                TlsTranscriptError::parse("server handshake flight ended before Finished")
            })?;
            let (inner_type, content) =
                decrypt_record(&s_key, &s_iv, server_seq, &record.payload.0)?;
            if inner_type != HANDSHAKE_INNER_TYPE {
                return Err(TlsTranscriptError::validation(format!(
                    "unexpected inner content type {inner_type} in server handshake flight",
                )));
            }
            server_stream.extend_from_slice(&content);
            server_seq += 1;
            recv_idx += 1;
            if handshake_flight_complete(&server_stream) {
                break;
            }
        }
        let recv_app_start = recv_idx;

        // 3. Parse and validate the server flight messages.
        let mut reader = Reader::init(&server_stream);
        let mut msgs = Vec::new();
        while reader.any_left() {
            let msg = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)
                .ok_or_else(|| {
                    TlsTranscriptError::parse("failed to parse server handshake message")
                })?;
            msgs.push(msg);
        }

        if !msgs
            .iter()
            .any(|m| matches!(m.payload, HandshakePayload::EncryptedExtensions(_)))
        {
            return Err(TlsTranscriptError::parse(
                "missing EncryptedExtensions in server flight",
            ));
        }
        if msgs.iter().any(|m| {
            matches!(
                m.payload,
                HandshakePayload::CertificateRequest(_)
                    | HandshakePayload::CertificateRequestTLS13(_)
            )
        }) {
            return Err(TlsTranscriptError::validation(
                "TLS 1.3 client authentication (CertificateRequest) is not supported",
            ));
        }
        let cert_entries = msgs
            .iter()
            .find_map(|m| match &m.payload {
                HandshakePayload::CertificateTLS13(c) => Some(&c.entries),
                _ => None,
            })
            .ok_or_else(|| TlsTranscriptError::parse("missing Certificate in server flight"))?;
        let cert_verify = msgs
            .iter()
            .find_map(|m| match &m.payload {
                HandshakePayload::CertificateVerify(cv) => Some(cv),
                _ => None,
            })
            .ok_or_else(|| {
                TlsTranscriptError::parse("missing CertificateVerify in server flight")
            })?;
        let server_finished_vd = msgs
            .iter()
            .find_map(|m| match &m.payload {
                HandshakePayload::Finished(f) => Some(&f.0),
                _ => None,
            })
            .ok_or_else(|| TlsTranscriptError::parse("missing server Finished"))?;

        // 4. Transcript hashes over the concatenated handshake messages.
        let infos = scan_handshake_messages(&server_stream)?;
        let cert_end = infos
            .iter()
            .find(|m| m.typ == HandshakeType::Certificate)
            .map(|m| m.end)
            .ok_or_else(|| TlsTranscriptError::parse("missing Certificate offset"))?;
        let cv_end = infos
            .iter()
            .find(|m| m.typ == HandshakeType::CertificateVerify)
            .map(|m| m.end)
            .ok_or_else(|| TlsTranscriptError::parse("missing CertificateVerify offset"))?;
        let finished_end = infos
            .iter()
            .find(|m| m.typ == HandshakeType::Finished)
            .map(|m| m.end)
            .ok_or_else(|| TlsTranscriptError::parse("missing Finished offset"))?;

        // cv_transcript_hash = H(CH..Certificate) — the CertificateVerify input.
        let cv_transcript_hash = sha256_concat(&[&ch_bytes, &sh_bytes, &server_stream[..cert_end]]);
        // H(CH..CertificateVerify) — the server Finished input.
        let sf_input_hash = sha256_concat(&[&ch_bytes, &sh_bytes, &server_stream[..cv_end]]);
        // h3 = H(CH..server Finished) — the client Finished input.
        let h3 = sha256_concat(&[&ch_bytes, &sh_bytes, &server_stream[..finished_end]]);

        // 5. Verify the server Finished.
        let expected_sf = verify_data(&finished_key(s_hs), &sf_input_hash);
        if server_finished_vd.as_slice() != expected_sf.as_slice() {
            return Err(TlsTranscriptError::crypto(
                "server Finished verify_data mismatch",
            ));
        }

        // 6. Decrypt and verify the client Finished (client auth is rejected,
        // so the client transcript ends at the server Finished, i.e. h3).
        let (c_key, c_iv) = traffic_keys(c_hs);
        let client_fin_idx = skip_ccs(sent_records, sent_hs_end);
        let client_fin_record = sent_records
            .get(client_fin_idx)
            .ok_or_else(|| TlsTranscriptError::parse("missing client Finished record"))?;
        let (inner_type, client_fin_content) =
            decrypt_record(&c_key, &c_iv, 0, &client_fin_record.payload.0)?;
        if inner_type != HANDSHAKE_INNER_TYPE {
            return Err(TlsTranscriptError::validation(
                "client Finished record is not a handshake message",
            ));
        }
        let mut reader = Reader::init(&client_fin_content);
        let client_fin =
            HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)
                .ok_or_else(|| TlsTranscriptError::parse("failed to parse client Finished"))?;
        let HandshakePayload::Finished(client_vd) = &client_fin.payload else {
            return Err(TlsTranscriptError::validation(
                "expected client Finished message",
            ));
        };
        let expected_cf = verify_data(&finished_key(c_hs), &h3);
        if client_vd.0.as_slice() != expected_cf.as_slice() {
            return Err(TlsTranscriptError::crypto(
                "client Finished verify_data mismatch",
            ));
        }
        let sent_app_start = client_fin_idx + 1;

        // 7. Build the certificate binding, chain and signature.
        let certs: Vec<CertificateDer> = cert_entries
            .iter()
            .map(|e| CertificateDer(e.cert.0.clone()))
            .collect();

        let sig_scheme = match cert_verify.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => SignatureScheme13::EcdsaSecp256r1Sha256,
            SignatureScheme::RSA_PSS_SHA256 => SignatureScheme13::RsaPssRsaeSha256,
            other => {
                return Err(TlsTranscriptError::validation(format!(
                    "unsupported TLS 1.3 CertificateVerify signature scheme: {other:?}",
                )));
            }
        };
        // `alg` is informational for TLS 1.3 — verification keys off
        // `sig_scheme` and uses the non-legacy RSA-PSS alg (see
        // `HandshakeData::verify`).
        let alg = match sig_scheme {
            SignatureScheme13::EcdsaSecp256r1Sha256 => SignatureAlgorithm::ECDSA_NISTP256_SHA256,
            SignatureScheme13::RsaPssRsaeSha256 => {
                SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
            }
        };
        let signature = ServerSignature {
            alg,
            sig: cert_verify.sig.0.clone(),
        };
        let binding = CertBinding::V1_3(CertBindingV1_3 {
            cv_transcript_hash,
            sig_scheme,
        });

        if self.server_signature.is_none() {
            self.server_signature = Some(signature);
        }
        if self.server_cert_chain.is_none() {
            self.server_cert_chain = Some(certs);
        }
        if self.certificate_binding.is_none() {
            self.certificate_binding = Some(binding);
        }

        Ok(Handshake13Output {
            sent_app_start,
            recv_app_start,
        })
    }

    /// Parse the pre-CCS handshake from both directions.
    fn parse_handshake_components(
        &mut self,
        sent_records: &[OpaqueMessage],
        recv_records: &[OpaqueMessage],
    ) -> Result<([u8; 32], [u8; 32], SfHashInput), TlsTranscriptError> {
        let (sent_hs_bytes, sent_hs) = parse_handshake_stream(sent_records)?;
        let (recv_hs_bytes, recv_hs) = parse_handshake_stream(recv_records)?;

        let (version, handshake) = extract_handshake(&sent_hs, &recv_hs)?;

        let sent_msgs = scan_handshake_messages(&sent_hs_bytes)?;
        let recv_msgs = scan_handshake_messages(&recv_hs_bytes)?;
        let (cf_hash, session_hash, sf_hash_input) =
            compute_handshake_hashes(sent_hs_bytes, recv_hs_bytes, &sent_msgs, &recv_msgs)?;

        if self.version.is_none() {
            self.version = Some(version);
        }
        if self.server_signature.is_none() {
            self.server_signature = Some(handshake.sig);
        }
        if self.server_cert_chain.is_none() {
            self.server_cert_chain = Some(handshake.certs);
        }
        if self.certificate_binding.is_none() {
            self.certificate_binding = Some(handshake.binding);
        }

        Ok((cf_hash, session_hash, sf_hash_input))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SfHashInput {
    pub(crate) sent_hs_bytes: Vec<u8>,
    pub(crate) recv_hs_bytes: Vec<u8>,
    pub(crate) sent_ch_end: usize,
    pub(crate) recv_shd_end: usize,
}

/// Where the application epoch begins in each direction after the TLS 1.3
/// handshake-epoch records have been consumed.
struct Handshake13Output {
    sent_app_start: usize,
    recv_app_start: usize,
}

const NONCE_LEN: usize = 8;
const TAG_LEN: usize = 16;

/// Inner content type of a TLS 1.3 handshake record (RFC 8446 §5).
const HANDSHAKE_INNER_TYPE: u8 = 0x16;

/// Parse raw TLS record frames from a byte slice.
fn parse_raw_records(bytes: &[u8]) -> Result<Vec<OpaqueMessage>, TlsTranscriptError> {
    let mut reader = Reader::init(bytes);
    let mut records = Vec::new();
    while reader.any_left() {
        let msg = OpaqueMessage::read(&mut reader)
            .map_err(|e| TlsTranscriptError::parse(format!("failed to read TLS record: {e:?}")))?;
        records.push(msg);
    }
    Ok(records)
}

/// Collect the pre-CCS handshake byte stream and decode it into
/// individual handshake messages.
fn parse_handshake_stream(
    records: &[OpaqueMessage],
) -> Result<(Vec<u8>, Vec<HandshakeMessagePayload>), TlsTranscriptError> {
    let handshake_bytes = collect_handshake_bytes_pre_ccs(records);

    let mut reader = Reader::init(&handshake_bytes);
    let mut messages = Vec::new();
    while reader.any_left() {
        let msg = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
            .ok_or_else(|| TlsTranscriptError::parse("failed to parse handshake message"))?;
        messages.push(msg);
    }
    Ok((handshake_bytes, messages))
}

/// Validate handshake-message bounds and compute the two
/// digests `cf_hash` and `session_hash`, and the cached
/// inputs needed to derive `sf_hash` later from `cf_vd`.
fn compute_handshake_hashes(
    sent_hs_bytes: Vec<u8>,
    recv_hs_bytes: Vec<u8>,
    sent_msgs: &[HandshakeMsgInfo],
    recv_msgs: &[HandshakeMsgInfo],
) -> Result<([u8; 32], [u8; 32], SfHashInput), TlsTranscriptError> {
    let client_hello = sent_msgs
        .first()
        .ok_or_else(|| TlsTranscriptError::parse("missing ClientHello in sent handshake stream"))?;
    if client_hello.typ != HandshakeType::ClientHello {
        return Err(TlsTranscriptError::parse(
            "first sent handshake message is not ClientHello",
        ));
    }
    let ckx = sent_msgs
        .iter()
        .find(|m| m.typ == HandshakeType::ClientKeyExchange)
        .ok_or_else(|| TlsTranscriptError::parse("missing ClientKeyExchange"))?;
    if !recv_msgs
        .iter()
        .any(|m| m.typ == HandshakeType::ServerHello)
    {
        return Err(TlsTranscriptError::parse("missing ServerHello"));
    }
    let shd = recv_msgs
        .iter()
        .find(|m| m.typ == HandshakeType::ServerHelloDone)
        .ok_or_else(|| TlsTranscriptError::parse("missing ServerHelloDone"))?;

    let sent_ch_end = client_hello.end;
    let recv_shd_end = shd.end;

    // session_hash: ClientHello → server flight (ServerHello..ServerHelloDone)
    // → client flight up to and including ClientKeyExchange.
    let mut hasher = Sha256::new();
    hasher.update(&sent_hs_bytes[..sent_ch_end]);
    hasher.update(&recv_hs_bytes);
    hasher.update(&sent_hs_bytes[sent_ch_end..ckx.end]);
    let session_hash: [u8; 32] = hasher.finalize().into();

    // cf_hash: ClientHello → server first flight (..ServerHelloDone)
    // → remaining client flight (ClientKeyExchange and, when client
    // auth is active, CertificateVerify).
    let mut hasher = Sha256::new();
    hasher.update(&sent_hs_bytes[..sent_ch_end]);
    hasher.update(&recv_hs_bytes[..recv_shd_end]);
    hasher.update(&sent_hs_bytes[sent_ch_end..]);
    let cf_hash: [u8; 32] = hasher.finalize().into();

    Ok((
        cf_hash,
        session_hash,
        SfHashInput {
            sent_hs_bytes,
            recv_hs_bytes,
            sent_ch_end,
            recv_shd_end,
        },
    ))
}

/// Concatenate the payload bytes of all handshake records appearing
/// before the first ChangeCipherSpec. These are the plaintext
/// handshake bytes as they appeared on the wire.
fn collect_handshake_bytes_pre_ccs(records: &[OpaqueMessage]) -> Vec<u8> {
    let mut handshake_bytes = Vec::new();
    for record in records {
        if record.typ == TlsContentType::ChangeCipherSpec {
            break;
        }
        if record.typ == TlsContentType::Handshake {
            handshake_bytes.extend_from_slice(&record.payload.0);
        }
    }
    handshake_bytes
}

/// Position information for a single handshake message inside a
/// concatenated handshake byte stream.
struct HandshakeMsgInfo {
    typ: HandshakeType,
    /// Exclusive end offset of the message (header + body) in the
    /// scanned byte stream.
    end: usize,
}

/// Walk a concatenated handshake byte stream and return the
/// [`HandshakeMsgInfo`].
fn scan_handshake_messages(bytes: &[u8]) -> Result<Vec<HandshakeMsgInfo>, TlsTranscriptError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes.len() - pos < 4 {
            return Err(TlsTranscriptError::parse("truncated handshake header"));
        }
        let typ = HandshakeType::from(bytes[pos]);
        let len = u32::from_be_bytes([0, bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
        let msg_end = pos + 4 + len;
        if msg_end > bytes.len() {
            return Err(TlsTranscriptError::parse(
                "handshake message length overflows buffer",
            ));
        }
        out.push(HandshakeMsgInfo { typ, end: msg_end });
        pos = msg_end;
    }
    Ok(out)
}

/// Split an encrypted TLS record payload into nonce / ciphertext / tag.
fn split_into_record(
    seq: u64,
    payload: &[u8],
    typ: TlsContentType,
) -> Result<Record, TlsTranscriptError> {
    let typ = ContentType::from(typ);

    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(TlsTranscriptError::parse("encrypted record too short"));
    }

    Ok(Record {
        seq,
        typ,
        plaintext: None,
        explicit_nonce: payload[..NONCE_LEN].to_vec(),
        ciphertext: payload[NONCE_LEN..payload.len() - TAG_LEN].to_vec(),
        tag: Some(payload[payload.len() - TAG_LEN..].to_vec()),
    })
}

/// Extract the full handshake data from parsed handshake messages.
fn extract_handshake(
    sent_hs: &[HandshakeMessagePayload],
    recv_hs: &[HandshakeMessagePayload],
) -> Result<(TlsVersion, HandshakeData), TlsTranscriptError> {
    let (version, server_random) = extract_server_hello_data(recv_hs)?;
    let client_random = extract_client_random(sent_hs)?;
    let certs = extract_certs(recv_hs)?;
    let (server_ephemeral_key, sig) = extract_server_key_exchange(recv_hs, &certs)?;

    let binding = CertBinding::V1_2(CertBindingV1_2 {
        client_random,
        server_random,
        server_ephemeral_key,
    });

    let handshake = HandshakeData {
        certs,
        sig,
        binding,
    };

    Ok((version, handshake))
}

/// Extract the TLS version and server random from the ServerHello message.
fn extract_server_hello_data(
    recv_hs: &[HandshakeMessagePayload],
) -> Result<(TlsVersion, [u8; 32]), TlsTranscriptError> {
    let server_hello = recv_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::ServerHello(sh) => Some(sh),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing ServerHello"))?;

    let version = TlsVersion::try_from(server_hello.legacy_version)
        .map_err(|e| TlsTranscriptError::parse(format!("unsupported TLS version: {e}")))?;

    Ok((version, server_hello.random.0))
}

fn extract_client_random(
    sent_hs: &[HandshakeMessagePayload],
) -> Result<[u8; 32], TlsTranscriptError> {
    let client_hello = sent_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::ClientHello(ch) => Some(ch),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing ClientHello"))?;

    Ok(client_hello.random.0)
}

fn extract_certs(
    recv_hs: &[HandshakeMessagePayload],
) -> Result<Vec<CertificateDer>, TlsTranscriptError> {
    let cert_payload = recv_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::Certificate(certs) => Some(certs),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing Certificate"))?;

    Ok(cert_payload
        .iter()
        .map(|cert| CertificateDer(cert.0.clone()))
        .collect())
}

fn extract_server_key_exchange(
    recv_hs: &[HandshakeMessagePayload],
    certs: &[CertificateDer],
) -> Result<(ServerEphemKey, ServerSignature), TlsTranscriptError> {
    let ske = recv_hs
        .iter()
        .find_map(|msg| match &msg.payload {
            HandshakePayload::ServerKeyExchange(ske) => Some(ske),
            _ => None,
        })
        .ok_or_else(|| TlsTranscriptError::parse("missing ServerKeyExchange"))?;

    let ecdhe = ske
        .unwrap_given_kxa(&KeyExchangeAlgorithm::ECDHE)
        .ok_or_else(|| TlsTranscriptError::parse("failed to parse ECDHE ServerKeyExchange"))?;

    if ecdhe.params.curve_params.named_group != NamedGroup::secp256r1 {
        return Err(TlsTranscriptError::parse(
            "unsupported key exchange group (only secp256r1 is supported)",
        ));
    }

    let key = ServerEphemKey {
        typ: KeyType::SECP256R1,
        key: ecdhe.params.public.0.clone(),
    };

    let alg = map_signature_scheme(ecdhe.dss.scheme, certs)?;
    let sig = ServerSignature {
        alg,
        sig: ecdhe.dss.sig.0.clone(),
    };

    Ok((key, sig))
}

/// Map a TLS `SignatureScheme` to our `SignatureAlgorithm`.
///
/// For ECDSA in TLS 1.2 the scheme only specifies the hash, not the curve.
/// The curve is determined from the end-entity certificate's public key.
fn map_signature_scheme(
    scheme: SignatureScheme,
    certs: &[CertificateDer],
) -> Result<SignatureAlgorithm, TlsTranscriptError> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512),
        SignatureScheme::RSA_PSS_SHA256 => {
            Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY)
        }
        SignatureScheme::RSA_PSS_SHA384 => {
            Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY)
        }
        SignatureScheme::RSA_PSS_SHA512 => {
            Ok(SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY)
        }
        SignatureScheme::ED25519 => Ok(SignatureAlgorithm::ED25519),
        // In TLS 1.2, ECDSA schemes specify only the hash — the curve
        // comes from the server certificate's public key.
        SignatureScheme::ECDSA_NISTP256_SHA256 => {
            let curve_oid = extract_ec_curve_oid(certs)?;
            match curve_oid {
                oid if oid == rfc5912::SECP_256_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP256_SHA256)
                }
                oid if oid == rfc5912::SECP_384_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP384_SHA256)
                }
                _ => Err(TlsTranscriptError::parse(format!(
                    "unsupported EC curve: {curve_oid}"
                ))),
            }
        }
        SignatureScheme::ECDSA_NISTP384_SHA384 => {
            let curve_oid = extract_ec_curve_oid(certs)?;
            match curve_oid {
                oid if oid == rfc5912::SECP_256_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP256_SHA384)
                }
                oid if oid == rfc5912::SECP_384_R_1 => {
                    Ok(SignatureAlgorithm::ECDSA_NISTP384_SHA384)
                }
                _ => Err(TlsTranscriptError::parse(format!(
                    "unsupported EC curve: {curve_oid}"
                ))),
            }
        }
        _ => Err(TlsTranscriptError::parse(format!(
            "unsupported signature scheme: {scheme:?}"
        ))),
    }
}

/// Extract the EC curve OID from the end-entity certificate's SPKI.
fn extract_ec_curve_oid(certs: &[CertificateDer]) -> Result<ObjectIdentifier, TlsTranscriptError> {
    let ee_cert = certs
        .first()
        .ok_or_else(|| TlsTranscriptError::parse("missing end-entity certificate"))?;

    let cert = pki_types::CertificateDer::from(ee_cert.0.as_slice());
    let ee = webpki::EndEntityCert::try_from(&cert)
        .map_err(|e| TlsTranscriptError::parse(format!("invalid end-entity certificate: {e}")))?;
    let spki_der = ee.subject_public_key_info();
    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der.as_ref())
        .map_err(|e| TlsTranscriptError::parse(format!("invalid SPKI: {e}")))?;
    spki.algorithm
        .parameters
        .ok_or_else(|| TlsTranscriptError::parse("missing EC curve parameters in SPKI"))?
        .decode_as::<ObjectIdentifier>()
        .map_err(|e| TlsTranscriptError::parse(format!("failed to decode EC curve OID: {e}")))
}

fn validate_finished_record(value: &Record) -> Result<(), TlsTranscriptError> {
    if !matches!(value.typ, ContentType::Handshake) {
        return Err(TlsTranscriptError::validation(format!(
            "first record expected to be a handshake finished message, but has type {:?}",
            value.typ
        )));
    }
    if value.seq != 0 {
        return Err(TlsTranscriptError::validation(format!(
            "first record should have sequence number 0, but has {}",
            value.seq
        )));
    }

    if let Some(payload) = &value.plaintext {
        let mut reader = Reader::init(payload);
        let payload = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_2)
            .ok_or_else(|| {
                TlsTranscriptError::validation("expected finished record but record is malformed")
            })?;

        if !matches!(payload.payload, HandshakePayload::Finished(_)) {
            return Err(TlsTranscriptError::validation("expected finished record"));
        }
    }

    Ok(())
}

fn validate_seq(records: &[Record]) -> Result<(), TlsTranscriptError> {
    for pair in records.windows(2) {
        if pair[1].seq <= pair[0].seq {
            return Err(TlsTranscriptError::validation(format!(
                "records must have strictly increasing sequence numbers, but got {} after {}",
                pair[1].seq, pair[0].seq,
            )));
        }
    }
    Ok(())
}

/// Parses records and adds plaintext to application data records.
fn parse_records(
    records: &[OpaqueMessage],
    app_data: Option<&[u8]>,
) -> Result<Vec<Record>, TlsTranscriptError> {
    let mut parsed = Vec::new();

    // Parse finished record.
    let ccs = records
        .iter()
        .position(|r| r.typ == TlsContentType::ChangeCipherSpec)
        .ok_or_else(|| TlsTranscriptError::missing("ccs record is missing"))?;
    let raw_finished = records
        .get(ccs + 1)
        .ok_or_else(|| TlsTranscriptError::parse("missing Finished record after CCS"))?;

    let payload = &raw_finished.payload.0;
    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(TlsTranscriptError::parse("encrypted record too short"));
    }

    let typ = raw_finished.typ.into();
    if !matches!(typ, ContentType::Handshake) {
        return Err(TlsTranscriptError::validation(format!(
            "expected content type handshake for finished record, but got {typ:?}"
        )));
    }

    let finished_record = Record {
        seq: 0,
        typ: ContentType::Handshake,
        plaintext: None,
        explicit_nonce: payload[..NONCE_LEN].to_vec(),
        ciphertext: payload[NONCE_LEN..payload.len() - TAG_LEN].to_vec(),
        tag: Some(payload[payload.len() - TAG_LEN..].to_vec()),
    };
    parsed.push(finished_record);

    // Now parse app data and skip CCS and the Finished record.
    let mut consumed = 0;
    for (seq, record) in (1u64..).zip(records.iter().skip(ccs + 2)) {
        let mut rec = split_into_record(seq, &record.payload.0, record.typ)?;

        if rec.typ == ContentType::ApplicationData
            && let Some(app_data) = app_data
        {
            let cipher_len = rec.ciphertext.len();
            if app_data[consumed..].len() >= cipher_len {
                rec.plaintext = Some(app_data[consumed..consumed + cipher_len].to_vec());
                consumed += cipher_len;
            } else {
                return Err(TlsTranscriptError::parse(
                    "insufficient plaintext application data",
                ));
            }
        }
        parsed.push(rec);
    }

    Ok(parsed)
}

/// Detects the negotiated TLS version from the ServerHello.
///
/// Keys off the `supported_versions` extension (the `legacy_version` field is
/// `0x0303` even for TLS 1.3). Returns `Ok(None)` if no plaintext ServerHello
/// is present. A HelloRetryRequest is rejected (parent spec §6.5).
fn detect_tls_version(records: &[OpaqueMessage]) -> Result<Option<TlsVersion>, TlsTranscriptError> {
    let Some(record) = records.iter().find(|r| r.typ == TlsContentType::Handshake) else {
        return Ok(None);
    };
    let mut reader = Reader::init(&record.payload.0);
    let Some(msg) = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)
    else {
        return Ok(None);
    };
    match msg.payload {
        HandshakePayload::ServerHello(sh) => {
            let version = sh.get_supported_versions().unwrap_or(sh.legacy_version);
            TlsVersion::try_from(version)
                .map(Some)
                .map_err(|e| TlsTranscriptError::parse(format!("unsupported TLS version: {e}")))
        }
        HandshakePayload::HelloRetryRequest(_) => Err(TlsTranscriptError::validation(
            "TLS 1.3 HelloRetryRequest is not supported",
        )),
        _ => Ok(None),
    }
}

/// Concatenates the payloads of the leading run of plaintext handshake records,
/// returning the bytes and the index of the first following record.
fn leading_handshake_bytes(records: &[OpaqueMessage]) -> (Vec<u8>, usize) {
    let mut bytes = Vec::new();
    let mut idx = 0;
    while let Some(record) = records.get(idx) {
        if record.typ != TlsContentType::Handshake {
            break;
        }
        bytes.extend_from_slice(&record.payload.0);
        idx += 1;
    }
    (bytes, idx)
}

/// Skips middlebox-compatibility ChangeCipherSpec records starting at `idx`.
fn skip_ccs(records: &[OpaqueMessage], mut idx: usize) -> usize {
    while let Some(record) = records.get(idx) {
        if record.typ == TlsContentType::ChangeCipherSpec {
            idx += 1;
        } else {
            break;
        }
    }
    idx
}

/// Parses exactly one TLS 1.3 handshake message from `bytes`.
fn parse_single_handshake(
    bytes: &[u8],
    what: &str,
) -> Result<HandshakeMessagePayload, TlsTranscriptError> {
    let mut reader = Reader::init(bytes);
    HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)
        .ok_or_else(|| TlsTranscriptError::parse(format!("failed to parse {what}")))
}

/// Returns whether `stream` contains a fully-assembled Finished message,
/// tolerating a trailing partial message split across record boundaries.
fn handshake_flight_complete(stream: &[u8]) -> bool {
    let mut pos = 0;
    while stream.len() >= pos + 4 {
        let typ = stream[pos];
        let len =
            u32::from_be_bytes([0, stream[pos + 1], stream[pos + 2], stream[pos + 3]]) as usize;
        let end = pos + 4 + len;
        if end > stream.len() {
            return false;
        }
        if typ == HandshakeType::Finished.get_u8() {
            return true;
        }
        pos = end;
    }
    false
}

/// SHA-256 over the concatenation of `parts`.
fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Maps a TLS 1.3 inner content-type byte to a [`ContentType`].
fn inner_content_type(value: u8) -> ContentType {
    match value {
        0x14 => ContentType::ChangeCipherSpec,
        0x15 => ContentType::Alert,
        0x16 => ContentType::Handshake,
        0x17 => ContentType::ApplicationData,
        0x18 => ContentType::Heartbeat,
        other => ContentType::Unknown(other),
    }
}

/// Frames the TLS 1.3 application-epoch records (parent spec §6.4).
///
/// Records before `app_start` (the plaintext ClientHello/ServerHello, the
/// ignored CCS, and the encrypted handshake flight) are skipped; `seq`
/// restarts at 0 for the application epoch. Unlike TLS 1.2 there is no 8-byte
/// explicit nonce, and `ciphertext` covers the full inner ciphertext (so
/// `ciphertext.len() == inner_plaintext.len()`); the trailing 16 bytes are the
/// tag.
///
/// `app_data`, when present, is the concatenation of the per-record **inner**
/// plaintexts (`content || inner_type || padding`), supplied by the party that
/// holds the application keys. Because the inner ciphertext and inner plaintext
/// have equal length, it is re-split per record; the inner type (the last
/// non-zero byte) sets [`Record::typ`] and the preceding `content` sets
/// [`Record::plaintext`]. When `app_data` is absent (the verifier, before the
/// ZK record proofs) the inner type and content are unknown without the
/// application keys: `plaintext` is `None` and `typ` is provisionally
/// `ApplicationData`. The authoritative inner-type classification and the
/// `type || padding` suffix proof are item 7 (parent spec §7.3).
fn parse_records_tls13(
    records: &[OpaqueMessage],
    app_data: Option<&[u8]>,
    app_start: usize,
) -> Result<Vec<Record>, TlsTranscriptError> {
    let mut parsed = Vec::new();
    let mut consumed = 0usize;

    for (seq, record) in (0u64..).zip(records.iter().skip(app_start)) {
        let body = &record.payload.0;
        if body.len() < TAG_LEN {
            return Err(TlsTranscriptError::parse(
                "TLS 1.3 encrypted record shorter than the AEAD tag",
            ));
        }
        let ct_len = body.len() - TAG_LEN;
        let ciphertext = body[..ct_len].to_vec();
        let tag = body[ct_len..].to_vec();

        let (typ, plaintext) = if let Some(app_data) = app_data {
            // `ciphertext.len() == inner_plaintext.len()` lets us re-split the
            // supplied inner plaintexts by the record's inner-ciphertext length.
            let inner = app_data.get(consumed..consumed + ct_len).ok_or_else(|| {
                TlsTranscriptError::parse("insufficient TLS 1.3 inner plaintext for app records")
            })?;
            consumed += ct_len;

            let type_pos = inner.iter().rposition(|&b| b != 0).ok_or_else(|| {
                TlsTranscriptError::parse("TLS 1.3 inner plaintext is all zero padding")
            })?;
            (
                inner_content_type(inner[type_pos]),
                Some(inner[..type_pos].to_vec()),
            )
        } else {
            // TODO(item 7, parent spec §7.3): the verifier learns the inner
            // type and the `type || padding` suffix via the ZK record proofs.
            (ContentType::ApplicationData, None)
        };

        parsed.push(Record {
            seq,
            typ,
            plaintext,
            explicit_nonce: Vec::new(),
            ciphertext,
            tag: Some(tag),
        });
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_server_fixture::SERVER_CERT_DER;

    // Pre-generated TLS 1.2 transcript fixtures. Captured once from a real
    // handshake against `tls_server_fixture::bind_test_server` followed by
    // four `msgN` records (each padded to 1024 bytes) echoed as "hello".
    // The server certificate is `tls_server_fixture::SERVER_CERT_DER`, so
    // regenerate these files if that cert ever changes.
    const SENT: &[u8] = include_bytes!("../fixtures/tls_sent.bin");
    const RECV: &[u8] = include_bytes!("../fixtures/tls_recv.bin");
    const APP_SENT: &[u8] = include_bytes!("../fixtures/tls_app_sent.bin");
    const APP_RECV: &[u8] = include_bytes!("../fixtures/tls_app_recv.bin");
    const MSG_COUNT: usize = 4;

    #[test]
    fn test_parse_handshake() {
        let transcript = TlsTranscript::builder()
            .time(0)
            .tls_sent(SENT)
            .tls_recv(RECV)
            .build()
            .unwrap();

        assert_eq!(transcript.version(), TlsVersion::V1_2);

        // Certificate chain should contain the server cert.
        let certs = transcript.server_cert_chain().expect("cert chain parsed");
        assert_eq!(certs[0].0, SERVER_CERT_DER);

        // Signature algorithm should be an RSA variant.
        let alg = &transcript.server_signature().expect("signature parsed").alg;
        assert!(
            matches!(
                alg,
                SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA256
                    | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA384
                    | SignatureAlgorithm::RSA_PKCS1_2048_8192_SHA512
                    | SignatureAlgorithm::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
                    | SignatureAlgorithm::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
                    | SignatureAlgorithm::RSA_PSS_2048_8192_SHA512_LEGACY_KEY
            ),
            "expected RSA signature algorithm, got {alg:?}"
        );

        // CertBinding should be V1_2 with valid values.
        let CertBinding::V1_2(binding) = transcript.certificate_binding() else {
            panic!("expected a TLS 1.2 certificate binding");
        };

        assert_ne!(binding.client_random, [0u8; 32]);
        assert_ne!(binding.server_random, [0u8; 32]);
        assert_eq!(binding.server_ephemeral_key.typ, KeyType::SECP256R1);
        // Uncompressed EC point: 65 bytes, starts with 0x04.
        assert_eq!(binding.server_ephemeral_key.key.len(), 65);
        assert_eq!(binding.server_ephemeral_key.key[0], 0x04);
    }

    #[test]
    fn test_parse_app_records() {
        let sent_raw = parse_raw_records(SENT).unwrap();
        let recv_raw = parse_raw_records(RECV).unwrap();
        let sent_records = parse_records(&sent_raw, Some(APP_SENT)).unwrap();
        let recv_records = parse_records(&recv_raw, Some(APP_RECV)).unwrap();

        // Sent records: 5 messages, finshed record and 4 app records
        assert_eq!(sent_records.len(), MSG_COUNT + 1);
        for (i, record) in sent_records.iter().enumerate() {
            let expected_seq = (i) as u64;
            if i == 0 {
                assert_eq!(record.typ, ContentType::Handshake);
            } else {
                assert_eq!(record.typ, ContentType::ApplicationData);
            }
            assert_eq!(record.seq, expected_seq);
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);
        }

        // Recv records: 5 messages, finshed record and 4 app records
        assert_eq!(recv_records.len(), MSG_COUNT + 1);
        for (i, record) in recv_records.iter().enumerate() {
            let expected_seq = (i) as u64;
            assert_eq!(record.seq, expected_seq);
            if i == 0 {
                assert_eq!(record.typ, ContentType::Handshake);
            } else {
                assert_eq!(record.typ, ContentType::ApplicationData);
            }
            assert_eq!(record.explicit_nonce.len(), 8);
            assert!(!record.ciphertext.is_empty());
            assert_eq!(record.tag.as_ref().unwrap().len(), 16);
        }
    }

    #[test]
    fn test_parse_into_transcript() {
        let transcript = TlsTranscript::builder()
            .time(0)
            .tls_sent(SENT)
            .tls_recv(RECV)
            .app_sent(APP_SENT)
            .app_recv(APP_RECV)
            .build()
            .unwrap();

        assert_eq!(transcript.version(), TlsVersion::V1_2);
        assert!(transcript.server_cert_chain().is_some());
        assert!(transcript.server_signature().is_some());

        // Finished verify-data records have content type Handshake.
        assert!(!transcript.client_finished().ciphertext.is_empty());
        assert!(!transcript.server_finished().ciphertext.is_empty());

        // 1 finished record and 4 app data records each
        assert_eq!(transcript.sent().len(), MSG_COUNT + 1);
        assert_eq!(transcript.recv().len(), MSG_COUNT + 1);
        assert_eq!(transcript.sent()[0].seq, 0);
        assert_eq!(transcript.recv()[0].seq, 0);
    }

    // ---- TLS 1.3 builder integration (RFC 8448 "simple 1-RTT handshake") ----
    //
    // We assemble a synthetic wire transcript from the published RFC 8448
    // records and disclosed traffic secrets. This exercises the full 1.3 path:
    // version detection, handshake-flight decryption + reassembly, server and
    // client Finished verification, CertBinding::V1_3 extraction, and
    // application-epoch record framing. The certificate-chain webpki check
    // lives in `HandshakeData::verify` (deferred to a real fixture, item 9) —
    // RFC 8448's 1024-bit, SAN-less cert is rejected by webpki — so it is not
    // exercised here.
    use super::super::tls13::rfc8448;

    /// Synthetic RFC 8448 wire transcript plus the disclosed handshake secrets.
    struct Rfc8448Wire {
        tls_sent: Vec<u8>,
        tls_recv: Vec<u8>,
        app_sent: Vec<u8>,
        app_recv: Vec<u8>,
        c_hs: [u8; 32],
        s_hs: [u8; 32],
    }

    /// Assembles the RFC 8448 wire transcript. The app-epoch inner plaintexts
    /// are recovered with the (known) application traffic secrets, mirroring
    /// what the record-holding party supplies.
    fn rfc8448_wire() -> Rfc8448Wire {
        let ch = rfc8448::record(0x16, &rfc8448::hex(rfc8448::CLIENT_HELLO_MSG));
        let sh = rfc8448::record(0x16, &rfc8448::hex(rfc8448::SERVER_HELLO_MSG));
        let flight = rfc8448::record(0x17, &rfc8448::hex(rfc8448::SERVER_FLIGHT_RECORD));
        let client_fin = rfc8448::record(0x17, &rfc8448::hex(rfc8448::CLIENT_FINISHED_RECORD));
        let ticket = rfc8448::record(0x17, &rfc8448::hex(rfc8448::SERVER_TICKET_RECORD));
        let client_app = rfc8448::record(0x17, &rfc8448::hex(rfc8448::CLIENT_APP_RECORD));

        let mut tls_sent = ch;
        tls_sent.extend_from_slice(&client_fin);
        tls_sent.extend_from_slice(&client_app);

        let mut tls_recv = sh;
        tls_recv.extend_from_slice(&flight);
        tls_recv.extend_from_slice(&ticket);

        // Client application record (seq 0) -> inner `content || 0x17`.
        let (c_key, c_iv) = traffic_keys(&rfc8448::hex_arr::<32>(rfc8448::C_AP));
        let (app_type, app_content) =
            decrypt_record(&c_key, &c_iv, 0, &rfc8448::hex(rfc8448::CLIENT_APP_RECORD)).unwrap();
        assert_eq!(app_type, 0x17);
        let mut app_sent = app_content;
        app_sent.push(0x17);

        // Server session-ticket record (seq 0) -> inner `NewSessionTicket || 0x16`.
        let (s_key, s_iv) = traffic_keys(&rfc8448::hex_arr::<32>(rfc8448::S_AP));
        let (ticket_type, ticket_content) = decrypt_record(
            &s_key,
            &s_iv,
            0,
            &rfc8448::hex(rfc8448::SERVER_TICKET_RECORD),
        )
        .unwrap();
        assert_eq!(ticket_type, 0x16);
        let mut app_recv = ticket_content;
        app_recv.push(0x16);

        Rfc8448Wire {
            tls_sent,
            tls_recv,
            app_sent,
            app_recv,
            c_hs: rfc8448::hex_arr::<32>(rfc8448::C_HS),
            s_hs: rfc8448::hex_arr::<32>(rfc8448::S_HS),
        }
    }

    #[test]
    fn test_tls13_build_decrypts_and_verifies_handshake() {
        let w = rfc8448_wire();

        let transcript = TlsTranscript::builder()
            .time(0)
            .tls_sent(&w.tls_sent)
            .tls_recv(&w.tls_recv)
            .handshake_secrets(w.c_hs, w.s_hs)
            .app_sent(&w.app_sent)
            .app_recv(&w.app_recv)
            .build()
            .unwrap();

        // Version detected from ServerHello supported_versions.
        assert_eq!(transcript.version(), TlsVersion::V1_3);

        // The certificate chain was extracted from the decrypted flight.
        let certs = transcript.server_cert_chain().expect("cert chain parsed");
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].0.is_empty());

        // The binding is V1_3 with a non-zero transcript hash and the RFC 8448
        // CertificateVerify scheme (rsa_pss_rsae_sha256).
        let CertBinding::V1_3(binding) = transcript.certificate_binding() else {
            panic!("expected a TLS 1.3 certificate binding");
        };
        assert_ne!(binding.cv_transcript_hash, [0u8; 32]);
        assert_eq!(binding.sig_scheme, SignatureScheme13::RsaPssRsaeSha256);

        // App epoch: exactly one record per direction, sequence restarts at 0,
        // no explicit nonce, 16-byte tag, and the full inner ciphertext.
        assert_eq!(transcript.sent().len(), 1);
        assert_eq!(transcript.recv().len(), 1);
        let sent0 = &transcript.sent()[0];
        assert_eq!(sent0.seq, 0);
        assert!(sent0.explicit_nonce.is_empty());
        assert_eq!(sent0.tag.as_ref().unwrap().len(), 16);
        assert_eq!(sent0.typ, ContentType::ApplicationData);
        // The recv app-epoch record is the NewSessionTicket (inner type
        // handshake), classified from the supplied inner plaintext.
        assert_eq!(transcript.recv()[0].typ, ContentType::Handshake);

        // The plaintext transcript holds the 50-byte client payload; the server
        // NewSessionTicket is filtered out (handshake, not application data).
        let app = transcript.to_transcript().unwrap();
        let expected_sent: Vec<u8> = (0u8..=0x31).collect();
        assert_eq!(app.sent(), expected_sent.as_slice());
        assert!(app.received().is_empty());
    }

    #[test]
    fn test_tls13_build_rejects_wrong_handshake_secret() {
        let mut w = rfc8448_wire();
        // Corrupt the server handshake secret: the AEAD tag must fail.
        w.s_hs[0] ^= 0x01;

        let err = TlsTranscript::builder()
            .time(0)
            .tls_sent(&w.tls_sent)
            .tls_recv(&w.tls_recv)
            .handshake_secrets(w.c_hs, w.s_hs)
            .build();

        assert!(err.is_err());
    }

    #[test]
    fn test_tls13_build_rejects_tampered_finished() {
        let mut w = rfc8448_wire();
        // Flip a byte inside the server flight ciphertext (after the SH record
        // and the 5-byte flight header): the AEAD tag check must fail.
        let sh_len = 5 + rfc8448::hex(rfc8448::SERVER_HELLO_MSG).len();
        let target = sh_len + 5 + 10;
        w.tls_recv[target] ^= 0x01;

        let err = TlsTranscript::builder()
            .time(0)
            .tls_sent(&w.tls_sent)
            .tls_recv(&w.tls_recv)
            .handshake_secrets(w.c_hs, w.s_hs)
            .build();

        assert!(err.is_err());
    }
}
