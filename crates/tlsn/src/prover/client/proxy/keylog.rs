//! `KeyLog` implementation that captures the per-connection TLS secrets the
//! proxy prover needs at finalization.
//!
//! For TLS 1.2 this is the 48-byte master secret (label `CLIENT_RANDOM`), as
//! before. For TLS 1.3 (see `specs/tls13-proxy.md` §4) rustls's `KeyLog` only
//! exposes the handshake *traffic* secrets, which alone cannot link the
//! handshake epoch to the application epoch in ZK. The `handshake_secret`
//! itself is recovered from the HKDF-capturing provider ([`super::capture`]);
//! this `KeyLog` captures the two handshake traffic secrets for disclosure and
//! validation, and decides 1.2 vs 1.3 from the labels rustls emits.

use std::sync::Mutex;

use rustls::KeyLog;

use crate::{Error as TlsnError, prover::client::proxy::capture::SharedLog};

/// The secrets captured from a single proxy-mode TLS connection, tagged by the
/// negotiated version. Consumed by [`crate::proxy::ProxyProver::finalize`].
pub(crate) enum CapturedSecrets {
    /// TLS 1.2: the 48-byte master secret (`CLIENT_RANDOM`).
    V1_2 { ms: [u8; 48] },
    /// TLS 1.3: the `handshake_secret` (recovered via the capturing HKDF
    /// provider) plus the two handshake traffic secrets (from the `KeyLog`).
    ///
    /// Consumed by the TLS 1.3 finalize flow (`specs/tls13-proxy.md` §8): the
    /// `handshake_secret` is the private input to the ZK key schedule and the
    /// two traffic secrets are asserted against its publicly-decoded outputs.
    V1_3 {
        handshake_secret: [u8; 32],
        client_hs_traffic_secret: [u8; 32],
        server_hs_traffic_secret: [u8; 32],
    },
}

#[derive(Debug, Default)]
struct KeyLogSecrets {
    /// TLS 1.2 master secret (label `CLIENT_RANDOM`).
    ms: Option<Vec<u8>>,
    /// TLS 1.3 client handshake traffic secret.
    client_hs: Option<Vec<u8>>,
    /// TLS 1.3 server handshake traffic secret.
    server_hs: Option<Vec<u8>>,
}

/// Captures the secrets of one proxy-mode connection.
///
/// Replaces the former `MasterSecretLog`: it is the connection's
/// [`rustls::KeyLog`] and also holds a handle to the HKDF capture log
/// ([`SharedLog`]) so it can recover `handshake_secret` for a TLS 1.3 session.
#[derive(Debug)]
pub(crate) struct SecretLog {
    /// HKDF capture log shared with the leaked capturing provider; the source
    /// of `handshake_secret` for TLS 1.3.
    capture: SharedLog,
    secrets: Mutex<KeyLogSecrets>,
}

impl SecretLog {
    pub(crate) fn new(capture: SharedLog) -> Self {
        Self {
            capture,
            secrets: Mutex::new(KeyLogSecrets::default()),
        }
    }

    /// Produces the captured secrets for this (now-complete) connection.
    ///
    /// A TLS 1.3 session is detected by the presence of
    /// handshake-traffic-secret labels; otherwise the 1.2 master secret is
    /// expected.
    pub(crate) fn take(&self) -> Result<CapturedSecrets, TlsnError> {
        let secrets = self
            .secrets
            .lock()
            .expect("secret log lock is not poisoned");

        // TLS 1.3: handshake traffic secrets were logged.
        if secrets.client_hs.is_some() || secrets.server_hs.is_some() {
            let client_hs_traffic_secret = to_array(secrets.client_hs.as_deref(), "client_hs")?;
            let server_hs_traffic_secret = to_array(secrets.server_hs.as_deref(), "server_hs")?;
            let handshake_secret = self
                .capture
                .lock()
                .expect("capture log lock is not poisoned")
                .handshake_secret()
                .ok_or_else(|| {
                    TlsnError::internal().with_msg("handshake_secret was not captured")
                })?;

            return Ok(CapturedSecrets::V1_3 {
                handshake_secret,
                client_hs_traffic_secret,
                server_hs_traffic_secret,
            });
        }

        // TLS 1.2: 48-byte master secret.
        let ms = to_array(secrets.ms.as_deref(), "master secret")?;
        Ok(CapturedSecrets::V1_2 { ms })
    }
}

fn to_array<const N: usize>(secret: Option<&[u8]>, what: &str) -> Result<[u8; N], TlsnError> {
    secret
        .ok_or_else(|| TlsnError::internal().with_msg(format!("{what} is not available")))?
        .try_into()
        .map_err(|_| TlsnError::internal().with_msg(format!("{what} has wrong length")))
}

impl KeyLog for SecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        let mut secrets = self
            .secrets
            .lock()
            .expect("secret log lock is not poisoned");
        match label {
            "CLIENT_RANDOM" => secrets.ms = Some(secret.to_vec()),
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => secrets.client_hs = Some(secret.to_vec()),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => secrets.server_hs = Some(secret.to_vec()),
            _ => {}
        }
    }

    fn will_log(&self, label: &str) -> bool {
        matches!(
            label,
            "CLIENT_RANDOM" | "CLIENT_HANDSHAKE_TRAFFIC_SECRET" | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
        )
    }
}
