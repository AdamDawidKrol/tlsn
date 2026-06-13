//! Proxy-specific proving and verifying logic.

use crate::{Error as TlsnError, tag::TagKeyIv, transcript_internal::auth::CipherParams};
use cipher::{Cipher, Keystream, aes::Aes128};
use futures::{AsyncRead, ready};
use hmac_sha256::{KeySchedule13, Prf, SessionKeys13};
use mpc_tls::SessionKeys;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm;
use std::{io, pin::Pin, task::Poll};

mod prover;
pub(crate) use prover::ProxyProver;

mod verifier;
pub(crate) use verifier::ProxyVerifier;

const AES_GCM_START_COUNTER: u32 = 2;

fn alloc_ghash_key(
    vm: &mut dyn Vm<Binary>,
    cipher: &mut Aes128,
) -> Result<Array<U8, 16>, TlsnError> {
    let zero_block: Array<U8, 16> = vm
        .alloc()
        .map_err(|e| TlsnError::internal().with_source(e))?;
    vm.mark_public(zero_block)
        .map_err(|e| TlsnError::internal().with_source(e))?;
    vm.assign(zero_block, [0u8; 16])
        .map_err(|e| TlsnError::internal().with_source(e))?;
    vm.commit(zero_block)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    let ghash_key = cipher
        .alloc_block(vm, zero_block)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    Ok(ghash_key)
}

/// Version-tagged proxy-mode session key handle, carried by [`TlsOutput`].
///
/// TLS 1.2 reuses [`mpc_tls::SessionKeys`] verbatim (4-byte implicit IVs,
/// shared with MPC mode — **never change that type**). TLS 1.3 needs 12-byte
/// IVs (RFC 8446 §5.3), so its keys are carried separately. The helpers below
/// produce the per-direction inputs the downstream record proofs consume
/// ([`TagKeyIv`] for tag verification, [`CipherParams`] for the plaintext
/// proofs), so callers never branch on the version themselves.
pub(crate) enum ProxyKeys {
    /// TLS 1.2 keys (4-byte IVs).
    V1_2(SessionKeys),
    /// TLS 1.3 keys (12-byte IVs).
    V1_3 {
        client_write_key: Array<U8, 16>,
        client_write_iv: Array<U8, 12>,
        server_write_key: Array<U8, 16>,
        server_write_iv: Array<U8, 12>,
        /// GHASH key `H = AES_serverkey(0^16)` for the received-record tags.
        server_write_mac_key: Array<U8, 16>,
    },
}

impl ProxyKeys {
    /// Tag-verification key/IV for the **received** (server) direction.
    pub(crate) fn recv_tag_key_iv(&self) -> TagKeyIv {
        match self {
            ProxyKeys::V1_2(keys) => TagKeyIv::V1_2 {
                key: keys.server_write_key,
                iv: keys.server_write_iv,
            },
            ProxyKeys::V1_3 {
                server_write_key,
                server_write_iv,
                ..
            } => TagKeyIv::V1_3 {
                key: *server_write_key,
                iv: *server_write_iv,
            },
        }
    }

    /// Plaintext-proof cipher params for the **sent** (client) direction.
    pub(crate) fn sent_cipher_params(&self) -> CipherParams {
        match self {
            ProxyKeys::V1_2(keys) => CipherParams::V1_2 {
                key: keys.client_write_key,
                iv: keys.client_write_iv,
            },
            ProxyKeys::V1_3 {
                client_write_key,
                client_write_iv,
                ..
            } => CipherParams::V1_3 {
                key: *client_write_key,
                iv: *client_write_iv,
            },
        }
    }

    /// Plaintext-proof cipher params for the **received** (server) direction.
    pub(crate) fn recv_cipher_params(&self) -> CipherParams {
        match self {
            ProxyKeys::V1_2(keys) => CipherParams::V1_2 {
                key: keys.server_write_key,
                iv: keys.server_write_iv,
            },
            ProxyKeys::V1_3 {
                server_write_key,
                server_write_iv,
                ..
            } => CipherParams::V1_3 {
                key: *server_write_key,
                iv: *server_write_iv,
            },
        }
    }

    /// GHASH key for the received-record tag verification.
    pub(crate) fn server_write_mac_key(&self) -> Array<U8, 16> {
        match self {
            ProxyKeys::V1_2(keys) => keys.server_write_mac_key,
            ProxyKeys::V1_3 {
                server_write_mac_key,
                ..
            } => *server_write_mac_key,
        }
    }
}

/// Controls how the master secret is marked in the VM during allocation.
enum MsVisibility {
    /// Prover knows the master secret value.
    Private,
    /// Verifier is blind to the master secret value.
    Blind,
}

/// Allocates all proxy-mode resources in the VM.
///
/// Because preprocessing runs **before** the connection, the negotiated TLS
/// version is unknown, so v1 allocates **both** graphs (parent spec §8,
/// open-question §2): the TLS 1.2 `Prf` (master secret, PRF-derived keys,
/// ciphers, GHASH key, verify-data decodes + checks) **and** the TLS 1.3
/// `KeySchedule13` (handshake secret, application keys, GHASH key, and the
/// public `c_hs`/`s_hs` decode futures). Only the negotiated graph is driven at
/// finalization; the unused one is allocated (a preprocessing cost) but never
/// flushed/executed (its inputs are never committed). The dual-allocation cost
/// is measured by the harness bench (item 9, open-question §2).
fn alloc_proxy_refs<V: Vm<Binary>>(
    vm: &mut V,
    prf: &mut Prf,
    ks13: &mut KeySchedule13,
    cf_vd_check: &mut VerifyDataCheck,
    sf_vd_check: &mut VerifyDataCheck,
    ms_visibility: MsVisibility,
) -> Result<References, TlsnError> {
    // ---- TLS 1.2 graph (Prf) --------------------------------------------
    let ms: Array<U8, 48> = vm.alloc().map_err(|e| {
        TlsnError::internal()
            .with_msg("ms allocation failed")
            .with_source(e)
    })?;

    match ms_visibility {
        MsVisibility::Private => vm.mark_private(ms),
        MsVisibility::Blind => vm.mark_blind(ms),
    }
    .map_err(|e| TlsnError::internal().with_source(e))?;

    let prf_output = prf.alloc_ms(vm, ms).map_err(|e| {
        TlsnError::internal()
            .with_msg("prf allocation failed")
            .with_source(e)
    })?;

    let mut encrypt = Aes128::default();
    encrypt.set_key(prf_output.keys.client_write_key);
    encrypt.set_iv(prf_output.keys.client_iv);

    let mut decrypt = Aes128::default();
    decrypt.set_key(prf_output.keys.server_write_key);
    decrypt.set_iv(prf_output.keys.server_iv);

    let server_write_mac_key = alloc_ghash_key(vm, &mut decrypt)?;

    let keys = SessionKeys {
        client_write_key: prf_output.keys.client_write_key,
        client_write_iv: prf_output.keys.client_iv,
        server_write_key: prf_output.keys.server_write_key,
        server_write_iv: prf_output.keys.server_iv,
        server_write_mac_key,
    };

    let cf_vd = vm
        .decode(prf_output.cf_vd)
        .map_err(|e| TlsnError::internal().with_source(e))?;
    _ = vm
        .decode(prf_output.sf_vd)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    cf_vd_check.alloc(vm, &mut encrypt, prf_output.cf_vd)?;
    sf_vd_check.alloc(vm, &mut decrypt, prf_output.sf_vd)?;

    // ---- TLS 1.3 graph (KeySchedule13) ----------------------------------
    let hs: Array<U8, 32> = vm.alloc().map_err(|e| {
        TlsnError::internal()
            .with_msg("handshake secret allocation failed")
            .with_source(e)
    })?;
    match ms_visibility {
        MsVisibility::Private => vm.mark_private(hs),
        MsVisibility::Blind => vm.mark_blind(hs),
    }
    .map_err(|e| TlsnError::internal().with_source(e))?;

    let schedule_out = ks13.alloc(vm, hs).map_err(|e| {
        TlsnError::internal()
            .with_msg("key schedule allocation failed")
            .with_source(e)
    })?;

    // 1.3 decrypt cipher + its GHASH key. `alloc_block` (used by
    // `alloc_ghash_key` for `AES_serverkey(0^16)`) needs only the key, so the
    // 12-byte IV is not required here.
    let mut decrypt13 = Aes128::default();
    decrypt13.set_key(schedule_out.keys.server_write_key);
    let server_write_mac_key13 = alloc_ghash_key(vm, &mut decrypt13)?;

    // Public decode of the handshake traffic secrets — the §5 disclosure
    // mechanism (prover asserts against captured values; verifier learns them).
    let c_hs = vm
        .decode(schedule_out.c_hs)
        .map_err(|e| TlsnError::internal().with_source(e))?;
    let s_hs = vm
        .decode(schedule_out.s_hs)
        .map_err(|e| TlsnError::internal().with_source(e))?;

    Ok(References {
        ms,
        keys,
        cf_vd,
        hs,
        keys13: schedule_out.keys,
        server_write_mac_key13,
        c_hs,
        s_hs,
    })
}

#[derive(Debug)]
struct References {
    // ---- TLS 1.2 set ----
    pub(crate) ms: Array<U8, 48>,
    pub(crate) keys: SessionKeys,
    pub(crate) cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    // ---- TLS 1.3 set ----
    pub(crate) hs: Array<U8, 32>,
    pub(crate) keys13: SessionKeys13,
    pub(crate) server_write_mac_key13: Array<U8, 16>,
    pub(crate) c_hs: DecodeFutureTyped<BitVec, [u8; 32]>,
    pub(crate) s_hs: DecodeFutureTyped<BitVec, [u8; 32]>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TlsBytes {
    pub(crate) tls_sent: Vec<u8>,
    pub(crate) tls_recv: Vec<u8>,
    pub(crate) app_sent: Vec<u8>,
    pub(crate) app_recv: Vec<u8>,
}

/// An [`AsyncRead`] adapter that records all bytes read into a buffer.
///
/// Used to intercept TLS traffic as it flows through the proxy,
/// extending the parser's transcript buffers on the fly.
pub(crate) struct InspectReader<'a, R> {
    inner: R,
    buf: &'a mut Vec<u8>,
    first_read: Option<u64>,
}

impl<'a, R> InspectReader<'a, R> {
    pub(crate) fn new(inner: R, buf: &'a mut Vec<u8>) -> Self {
        Self {
            inner,
            buf,
            first_read: None,
        }
    }

    pub(crate) fn first_read(&self) -> Option<u64> {
        self.first_read
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for InspectReader<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        if this.first_read.is_none() && n > 0 {
            let now = web_time::UNIX_EPOCH
                .elapsed()
                .expect("system time is available")
                .as_secs();
            this.first_read = Some(now);
        }
        this.buf.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }
}

#[derive(Debug, Default)]
pub(crate) struct VerifyDataCheck {
    state: InnerState,
}

#[derive(Default)]
enum InnerState {
    #[default]
    Init,
    Alloc {
        keystream: Keystream<Array<U8, 8>, Array<U8, 4>, Array<U8, 16>>,
        ciphertext_vd: Array<U8, 16>,
        expected_vd: Array<U8, 12>,
        actual_vd: Vector<U8>,
    },
    Assigned {
        expected_vd: Array<U8, 12>,
        actual_vd: Array<U8, 12>,
    },
}

opaque_debug::implement!(InnerState);

impl VerifyDataCheck {
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        cipher: &mut Aes128,
        expected_vd: Array<U8, 12>,
    ) -> Result<(), TlsnError> {
        let InnerState::Init = self.state else {
            return Err(TlsnError::internal().with_msg("unable to alloc verify data check"));
        };

        let ciphertext_vd: Array<U8, 16> = vm
            .alloc()
            .map_err(|e| TlsnError::internal().with_source(e))?;
        vm.mark_public(ciphertext_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        let keystream = cipher
            .alloc_keystream(vm, 16)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        let actual_vd = keystream
            .apply(vm, Vector::from(ciphertext_vd))
            .map_err(|e| TlsnError::internal().with_source(e))?;

        drop(
            vm.decode(actual_vd)
                .map_err(|e| TlsnError::internal().with_source(e))?,
        );

        self.state = InnerState::Alloc {
            keystream,
            ciphertext_vd,
            expected_vd,
            actual_vd,
        };
        Ok(())
    }

    pub(crate) fn assign(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: &[u8],
        ciphertext_vd: &[u8],
    ) -> Result<(), TlsnError> {
        let InnerState::Alloc {
            expected_vd,
            ciphertext_vd: ciphertext_vd_ref,
            actual_vd,
            keystream,
        } = &mut self.state
        else {
            return Err(TlsnError::internal().with_msg("unable to assign verify data check"));
        };
        let explicit_nonce = explicit_nonce
            .try_into()
            .map_err(|e| TlsnError::internal().with_source(e))?;
        let ciphertext_vd: [u8; 16] = ciphertext_vd
            .try_into()
            .map_err(|e| TlsnError::internal().with_source(e))?;

        keystream
            .assign(vm, explicit_nonce, || AES_GCM_START_COUNTER.to_be_bytes())
            .map_err(|e| TlsnError::internal().with_source(e))?;

        vm.assign(*ciphertext_vd_ref, ciphertext_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        vm.commit(*ciphertext_vd_ref)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // split off the handshake header first.
        let actual_vd = actual_vd.split_off(4);
        let actual_vd =
            Array::try_from(actual_vd).map_err(|e| TlsnError::internal().with_source(e))?;

        self.state = InnerState::Assigned {
            expected_vd: *expected_vd,
            actual_vd,
        };

        Ok(())
    }

    pub(crate) fn check(self, vm: &mut dyn Vm<Binary>) -> Result<(), TlsnError> {
        let InnerState::Assigned {
            expected_vd,
            actual_vd,
        } = self.state
        else {
            return Err(TlsnError::internal().with_msg("unable to check verify data"));
        };

        let expected_vd = vm
            .get(expected_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("could not retrieve expected verify data"))?;

        let actual_vd = vm
            .get(actual_vd)
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("could not retrieve actual verify data"))?;

        if expected_vd != actual_vd {
            return Err(TlsnError::user().with_msg("verify data check failed"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_ideal_vm::IdealVm;

    fn alloc<const N: usize>(vm: &mut IdealVm) -> Array<U8, N> {
        vm.alloc().unwrap()
    }

    /// The `ProxyKeys::V1_3` helpers must select the right direction and the
    /// 12-byte (TLS 1.3) IV width for every downstream record-proof input.
    #[test]
    fn test_proxy_keys_v1_3_mapping() {
        let mut vm = IdealVm::new();
        let cwk: Array<U8, 16> = alloc(&mut vm);
        let civ: Array<U8, 12> = alloc(&mut vm);
        let swk: Array<U8, 16> = alloc(&mut vm);
        let siv: Array<U8, 12> = alloc(&mut vm);
        let mac: Array<U8, 16> = alloc(&mut vm);

        let keys = ProxyKeys::V1_3 {
            client_write_key: cwk,
            client_write_iv: civ,
            server_write_key: swk,
            server_write_iv: siv,
            server_write_mac_key: mac,
        };

        // Received-record tags use the server key/IV (12-byte IV).
        match keys.recv_tag_key_iv() {
            TagKeyIv::V1_3 { key, iv } => {
                assert_eq!(key, swk);
                assert_eq!(iv, siv);
            }
            _ => panic!("expected TLS 1.3 tag key/iv"),
        }

        // Sent plaintext proofs use the client key/IV.
        match keys.sent_cipher_params() {
            CipherParams::V1_3 { key, iv } => {
                assert_eq!(key, cwk);
                assert_eq!(iv, civ);
            }
            _ => panic!("expected TLS 1.3 cipher params"),
        }

        // Received plaintext proofs use the server key/IV.
        match keys.recv_cipher_params() {
            CipherParams::V1_3 { key, iv } => {
                assert_eq!(key, swk);
                assert_eq!(iv, siv);
            }
            _ => panic!("expected TLS 1.3 cipher params"),
        }

        assert_eq!(keys.server_write_mac_key(), mac);
    }

    /// The `ProxyKeys::V1_2` helpers reproduce the original 1.2 mapping (4-byte
    /// IVs) byte-for-byte.
    #[test]
    fn test_proxy_keys_v1_2_mapping() {
        let mut vm = IdealVm::new();
        let cwk: Array<U8, 16> = alloc(&mut vm);
        let civ: Array<U8, 4> = alloc(&mut vm);
        let swk: Array<U8, 16> = alloc(&mut vm);
        let siv: Array<U8, 4> = alloc(&mut vm);
        let mac: Array<U8, 16> = alloc(&mut vm);

        let keys = ProxyKeys::V1_2(SessionKeys {
            client_write_key: cwk,
            client_write_iv: civ,
            server_write_key: swk,
            server_write_iv: siv,
            server_write_mac_key: mac,
        });

        match keys.recv_tag_key_iv() {
            TagKeyIv::V1_2 { key, iv } => {
                assert_eq!(key, swk);
                assert_eq!(iv, siv);
            }
            _ => panic!("expected TLS 1.2 tag key/iv"),
        }
        match keys.sent_cipher_params() {
            CipherParams::V1_2 { key, iv } => {
                assert_eq!(key, cwk);
                assert_eq!(iv, civ);
            }
            _ => panic!("expected TLS 1.2 cipher params"),
        }
        match keys.recv_cipher_params() {
            CipherParams::V1_2 { key, iv } => {
                assert_eq!(key, swk);
                assert_eq!(iv, siv);
            }
            _ => panic!("expected TLS 1.2 cipher params"),
        }
        assert_eq!(keys.server_write_mac_key(), mac);
    }
}
