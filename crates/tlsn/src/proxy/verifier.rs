use crate::{
    Error as TlsnError, TlsOutput,
    deps::VerifierZk,
    proxy::{MsVisibility, ProxyKeys, References, VerifyDataCheck, alloc_proxy_refs},
};
use hmac_sha256::{KeySchedule13, Prf};
use mpz_common::Context;
use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
use serio::stream::IoStreamExt;
use tlsn_core::{
    connection::TlsVersion,
    transcript::{Tls13Metadata, TlsTranscript, peek_tls_version_and_sh_hash},
};

/// The verifier's finalize output. The two verify-data checks are `Some` only
/// for TLS 1.2 (the cf/sf Finished records); TLS 1.3 has no such records and
/// returns `None` for both (parent spec §7).
type FinalizeOutput = (
    Context,
    VerifierZk,
    TlsOutput,
    Option<VerifyDataCheck>,
    Option<VerifyDataCheck>,
);

pub(crate) struct ProxyVerifier {
    ctx: Context,
    vm: VerifierZk,
    prf: Prf,
    /// TLS 1.3 ZK key schedule, allocated alongside `prf` (dual-graph
    /// allocation, parent spec §8); only one is driven at finalization.
    ks13: KeySchedule13,
    refs: Option<References>,
    cf_vd_check: VerifyDataCheck,
    sf_vd_check: VerifyDataCheck,
}

impl ProxyVerifier {
    pub(crate) fn new(prf: Prf, vm: VerifierZk, ctx: Context) -> Self {
        Self {
            ctx,
            vm,
            prf,
            ks13: KeySchedule13::new(),
            refs: None,
            cf_vd_check: VerifyDataCheck::default(),
            sf_vd_check: VerifyDataCheck::default(),
        }
    }

    pub(crate) fn alloc(&mut self) -> Result<(), TlsnError> {
        self.refs = Some(alloc_proxy_refs(
            &mut self.vm,
            &mut self.prf,
            &mut self.ks13,
            &mut self.cf_vd_check,
            &mut self.sf_vd_check,
            MsVisibility::Blind,
        )?);
        Ok(())
    }

    pub(crate) async fn preprocess(&mut self) -> Result<(), TlsnError> {
        self.vm.flush(&mut self.ctx).await.map_err(|e| {
            TlsnError::internal()
                .with_msg("preprocessing proxy-tls failed")
                .with_source(e)
        })
    }

    pub(crate) async fn finalize(
        self,
        sent: &[u8],
        recv: &[u8],
        conn_time: u64,
    ) -> Result<FinalizeOutput, TlsnError> {
        // The verifier has no rustls connection, so it learns the negotiated
        // version (and `h2`) from the plaintext wire records.
        let (version, h2) = peek_tls_version_and_sh_hash(sent, recv).map_err(|e| {
            TlsnError::internal()
                .with_msg("verifier could not peek tls version")
                .with_source(e)
        })?;

        match version {
            TlsVersion::V1_2 => self.finalize_v1_2(sent, recv, conn_time).await,
            TlsVersion::V1_3 => self.finalize_v1_3(sent, recv, conn_time, h2).await,
        }
    }

    /// TLS 1.2 finalize flow. Byte-for-byte the original proxy-mode verifier
    /// flow; returns `Some` cf/sf checks.
    async fn finalize_v1_2(
        mut self,
        sent: &[u8],
        recv: &[u8],
        conn_time: u64,
    ) -> Result<FinalizeOutput, TlsnError> {
        let tls_transcript = TlsTranscript::builder()
            .time(conn_time)
            .tls_sent(sent)
            .tls_recv(recv)
            .build()
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("verifier could not build tls transcript")
                    .with_source(e)
            })?;
        tracing::debug!("successfully parsed transcript");

        let mut refs = self.refs.expect("key refs should be available");

        let cf_hash: [u8; 32] = tls_transcript
            .cf_hash()
            .expect("client finished hash should be available");

        let tlsn_core::connection::CertBinding::V1_2(binding) =
            tls_transcript.certificate_binding()
        else {
            return Err(
                TlsnError::internal().with_msg("version of certificate binding is not supported")
            );
        };

        tracing::debug!("computing PRF...");
        self.vm
            .commit(refs.ms)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        self.prf.set_client_random(binding.client_random);
        self.prf
            .set_server_random(binding.server_random)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.prf
            .set_cf_hash(cf_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // First flush: master_secret, key_expansion, and client_finished
        // progress. server_finished sits idle (sf_hash not yet set).
        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        tracing::debug!("decoding client finished verify data...");
        let cf_vd = refs
            .cf_vd
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive cf_vd from decoding"))?;

        // Now that cf_vd is known, compute sf_hash and resume the PRF.
        let sf_hash: [u8; 32] = tls_transcript
            .sf_hash(&cf_vd)
            .expect("server finished hash should be available");

        self.prf
            .set_sf_hash(sf_hash)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // Second flush: server_finished completes.
        while self.prf.wants_flush() {
            self.prf
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        tracing::debug!("decoding server finished verify data...");

        let cf_record = tls_transcript.client_finished();
        self.cf_vd_check.assign(
            &mut self.vm,
            &cf_record.explicit_nonce,
            &cf_record.ciphertext,
        )?;

        let sf_record = tls_transcript.server_finished();
        self.sf_vd_check.assign(
            &mut self.vm,
            &sf_record.explicit_nonce,
            &sf_record.ciphertext,
        )?;

        tracing::info!("Proxy-TLS done");
        let output = TlsOutput {
            keys: ProxyKeys::V1_2(refs.keys),
            tls_transcript,
        };

        Ok((
            self.ctx,
            self.vm,
            output,
            Some(self.cf_vd_check),
            Some(self.sf_vd_check),
        ))
    }

    /// TLS 1.3 finalize flow (parent spec §7/§8): the verifier mirrors the
    /// prover but leaves `hs` blind and *learns* `c_hs`/`s_hs` from the public
    /// decode. There are no Finished records to check, so both verify-data
    /// checks are `None`.
    async fn finalize_v1_3(
        mut self,
        sent: &[u8],
        recv: &[u8],
        conn_time: u64,
        h2: [u8; 32],
    ) -> Result<FinalizeOutput, TlsnError> {
        let mut refs = self.refs.expect("key refs should be available");

        // The blind handshake secret is committed but never assigned by the
        // verifier (the prover provides it privately).
        tracing::debug!("driving TLS 1.3 key schedule (phase 1)...");
        self.vm
            .commit(refs.hs)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // Phase 1: `h2` unblocks the disclosed `c_hs`/`s_hs`.
        self.ks13
            .set_sh_hash(h2)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        while self.ks13.wants_flush() {
            self.ks13
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        let c_hs = refs
            .c_hs
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive c_hs from decoding"))?;
        let s_hs = refs
            .s_hs
            .try_recv()
            .map_err(|e| TlsnError::internal().with_source(e))?
            .ok_or(TlsnError::internal().with_msg("unable to receive s_hs from decoding"))?;

        // Metadata channel (metadata-channel spec §2/§3), finalize-time mux
        // seam: receive the prover's per-record `(inner_type, content_len)`
        // framing over the shared proxy IO channel. The verifier cannot decrypt
        // the app-epoch records (its application keys are blind in ZK), so it
        // frames `Record.typ`/`content_len` from this metadata. It is a hint —
        // the `type || padding` suffix proof later validates it (spec §5), so a
        // mis-declared type/boundary fails the consistency proof at `verify`.
        let metadata: Tls13Metadata = self.ctx.io_mut().expect_next().await.map_err(|e| {
            TlsnError::internal()
                .with_msg("verifier could not receive tls 1.3 record metadata")
                .with_source(e)
        })?;

        // Build the transcript, decrypting the handshake flight with the
        // learned secrets. This also computes `h3`. The app-epoch records are
        // framed from the prover-declared metadata (the verifier has no
        // application keys).
        let tls_transcript = TlsTranscript::builder()
            .time(conn_time)
            .tls_sent(sent)
            .tls_recv(recv)
            .handshake_secrets(c_hs, s_hs)
            .tls13_record_meta(metadata)
            .build()
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("verifier could not build tls 1.3 transcript")
                    .with_source(e)
            })?;
        tracing::debug!("successfully parsed tls 1.3 transcript");

        let h3 = tls_transcript
            .tls13_sf_hash()
            .ok_or(TlsnError::internal().with_msg("tls 1.3 sf hash should be available"))?;

        tracing::debug!("driving TLS 1.3 key schedule (phase 2)...");
        self.ks13
            .set_sf_hash(h3)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        while self.ks13.wants_flush() {
            self.ks13
                .flush(&mut self.vm)
                .map_err(|e| TlsnError::internal().with_source(e))?;
            self.vm
                .execute_all(&mut self.ctx)
                .await
                .map_err(|e| TlsnError::internal().with_source(e))?;
        }

        tracing::info!("Proxy-TLS 1.3 done");
        let output = TlsOutput {
            keys: ProxyKeys::V1_3 {
                client_write_key: refs.keys13.client_write_key,
                client_write_iv: refs.keys13.client_iv,
                server_write_key: refs.keys13.server_write_key,
                server_write_iv: refs.keys13.server_iv,
                server_write_mac_key: refs.server_write_mac_key13,
            },
            tls_transcript,
        };

        Ok((self.ctx, self.vm, output, None, None))
    }
}
