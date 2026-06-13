use crate::{
    Error as TlsnError, TlsOutput,
    deps::ProverZk,
    prover::client::proxy::keylog::CapturedSecrets,
    proxy::{MsVisibility, ProxyKeys, References, TlsBytes, VerifyDataCheck, alloc_proxy_refs},
};
use hmac_sha256::{KeySchedule13, MSMode, NetworkMode, Prf, PrfConfig};
use mpz_common::Context;
use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
use tlsn_core::transcript::{TlsTranscript, peek_tls_version_and_sh_hash};

#[derive(Debug)]
pub(crate) struct ProxyProver {
    ctx: Context,
    vm: ProverZk,
    prf: Prf,
    /// TLS 1.3 ZK key schedule, allocated alongside `prf` (dual-graph
    /// allocation, parent spec §8); only one is driven at finalization.
    ks13: KeySchedule13,
    refs: Option<References>,
    cf_vd_check: VerifyDataCheck,
    sf_vd_check: VerifyDataCheck,
}

impl ProxyProver {
    pub(crate) fn new(vm: ProverZk, ctx: Context) -> Self {
        let prf_config = PrfConfig::new(NetworkMode::Normal, MSMode::Direct);
        let prf = Prf::new(prf_config);

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
            MsVisibility::Private,
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
        secrets: CapturedSecrets,
        time: u64,
        traffic: TlsBytes,
    ) -> Result<(Context, ProverZk, TlsOutput), TlsnError> {
        match secrets {
            CapturedSecrets::V1_2 { ms } => self.finalize_v1_2(ms, time, traffic).await,
            CapturedSecrets::V1_3 {
                handshake_secret,
                client_hs_traffic_secret,
                server_hs_traffic_secret,
            } => {
                self.finalize_v1_3(
                    handshake_secret,
                    client_hs_traffic_secret,
                    server_hs_traffic_secret,
                    time,
                    traffic,
                )
                .await
            }
        }
    }

    /// TLS 1.2 finalize flow (PRF key derivation + cf/sf verify-data).
    /// Byte-for- byte the original proxy-mode flow.
    async fn finalize_v1_2(
        mut self,
        ms: [u8; 48],
        time: u64,
        traffic: TlsBytes,
    ) -> Result<(Context, ProverZk, TlsOutput), TlsnError> {
        let tls_transcript = TlsTranscript::builder()
            .time(time)
            .tls_sent(&traffic.tls_sent)
            .tls_recv(&traffic.tls_recv)
            .app_sent(&traffic.app_sent)
            .app_recv(&traffic.app_recv)
            .build()
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("prover could not build tls transcript")
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
            .assign(refs.ms, ms)
            .map_err(|e| TlsnError::internal().with_source(e))?;
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

        tracing::info!("Proxy TLS done");
        let output = TlsOutput {
            keys: ProxyKeys::V1_2(refs.keys),
            tls_transcript,
        };

        Ok((self.ctx, self.vm, output))
    }

    /// TLS 1.3 finalize flow (parent spec §6/§8).
    ///
    /// The order is inverted relative to 1.2: the ZK key schedule must run
    /// **before** the transcript can be built, because decrypting the handshake
    /// flight needs the disclosed `c_hs`/`s_hs`, which the schedule produces
    /// from `h2`. Then the built transcript's `h3` feeds the schedule's second
    /// phase to derive the application keys.
    async fn finalize_v1_3(
        mut self,
        handshake_secret: [u8; 32],
        client_hs_traffic_secret: [u8; 32],
        server_hs_traffic_secret: [u8; 32],
        time: u64,
        traffic: TlsBytes,
    ) -> Result<(Context, ProverZk, TlsOutput), TlsnError> {
        // 1. Pre-parse `h2 = H(CH..SH)` from the plaintext wire records.
        let (_version, h2) = peek_tls_version_and_sh_hash(&traffic.tls_sent, &traffic.tls_recv)
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("prover could not peek tls 1.3 sh hash")
                    .with_source(e)
            })?;

        let mut refs = self.refs.expect("key refs should be available");

        // 2. Assign the (private) handshake secret to the ZK key schedule.
        tracing::debug!("driving TLS 1.3 key schedule (phase 1)...");
        self.vm
            .assign(refs.hs, handshake_secret)
            .map_err(|e| TlsnError::internal().with_source(e))?;
        self.vm
            .commit(refs.hs)
            .map_err(|e| TlsnError::internal().with_source(e))?;

        // 3. Phase 1: `h2` unblocks `c_hs`/`s_hs`.
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

        // 4. Decode the disclosed handshake traffic secrets.
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

        // 5. The ZK-derived secrets must equal the captured ones; otherwise the
        // captured `handshake_secret` is inconsistent with the wire transcript.
        if c_hs != client_hs_traffic_secret || s_hs != server_hs_traffic_secret {
            return Err(TlsnError::internal().with_msg(
                "TLS 1.3 handshake traffic secrets do not match the ZK key schedule output",
            ));
        }

        // 6. Build the transcript, decrypting the handshake flight with the
        // disclosed secrets. This also computes `h2`/`h3`.
        let tls_transcript = TlsTranscript::builder()
            .time(time)
            .tls_sent(&traffic.tls_sent)
            .tls_recv(&traffic.tls_recv)
            .app_sent(&traffic.app_sent)
            .app_recv(&traffic.app_recv)
            .handshake_secrets(c_hs, s_hs)
            .build()
            .map_err(|e| {
                TlsnError::internal()
                    .with_msg("prover could not build tls 1.3 transcript")
                    .with_source(e)
            })?;
        tracing::debug!("successfully parsed tls 1.3 transcript");

        // 7. `h3 = H(CH..server Finished)` feeds the schedule's second phase.
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

        tracing::info!("Proxy TLS 1.3 done");
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

        Ok((self.ctx, self.vm, output))
    }
}
