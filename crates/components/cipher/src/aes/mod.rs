//! The AES-128 block cipher.

use crate::{Cipher, CtrBlock, Keystream};
use async_trait::async_trait;
use mpz_circuits::{AES128_KS, AES128_POST_KS, circuits::xor};
use mpz_memory_core::{
    Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, Vm, prelude::*};
use std::{fmt::Debug, sync::Arc};

mod error;

pub use error::AesError;
use error::ErrorKind;

/// AES key schedule: 11 round keys, 16 bytes each.
type KeySchedule = Array<U8, 176>;

/// Computes AES-128.
#[derive(Default, Debug)]
pub struct Aes128 {
    key: Option<Array<U8, 16>>,
    key_schedule: Option<KeySchedule>,
    iv: Option<Array<U8, 4>>,
    iv13: Option<Array<U8, 12>>,
}

impl Aes128 {
    // Allocates key schedule.
    //
    // Expects the key to be already set.
    fn alloc_key_schedule(&self, vm: &mut dyn Vm<Binary>) -> Result<KeySchedule, AesError> {
        let ks: KeySchedule = vm
            .call(
                Call::builder(AES128_KS.clone())
                    .arg(self.key.expect("key is set"))
                    .build()
                    .expect("call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(ks)
    }

    /// Sets the 12-byte TLS 1.3 write IV.
    ///
    /// This is the secret per-direction IV produced by the TLS 1.3 key
    /// schedule (RFC 8446 §7.3,
    /// `hmac_sha256::SessionKeys13.{client,server}_iv`). It is XORed with
    /// the public per-record sequence-number pad to form the AEAD nonce;
    /// see [`Aes128::alloc_ctr_block_tls13`].
    pub fn set_iv_tls13(&mut self, iv: Array<U8, 12>) {
        self.iv13 = Some(iv);
    }

    /// Allocates a single TLS 1.3 CTR-mode block.
    ///
    /// The 16-byte AES input is `(iv13 XOR seq_pad) || counter`, where:
    ///
    /// * `iv13` is the secret 12-byte write IV set via
    ///   [`Aes128::set_iv_tls13`],
    /// * `seq_pad` is the public 12-byte sequence-number pad `0x00_00_00_00 ||
    ///   seq.to_be_bytes()` (RFC 8446 §5.3), and
    /// * `counter` is the public 4-byte big-endian block counter.
    ///
    /// The returned [`CtrBlock`] stores the public `seq_pad` reference in its
    /// `explicit_nonce` slot and the `counter` reference in `counter`; both are
    /// assigned later via the [`CtrBlock`]/[`Keystream`] assignment helpers
    /// (e.g. `Keystream::assign(vm, seq_pad, ctr)`). The XORed nonce is an
    /// internal VM node and is not exposed.
    #[allow(clippy::type_complexity)]
    pub fn alloc_ctr_block_tls13(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<CtrBlock<Array<U8, 12>, Array<U8, 4>, Array<U8, 16>>, AesError> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv13 = self
            .iv13
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "tls 1.3 iv not set"))?;

        let seq_pad: Array<U8, 12> = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.mark_public(seq_pad)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let counter: Array<U8, 4> = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.mark_public(counter)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        if self.key_schedule.is_none() {
            self.key_schedule = Some(self.alloc_key_schedule(vm)?);
        }
        let ks = *self.key_schedule.as_ref().expect("key schedule was set");

        let output = Self::ctr_block_tls13(vm, ks, iv13, seq_pad, counter)?;

        Ok(CtrBlock {
            explicit_nonce: seq_pad,
            counter,
            output,
        })
    }

    /// Allocates a TLS 1.3 keystream of `len` bytes.
    ///
    /// Each block uses the same nonce construction as
    /// [`Aes128::alloc_ctr_block_tls13`]: a single per-record `seq_pad` shared
    /// across the whole record (XORed with the secret `iv13`), while the
    /// counter increments per block. Assign with
    /// `Keystream::assign(vm, seq_pad, ctr)`, where `ctr` typically starts at
    /// `AES_GCM_START_COUNTER = 2`.
    #[allow(clippy::type_complexity)]
    pub fn alloc_keystream_tls13(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
    ) -> Result<Keystream<Array<U8, 12>, Array<U8, 4>, Array<U8, 16>>, AesError> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv13 = self
            .iv13
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "tls 1.3 iv not set"))?;

        let block_count = len.div_ceil(16);

        let inputs = (0..block_count)
            .map(|_| {
                let seq_pad: Array<U8, 12> = vm
                    .alloc()
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
                let counter: Array<U8, 4> = vm
                    .alloc()
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                vm.mark_public(seq_pad)
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
                vm.mark_public(counter)
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                Ok((seq_pad, counter))
            })
            .collect::<Result<Vec<_>, AesError>>()?;

        let blocks = inputs
            .into_iter()
            .map(|(seq_pad, counter)| {
                if self.key_schedule.is_none() {
                    self.key_schedule = Some(self.alloc_key_schedule(vm)?);
                }
                let ks = *self.key_schedule.as_ref().expect("key schedule was set");

                let output = Self::ctr_block_tls13(vm, ks, iv13, seq_pad, counter)?;

                Ok(CtrBlock {
                    explicit_nonce: seq_pad,
                    counter,
                    output,
                })
            })
            .collect::<Result<Vec<_>, AesError>>()?;

        Ok(Keystream::new(&blocks))
    }

    // Computes one TLS 1.3 CTR-mode block output.
    //
    // Derives the 12-byte AEAD nonce `nonce12 = iv13 XOR seq_pad` via a
    // VM-level XOR (free against the public `seq_pad` operand), then feeds
    // `nonce12[0..4]`, `nonce12[4..12]` and `counter` into the existing
    // `AES128_POST_KS` circuit. That circuit concatenates its three trailing
    // args into the 16-byte AES message input, reproducing `nonce12 || counter`
    // without authoring a new circuit. `Call` matches args by bit-length, so
    // feeding `Vector<U8>` slices into the slots the 1.2 path fills with
    // `Array<U8, 4>` / `Array<U8, 8>` is sound.
    fn ctr_block_tls13(
        vm: &mut dyn Vm<Binary>,
        ks: KeySchedule,
        iv13: Array<U8, 12>,
        seq_pad: Array<U8, 12>,
        counter: Array<U8, 4>,
    ) -> Result<Array<U8, 16>, AesError> {
        let nonce12: Vector<U8> = vm
            .call(
                Call::builder(Arc::new(xor(96)))
                    .arg(iv13)
                    .arg(seq_pad)
                    .build()
                    .expect("xor call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let nonce_iv = nonce12.get(0..4).expect("nonce slice 0..4 is in bounds");
        let nonce_rest = nonce12.get(4..12).expect("nonce slice 4..12 is in bounds");

        let output = vm
            .call(
                Call::builder(AES128_POST_KS.clone())
                    .arg(ks)
                    .arg(nonce_iv)
                    .arg(nonce_rest)
                    .arg(counter)
                    .build()
                    .expect("call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(output)
    }
}

#[async_trait]
impl Cipher for Aes128 {
    type Error = AesError;
    type Key = Array<U8, 16>;
    type Iv = Array<U8, 4>;
    type Nonce = Array<U8, 8>;
    type Counter = Array<U8, 4>;
    type Block = Array<U8, 16>;

    fn set_key(&mut self, key: Array<U8, 16>) {
        self.key = Some(key);
    }

    fn set_iv(&mut self, iv: Array<U8, 4>) {
        self.iv = Some(iv);
    }

    fn key(&self) -> Option<&Array<U8, 16>> {
        self.key.as_ref()
    }

    fn iv(&self) -> Option<&Array<U8, 4>> {
        self.iv.as_ref()
    }

    fn alloc_block(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        input: Array<U8, 16>,
    ) -> Result<Self::Block, Self::Error> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;

        if self.key_schedule.is_none() {
            self.key_schedule = Some(self.alloc_key_schedule(vm)?);
        }
        let ks = *self.key_schedule.as_ref().expect("key schedule was set");

        let output = vm
            .call(
                Call::builder(AES128_POST_KS.clone())
                    .arg(ks)
                    .arg(input)
                    .build()
                    .expect("call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(output)
    }

    fn alloc_ctr_block(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv = self
            .iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;

        let explicit_nonce: Array<U8, 8> = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.mark_public(explicit_nonce)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let counter: Array<U8, 4> = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.mark_public(counter)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        if self.key_schedule.is_none() {
            self.key_schedule = Some(self.alloc_key_schedule(vm)?);
        }
        let ks = *self.key_schedule.as_ref().expect("key schedule was set");

        let output = vm
            .call(
                Call::builder(AES128_POST_KS.clone())
                    .arg(ks)
                    .arg(iv)
                    .arg(explicit_nonce)
                    .arg(counter)
                    .build()
                    .expect("call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(CtrBlock {
            explicit_nonce,
            counter,
            output,
        })
    }

    fn alloc_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
    ) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv = self
            .iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;

        let block_count = len.div_ceil(16);

        let inputs = (0..block_count)
            .map(|_| {
                let explicit_nonce: Array<U8, 8> = vm
                    .alloc()
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
                let counter: Array<U8, 4> = vm
                    .alloc()
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                vm.mark_public(explicit_nonce)
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
                vm.mark_public(counter)
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                Ok((explicit_nonce, counter))
            })
            .collect::<Result<Vec<_>, AesError>>()?;

        let blocks = inputs
            .into_iter()
            .map(|(explicit_nonce, counter)| {
                if self.key_schedule.is_none() {
                    self.key_schedule = Some(self.alloc_key_schedule(vm)?);
                }
                let ks = *self.key_schedule.as_ref().expect("key schedule was set");

                let output = vm
                    .call(
                        Call::builder(AES128_POST_KS.clone())
                            .arg(ks)
                            .arg(iv)
                            .arg(explicit_nonce)
                            .arg(counter)
                            .build()
                            .expect("call should be valid"),
                    )
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                Ok(CtrBlock {
                    explicit_nonce,
                    counter,
                    output,
                })
            })
            .collect::<Result<Vec<_>, AesError>>()?;

        Ok(Keystream::new(&blocks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cipher;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_memory_core::{
        Array, MemoryExt, Vector, ViewExt,
        binary::{Binary, U8},
    };
    use mpz_vm_core::{Execute, Vm};

    #[tokio::test]
    async fn test_aes_ctr() {
        let key = [42_u8; 16];
        let iv = [3_u8; 4];
        let nonce = [5_u8; 8];
        let start_counter = 3u32;

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut gen_vm = IdealVm::new();
        let mut ev = IdealVm::new();

        let mut aes_gen = setup_ctr(key, iv, &mut gen_vm);
        let mut aes_ev = setup_ctr(key, iv, &mut ev);

        let msg = vec![42u8; 128];

        let keystream_gen = aes_gen.alloc_keystream(&mut gen_vm, msg.len()).unwrap();
        let keystream_ev = aes_ev.alloc_keystream(&mut ev, msg.len()).unwrap();

        let msg_ref_gen: Vector<U8> = gen_vm.alloc_vec(msg.len()).unwrap();
        gen_vm.mark_public(msg_ref_gen).unwrap();
        gen_vm.assign(msg_ref_gen, msg.clone()).unwrap();
        gen_vm.commit(msg_ref_gen).unwrap();

        let msg_ref_ev: Vector<U8> = ev.alloc_vec(msg.len()).unwrap();
        ev.mark_public(msg_ref_ev).unwrap();
        ev.assign(msg_ref_ev, msg.clone()).unwrap();
        ev.commit(msg_ref_ev).unwrap();

        let mut ctr = start_counter..;
        keystream_gen
            .assign(&mut gen_vm, nonce, move || {
                ctr.next().unwrap().to_be_bytes()
            })
            .unwrap();
        let mut ctr = start_counter..;
        keystream_ev
            .assign(&mut ev, nonce, move || ctr.next().unwrap().to_be_bytes())
            .unwrap();

        let cipher_out_gen = keystream_gen.apply(&mut gen_vm, msg_ref_gen).unwrap();
        let cipher_out_ev = keystream_ev.apply(&mut ev, msg_ref_ev).unwrap();

        let (ct_gen, ct_ev) = tokio::try_join!(
            async {
                let out = gen_vm.decode(cipher_out_gen).unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                gen_vm.execute(&mut ctx_a).await.unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(cipher_out_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(ct_gen, ct_ev);

        let expected = aes_apply_keystream(key, iv, nonce, start_counter as usize, msg);
        assert_eq!(ct_gen, expected);
    }

    #[tokio::test]
    async fn test_aes_ecb() {
        let key = [1_u8; 16];
        let input = [5_u8; 16];

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut gen_vm = IdealVm::new();
        let mut ev = IdealVm::new();

        let mut aes_gen = setup_block(key, &mut gen_vm);
        let mut aes_ev = setup_block(key, &mut ev);

        let block_ref_gen: Array<U8, 16> = gen_vm.alloc().unwrap();
        gen_vm.mark_public(block_ref_gen).unwrap();
        gen_vm.assign(block_ref_gen, input).unwrap();
        gen_vm.commit(block_ref_gen).unwrap();

        let block_ref_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(block_ref_ev).unwrap();
        ev.assign(block_ref_ev, input).unwrap();
        ev.commit(block_ref_ev).unwrap();

        let block_gen = aes_gen.alloc_block(&mut gen_vm, block_ref_gen).unwrap();
        let block_ev = aes_ev.alloc_block(&mut ev, block_ref_ev).unwrap();

        let (ciphertext_gen, ciphetext_ev) = tokio::try_join!(
            async {
                let out = gen_vm.decode(block_gen).unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                gen_vm.execute(&mut ctx_a).await.unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(block_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(ciphertext_gen, ciphetext_ev);

        let expected = aes128(key, input);
        assert_eq!(ciphertext_gen, expected);
    }

    #[tokio::test]
    async fn test_aes_ctr_tls13() {
        let key = [42_u8; 16];
        let iv12 = [7_u8; 12];
        let seq = 5u64;
        let start_counter = 2u32;

        let seq_pad = tls13_seq_pad(seq);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut gen_vm = IdealVm::new();
        let mut ev = IdealVm::new();

        let mut aes_gen = setup_ctr_tls13(key, iv12, &mut gen_vm);
        let mut aes_ev = setup_ctr_tls13(key, iv12, &mut ev);

        let msg = vec![42u8; 128];

        let keystream_gen = aes_gen
            .alloc_keystream_tls13(&mut gen_vm, msg.len())
            .unwrap();
        let keystream_ev = aes_ev.alloc_keystream_tls13(&mut ev, msg.len()).unwrap();

        let msg_ref_gen: Vector<U8> = gen_vm.alloc_vec(msg.len()).unwrap();
        gen_vm.mark_public(msg_ref_gen).unwrap();
        gen_vm.assign(msg_ref_gen, msg.clone()).unwrap();
        gen_vm.commit(msg_ref_gen).unwrap();

        let msg_ref_ev: Vector<U8> = ev.alloc_vec(msg.len()).unwrap();
        ev.mark_public(msg_ref_ev).unwrap();
        ev.assign(msg_ref_ev, msg.clone()).unwrap();
        ev.commit(msg_ref_ev).unwrap();

        let mut ctr = start_counter..;
        keystream_gen
            .assign(&mut gen_vm, seq_pad, move || {
                ctr.next().unwrap().to_be_bytes()
            })
            .unwrap();
        let mut ctr = start_counter..;
        keystream_ev
            .assign(&mut ev, seq_pad, move || ctr.next().unwrap().to_be_bytes())
            .unwrap();

        let cipher_out_gen = keystream_gen.apply(&mut gen_vm, msg_ref_gen).unwrap();
        let cipher_out_ev = keystream_ev.apply(&mut ev, msg_ref_ev).unwrap();

        let (ct_gen, ct_ev) = tokio::try_join!(
            async {
                let out = gen_vm.decode(cipher_out_gen).unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                gen_vm.execute(&mut ctx_a).await.unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(cipher_out_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(ct_gen, ct_ev);

        let expected = aes_apply_keystream_tls13(key, iv12, seq_pad, start_counter as usize, msg);
        assert_eq!(ct_gen, expected);
    }

    #[tokio::test]
    async fn test_aes_j0_tls13() {
        let key = [9_u8; 16];
        let iv12 = [3_u8; 12];
        let seq = 7u64;

        let seq_pad = tls13_seq_pad(seq);

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut gen_vm = IdealVm::new();
        let mut ev = IdealVm::new();

        let mut aes_gen = setup_ctr_tls13(key, iv12, &mut gen_vm);
        let mut aes_ev = setup_ctr_tls13(key, iv12, &mut ev);

        let block_gen = aes_gen.alloc_ctr_block_tls13(&mut gen_vm).unwrap();
        let block_ev = aes_ev.alloc_ctr_block_tls13(&mut ev).unwrap();

        // J0 for the tag uses counter = 1.
        let counter = 1u32.to_be_bytes();

        gen_vm.assign(block_gen.explicit_nonce, seq_pad).unwrap();
        gen_vm.commit(block_gen.explicit_nonce).unwrap();
        gen_vm.assign(block_gen.counter, counter).unwrap();
        gen_vm.commit(block_gen.counter).unwrap();

        ev.assign(block_ev.explicit_nonce, seq_pad).unwrap();
        ev.commit(block_ev.explicit_nonce).unwrap();
        ev.assign(block_ev.counter, counter).unwrap();
        ev.commit(block_ev.counter).unwrap();

        let (j0_gen, j0_ev) = tokio::try_join!(
            async {
                let out = gen_vm.decode(block_gen.output).unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                gen_vm.execute(&mut ctx_a).await.unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(block_ev.output).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(j0_gen, j0_ev);

        // Software J0 = AES_K(nonce || 0x00000001), nonce = iv12 XOR seq_pad.
        let mut j0_input = [0u8; 16];
        for i in 0..12 {
            j0_input[i] = iv12[i] ^ seq_pad[i];
        }
        j0_input[12..16].copy_from_slice(&counter);
        let expected = aes128(key, j0_input);
        assert_eq!(j0_gen, expected);
    }

    /// Known-answer test against AES-128-GCM "Test Case 3" from McGrew &
    /// Viega's GCM specification (NIST proposed-modes appendix B).
    ///
    /// `K`, `IV`, `P`, `C` are published constants. GCM encrypts with the CTR
    /// keystream starting at counter 2 (`Y1 = IV || 0x00000002`), so the TLS
    /// 1.3 keystream with `start_counter = 2` and `nonce = IV` must turn `P`
    /// into `C`. We synthesize a non-trivial XOR by setting
    /// `iv13 = IV XOR seq_pad`, so the circuit recomputes `nonce = IV`.
    #[tokio::test]
    async fn test_aes_ctr_tls13_kat() {
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        let key: [u8; 16] = unhex("feffe9928665731c6d6a8f9467308308")
            .try_into()
            .unwrap();
        let gcm_iv: [u8; 12] = unhex("cafebabefacedbaddecaf888").try_into().unwrap();
        let plaintext = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let ciphertext = unhex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        );
        let start_counter = 2u32;

        // Pick an arbitrary sequence number and derive iv13 so that
        // iv13 XOR seq_pad == gcm_iv (the published GCM nonce).
        let seq = 0x0102_0304_0506_0708u64;
        let seq_pad = tls13_seq_pad(seq);
        let mut iv13 = [0u8; 12];
        for i in 0..12 {
            iv13[i] = gcm_iv[i] ^ seq_pad[i];
        }

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut gen_vm = IdealVm::new();
        let mut ev = IdealVm::new();

        let mut aes_gen = setup_ctr_tls13(key, iv13, &mut gen_vm);
        let mut aes_ev = setup_ctr_tls13(key, iv13, &mut ev);

        let keystream_gen = aes_gen
            .alloc_keystream_tls13(&mut gen_vm, plaintext.len())
            .unwrap();
        let keystream_ev = aes_ev
            .alloc_keystream_tls13(&mut ev, plaintext.len())
            .unwrap();

        let pt_ref_gen: Vector<U8> = gen_vm.alloc_vec(plaintext.len()).unwrap();
        gen_vm.mark_public(pt_ref_gen).unwrap();
        gen_vm.assign(pt_ref_gen, plaintext.clone()).unwrap();
        gen_vm.commit(pt_ref_gen).unwrap();

        let pt_ref_ev: Vector<U8> = ev.alloc_vec(plaintext.len()).unwrap();
        ev.mark_public(pt_ref_ev).unwrap();
        ev.assign(pt_ref_ev, plaintext.clone()).unwrap();
        ev.commit(pt_ref_ev).unwrap();

        let mut ctr = start_counter..;
        keystream_gen
            .assign(&mut gen_vm, seq_pad, move || {
                ctr.next().unwrap().to_be_bytes()
            })
            .unwrap();
        let mut ctr = start_counter..;
        keystream_ev
            .assign(&mut ev, seq_pad, move || ctr.next().unwrap().to_be_bytes())
            .unwrap();

        let ct_gen = keystream_gen.apply(&mut gen_vm, pt_ref_gen).unwrap();
        let ct_ev = keystream_ev.apply(&mut ev, pt_ref_ev).unwrap();

        let (out_gen, out_ev) = tokio::try_join!(
            async {
                let out = gen_vm.decode(ct_gen).unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                gen_vm.execute(&mut ctx_a).await.unwrap();
                gen_vm.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(ct_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(out_gen, out_ev);
        assert_eq!(out_gen, ciphertext);
    }

    fn setup_ctr_tls13(key: [u8; 16], iv: [u8; 12], vm: &mut dyn Vm<Binary>) -> Aes128 {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let iv_ref: Array<U8, 12> = vm.alloc().unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(iv_ref).unwrap();

        let mut aes = Aes128::default();

        aes.set_key(key_ref);
        aes.set_iv_tls13(iv_ref);

        aes
    }

    // Builds the TLS 1.3 sequence-number pad `0x00_00_00_00 || seq.to_be_bytes()`.
    fn tls13_seq_pad(seq: u64) -> [u8; 12] {
        let mut seq_pad = [0u8; 12];
        seq_pad[4..12].copy_from_slice(&seq.to_be_bytes());
        seq_pad
    }

    fn aes_apply_keystream_tls13(
        key: [u8; 16],
        iv: [u8; 12],
        seq_pad: [u8; 12],
        start_ctr: usize,
        msg: Vec<u8>,
    ) -> Vec<u8> {
        use ::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use aes::Aes128;
        use ctr::Ctr32BE;

        // TLS 1.3 AEAD nonce: write_iv XOR (0^4 || seq_be64). The 16-byte CTR
        // counter block is `nonce(12) || 0x00000000`; `try_seek` advances to
        // the requested block.
        let mut full_iv = [0u8; 16];
        for i in 0..12 {
            full_iv[i] = iv[i] ^ seq_pad[i];
        }

        let mut cipher = Ctr32BE::<Aes128>::new(&key.into(), &full_iv.into());
        let mut out = msg.clone();

        cipher
            .try_seek(start_ctr * 16)
            .expect("start counter is less than keystream length");
        cipher.apply_keystream(&mut out);

        out
    }

    fn setup_ctr(key: [u8; 16], iv: [u8; 4], vm: &mut dyn Vm<Binary>) -> Aes128 {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let iv_ref: Array<U8, 4> = vm.alloc().unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(iv_ref).unwrap();

        let mut aes = Aes128::default();

        aes.set_key(key_ref);
        aes.set_iv(iv_ref);

        aes
    }

    fn setup_block(key: [u8; 16], vm: &mut dyn Vm<Binary>) -> Aes128 {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let mut aes = Aes128::default();
        aes.set_key(key_ref);

        aes
    }

    fn aes_apply_keystream(
        key: [u8; 16],
        iv: [u8; 4],
        explicit_nonce: [u8; 8],
        start_ctr: usize,
        msg: Vec<u8>,
    ) -> Vec<u8> {
        use ::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use aes::Aes128;
        use ctr::Ctr32BE;

        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(&iv);
        full_iv[4..12].copy_from_slice(&explicit_nonce);

        let mut cipher = Ctr32BE::<Aes128>::new(&key.into(), &full_iv.into());
        let mut out = msg.clone();

        cipher
            .try_seek(start_ctr * 16)
            .expect("start counter is less than keystream length");
        cipher.apply_keystream(&mut out);

        out
    }

    fn aes128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
        use ::aes::Aes128 as TestAes128;
        use ::cipher::{BlockEncrypt, KeyInit};

        let mut msg = msg.into();
        let cipher = TestAes128::new(&key.into());
        cipher.encrypt_block(&mut msg);
        msg.into()
    }
}
