//! Provides [`KeySchedule13`], for computing the TLS 1.3 key schedule.

use crate::{
    PrfError,
    hmac::{IPAD, OPAD, hmac_sha256},
    prf::{compute_partial, merge_outputs},
};
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    Vm,
    memory::{
        Array, MemoryExt, Vector, ViewExt,
        binary::{Binary, U8},
    },
};
use tracing::instrument;

/// SHA-256 of the empty string, used as the context of the "derived" label
/// (RFC 8446 §7.1).
const EMPTY_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Prefix of every HkdfLabel label field (RFC 8446 §7.1).
const LABEL_PREFIX: &[u8] = b"tls13 ";

const C_HS_LABEL: &[u8] = b"c hs traffic";
const S_HS_LABEL: &[u8] = b"s hs traffic";
const DERIVED_LABEL: &[u8] = b"derived";
const C_AP_LABEL: &[u8] = b"c ap traffic";
const S_AP_LABEL: &[u8] = b"s ap traffic";
const KEY_LABEL: &[u8] = b"key";
const IV_LABEL: &[u8] = b"iv";

/// TLS 1.3 key schedule (RFC 8446 §7.1), SHA-256-based suites.
///
/// Evaluates the key schedule inside the VM, from a caller-supplied
/// `handshake_secret` reference down to the application-traffic AES-128-GCM
/// key/IV references. The handshake traffic secrets are exposed as references
/// so the caller can decode them (publicly, in proxy mode — that decode is the
/// disclosure mechanism).
#[derive(Debug)]
pub struct KeySchedule13 {
    state: State,
}

impl Default for KeySchedule13 {
    fn default() -> Self {
        Self::new()
    }
}

/// Output references of the TLS 1.3 key schedule.
#[derive(Debug, Clone, Copy)]
pub struct ScheduleOutput13 {
    /// Application traffic keys.
    pub keys: SessionKeys13,
    /// Client handshake traffic secret (intended for public decode by the
    /// caller — this is the disclosure mechanism in proxy mode).
    pub c_hs: Array<U8, 32>,
    /// Server handshake traffic secret (ditto).
    pub s_hs: Array<U8, 32>,
}

/// TLS 1.3 application-epoch session keys (note 12-byte IVs, unlike the
/// 4-byte IVs of the TLS 1.2 [`SessionKeys`](crate::SessionKeys)).
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys13 {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Client IV.
    pub client_iv: Array<U8, 12>,
    /// Server IV.
    pub server_iv: Array<U8, 12>,
}

#[derive(Debug)]
enum State {
    Initialized,
    Setup { nodes: Box<Nodes> },
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

/// The HMAC nodes of the derivation graph.
///
/// Every node is a single un-iterated HMAC-SHA256:
///
/// - `HKDF-Extract(salt, ikm) = HMAC(key = salt, msg = ikm)`.
/// - `HKDF-Expand-Label(secret, label, ctx, L)` with `L <= 32` is `HMAC(key =
///   secret, msg = HkdfLabel || 0x01)`, truncated to `L`.
#[derive(Debug)]
struct Nodes {
    /// c_hs = Expand-Label(HS, "c hs traffic", h2, 32). Message set by
    /// [`KeySchedule13::set_sh_hash`].
    c_hs: HmacNode,
    /// s_hs = Expand-Label(HS, "s hs traffic", h2, 32). Message set by
    /// [`KeySchedule13::set_sh_hash`].
    s_hs: HmacNode,
    /// derived = Expand-Label(HS, "derived", H(""), 32). Constant message.
    derived: HmacNode,
    /// MS = Extract(salt = derived, ikm = 0^32). Constant message.
    master: HmacNode,
    /// c_ap = Expand-Label(MS, "c ap traffic", h3, 32). Message set by
    /// [`KeySchedule13::set_sf_hash`].
    c_ap: HmacNode,
    /// s_ap = Expand-Label(MS, "s ap traffic", h3, 32). Message set by
    /// [`KeySchedule13::set_sf_hash`].
    s_ap: HmacNode,
    /// client_write_key = Expand-Label(c_ap, "key", "", 16). Constant message.
    cwk: HmacNode,
    /// client_write_iv = Expand-Label(c_ap, "iv", "", 12). Constant message.
    civ: HmacNode,
    /// server_write_key = Expand-Label(s_ap, "key", "", 16). Constant message.
    swk: HmacNode,
    /// server_write_iv = Expand-Label(s_ap, "iv", "", 12). Constant message.
    siv: HmacNode,
}

impl Nodes {
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut HmacNode> {
        [
            &mut self.c_hs,
            &mut self.s_hs,
            &mut self.derived,
            &mut self.master,
            &mut self.c_ap,
            &mut self.s_ap,
            &mut self.cwk,
            &mut self.civ,
            &mut self.swk,
            &mut self.siv,
        ]
        .into_iter()
    }

    fn wants_flush(&self) -> bool {
        [
            &self.c_hs,
            &self.s_hs,
            &self.derived,
            &self.master,
            &self.c_ap,
            &self.s_ap,
            &self.cwk,
            &self.civ,
            &self.swk,
            &self.siv,
        ]
        .into_iter()
        .any(|node| node.wants_flush())
    }

    fn is_done(&self) -> bool {
        [
            &self.c_hs,
            &self.s_hs,
            &self.derived,
            &self.master,
            &self.c_ap,
            &self.s_ap,
            &self.cwk,
            &self.civ,
            &self.swk,
            &self.siv,
        ]
        .into_iter()
        .all(|node| node.is_done())
    }
}

impl KeySchedule13 {
    /// Creates a new instance of the key schedule.
    pub fn new() -> Self {
        Self {
            state: State::Initialized,
        }
    }

    /// Allocates the full derivation graph.
    ///
    /// `hs` is the TLS 1.3 handshake_secret. The caller controls its
    /// visibility (private for the prover / blind for the verifier) before
    /// calling, exactly like [`Prf::alloc_ms`](crate::Prf::alloc_ms).
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `hs` - The handshake secret.
    #[instrument(level = "debug", skip_all, err)]
    pub fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        hs: Array<U8, 32>,
    ) -> Result<ScheduleOutput13, PrfError> {
        let State::Initialized = self.state.take() else {
            return Err(PrfError::state("key schedule not in initialized state"));
        };

        let (outer_hs, inner_hs) = key_states(vm, hs)?;

        let traffic_msg_len = expand_label_msg_len(C_HS_LABEL, 32);
        let c_hs = HmacNode::alloc(vm, outer_hs.clone(), inner_hs.clone(), traffic_msg_len)?;
        let s_hs = HmacNode::alloc(vm, outer_hs.clone(), inner_hs.clone(), traffic_msg_len)?;

        let mut derived = HmacNode::alloc(
            vm,
            outer_hs,
            inner_hs,
            expand_label_msg_len(DERIVED_LABEL, 32),
        )?;
        derived.set_msg(expand_label_msg(32, DERIVED_LABEL, &EMPTY_HASH));

        // MS = HKDF-Extract(salt = derived, ikm = 0^32) = HMAC(derived, 0^32).
        let (outer_derived, inner_derived) = key_states(vm, derived.output)?;
        let mut master = HmacNode::alloc(vm, outer_derived, inner_derived, 32)?;
        master.set_msg(vec![0_u8; 32]);

        let (outer_ms, inner_ms) = key_states(vm, master.output)?;
        let c_ap = HmacNode::alloc(vm, outer_ms.clone(), inner_ms.clone(), traffic_msg_len)?;
        let s_ap = HmacNode::alloc(vm, outer_ms, inner_ms, traffic_msg_len)?;

        let (outer_c_ap, inner_c_ap) = key_states(vm, c_ap.output)?;
        let mut cwk = HmacNode::alloc(
            vm,
            outer_c_ap.clone(),
            inner_c_ap.clone(),
            expand_label_msg_len(KEY_LABEL, 0),
        )?;
        cwk.set_msg(expand_label_msg(16, KEY_LABEL, &[]));
        let mut civ = HmacNode::alloc(
            vm,
            outer_c_ap,
            inner_c_ap,
            expand_label_msg_len(IV_LABEL, 0),
        )?;
        civ.set_msg(expand_label_msg(12, IV_LABEL, &[]));

        let (outer_s_ap, inner_s_ap) = key_states(vm, s_ap.output)?;
        let mut swk = HmacNode::alloc(
            vm,
            outer_s_ap.clone(),
            inner_s_ap.clone(),
            expand_label_msg_len(KEY_LABEL, 0),
        )?;
        swk.set_msg(expand_label_msg(16, KEY_LABEL, &[]));
        let mut siv = HmacNode::alloc(
            vm,
            outer_s_ap,
            inner_s_ap,
            expand_label_msg_len(IV_LABEL, 0),
        )?;
        siv.set_msg(expand_label_msg(12, IV_LABEL, &[]));

        let keys = SessionKeys13 {
            client_write_key: truncate::<16>(vm, cwk.output)?,
            server_write_key: truncate::<16>(vm, swk.output)?,
            client_iv: truncate::<12>(vm, civ.output)?,
            server_iv: truncate::<12>(vm, siv.output)?,
        };

        let output = ScheduleOutput13 {
            keys,
            c_hs: c_hs.output,
            s_hs: s_hs.output,
        };

        self.state = State::Setup {
            nodes: Box::new(Nodes {
                c_hs,
                s_hs,
                derived,
                master,
                c_ap,
                s_ap,
                cwk,
                civ,
                swk,
                siv,
            }),
        };

        Ok(output)
    }

    /// Sets h2 = SHA-256(ClientHello..ServerHello).
    ///
    /// Unblocks the c_hs / s_hs expansions.
    ///
    /// # Arguments
    ///
    /// * `hash` - The handshake transcript hash up to and including
    ///   ServerHello.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_sh_hash(&mut self, hash: [u8; 32]) -> Result<(), PrfError> {
        let State::Setup { nodes } = &mut self.state else {
            return Err(PrfError::state("key schedule not set up"));
        };

        nodes.c_hs.set_msg(expand_label_msg(32, C_HS_LABEL, &hash));
        nodes.s_hs.set_msg(expand_label_msg(32, S_HS_LABEL, &hash));

        Ok(())
    }

    /// Sets h3 = SHA-256(ClientHello..server Finished).
    ///
    /// Unblocks the application traffic secrets and keys.
    ///
    /// # Arguments
    ///
    /// * `hash` - The handshake transcript hash up to and including the server
    ///   Finished message.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_sf_hash(&mut self, hash: [u8; 32]) -> Result<(), PrfError> {
        let State::Setup { nodes } = &mut self.state else {
            return Err(PrfError::state("key schedule not set up"));
        };

        nodes.c_ap.set_msg(expand_label_msg(32, C_AP_LABEL, &hash));
        nodes.s_ap.set_msg(expand_label_msg(32, S_AP_LABEL, &hash));

        Ok(())
    }

    /// Returns if the key schedule needs to be flushed.
    pub fn wants_flush(&self) -> bool {
        match &self.state {
            State::Setup { nodes } => nodes.wants_flush(),
            _ => false,
        }
    }

    /// Flushes the key schedule.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    #[instrument(level = "debug", skip_all, err)]
    pub fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        self.state = match self.state.take() {
            State::Setup { mut nodes } => {
                for node in nodes.iter_mut() {
                    node.flush(vm)?;
                }

                if nodes.is_done() {
                    State::Complete
                } else {
                    State::Setup { nodes }
                }
            }
            other => other,
        };

        Ok(())
    }
}

/// A single HMAC-SHA256 node with a public message of fixed length, assigned
/// lazily on flush.
#[derive(Debug)]
struct HmacNode {
    msg: Vector<U8>,
    msg_value: Option<Vec<u8>>,
    assigned: bool,
    output: Array<U8, 32>,
}

impl HmacNode {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
        msg_len: usize,
    ) -> Result<Self, PrfError> {
        let msg: Vector<U8> = vm.alloc_vec(msg_len).map_err(PrfError::vm)?;
        vm.mark_public(msg).map_err(PrfError::vm)?;

        let mut inner_local = inner_partial;
        inner_local.update(&msg);
        inner_local.compress(vm)?;
        let inner_local = inner_local.finalize(vm)?;

        let output = hmac_sha256(vm, outer_partial, inner_local)?;

        Ok(Self {
            msg,
            msg_value: None,
            assigned: false,
            output,
        })
    }

    fn set_msg(&mut self, value: Vec<u8>) {
        debug_assert_eq!(value.len(), self.msg.len(), "message length mismatch");
        self.msg_value = Some(value);
    }

    fn wants_flush(&self) -> bool {
        !self.assigned && self.msg_value.is_some()
    }

    fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        if self.wants_flush() {
            let value = self
                .msg_value
                .take()
                .expect("message value should be present");

            vm.assign(self.msg, value).map_err(PrfError::vm)?;
            vm.commit(self.msg).map_err(PrfError::vm)?;

            self.assigned = true;
        }
        Ok(())
    }

    fn is_done(&self) -> bool {
        self.assigned
    }
}

/// Computes the OPAD/IPAD padded-key [`Sha256`] states for an HMAC keyed by a
/// 32-byte VM reference.
fn key_states(vm: &mut dyn Vm<Binary>, key: Array<U8, 32>) -> Result<(Sha256, Sha256), PrfError> {
    let key: Vector<U8> = key.into();

    let outer_partial = compute_partial(vm, key, OPAD)?;
    let inner_partial = compute_partial(vm, key, IPAD)?;

    Ok((outer_partial, inner_partial))
}

/// Truncates a 32-byte HMAC output to its first `N` bytes.
fn truncate<const N: usize>(
    vm: &mut dyn Vm<Binary>,
    output: Array<U8, 32>,
) -> Result<Array<U8, N>, PrfError> {
    let out = merge_outputs(vm, vec![output], N)?;
    Ok(Array::<U8, N>::try_from(out).expect("output is N bytes"))
}

/// Returns the HMAC message of `HKDF-Expand-Label(., label, ctx, output_len)`,
/// i.e. `HkdfLabel || 0x01` (RFC 8446 §7.1, RFC 5869 §2.3 with `T(1)` only).
fn expand_label_msg(output_len: u16, label: &[u8], ctx: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(expand_label_msg_len(label, ctx.len()));
    msg.extend_from_slice(&output_len.to_be_bytes());
    msg.push((LABEL_PREFIX.len() + label.len()) as u8);
    msg.extend_from_slice(LABEL_PREFIX);
    msg.extend_from_slice(label);
    msg.push(ctx.len() as u8);
    msg.extend_from_slice(ctx);
    msg.push(0x01);
    msg
}

/// Returns the length of [`expand_label_msg`] for the given label and context
/// length.
fn expand_label_msg_len(label: &[u8], ctx_len: usize) -> usize {
    2 + 1 + LABEL_PREFIX.len() + label.len() + 1 + ctx_len + 1
}

#[cfg(test)]
mod tests {
    use super::{KeySchedule13, ScheduleOutput13, SessionKeys13, State};
    use crate::test_utils::tls13::key_schedule13 as reference_schedule;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::{
        Execute,
        memory::{Array, MemoryExt, ViewExt, binary::U8},
    };
    use rand::{Rng, SeedableRng, rngs::StdRng};

    // Test vectors from RFC 8448 §3, "Simple 1-RTT Handshake".

    /// `{server} extract secret "handshake"` → secret.
    const RFC8448_HS: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    /// `{server} derive secret "tls13 c hs traffic"` → hash (h2).
    const RFC8448_H2: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
    /// `{server} derive secret "tls13 c ap traffic"` → hash (h3).
    const RFC8448_H3: &str = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
    /// `{server} derive secret "tls13 c hs traffic"` → expanded.
    const RFC8448_C_HS: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    /// `{server} derive secret "tls13 s hs traffic"` → expanded.
    const RFC8448_S_HS: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    /// `{server} derive secret for master "tls13 derived"` → expanded.
    const RFC8448_DERIVED: &str =
        "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4";
    /// `{server} extract secret "master"` → secret.
    const RFC8448_MASTER: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    /// `{server} derive secret "tls13 c ap traffic"` → expanded.
    const RFC8448_C_AP: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    /// `{server} derive secret "tls13 s ap traffic"` → expanded.
    const RFC8448_S_AP: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    /// `{client} derive write traffic keys for application data` → key.
    const RFC8448_CLIENT_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
    /// `{client} derive write traffic keys for application data` → iv.
    const RFC8448_CLIENT_IV: &str = "5b78923dee08579033e523d9";
    /// `{server} derive write traffic keys for application data` → key.
    const RFC8448_SERVER_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
    /// `{server} derive write traffic keys for application data` → iv.
    const RFC8448_SERVER_IV: &str = "cf782b88dd83549aadf1e984";

    fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// Visibility of the handshake secret in the two-party tests.
    enum Visibility {
        /// Public on both parties.
        Public,
        /// Private on the leader, blind on the follower (the realistic
        /// proxy-mode split).
        Split,
    }

    /// (derived, master, c_ap, s_ap) node values.
    type InternalValues = ([u8; 32], [u8; 32], [u8; 32], [u8; 32]);
    /// (derived, master, c_ap, s_ap) decode futures.
    type InternalDecodes = (Decode32, Decode32, Decode32, Decode32);

    /// Decoded values of the full derivation graph.
    struct ScheduleValues {
        c_hs: [u8; 32],
        s_hs: [u8; 32],
        /// (derived, master, c_ap, s_ap), only decoded when requested.
        internal: Option<InternalValues>,
        client_write_key: [u8; 16],
        server_write_key: [u8; 16],
        client_iv: [u8; 12],
        server_iv: [u8; 12],
    }

    /// Runs the key schedule on two `IdealVm`s following the spec'd phase
    /// order, asserts leader/follower equality, and returns the leader's
    /// decoded values.
    async fn run_key_schedule(
        vis: Visibility,
        decode_internal: bool,
        hs: [u8; 32],
        h2: [u8; 32],
        h3: [u8; 32],
    ) -> ScheduleValues {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut leader = IdealVm::new();
        let mut follower = IdealVm::new();

        let hs_leader: Array<U8, 32> = leader.alloc().unwrap();
        let hs_follower: Array<U8, 32> = follower.alloc().unwrap();
        match vis {
            Visibility::Public => {
                leader.mark_public(hs_leader).unwrap();
                leader.assign(hs_leader, hs).unwrap();
                leader.commit(hs_leader).unwrap();

                follower.mark_public(hs_follower).unwrap();
                follower.assign(hs_follower, hs).unwrap();
                follower.commit(hs_follower).unwrap();
            }
            Visibility::Split => {
                leader.mark_private(hs_leader).unwrap();
                leader.assign(hs_leader, hs).unwrap();
                leader.commit(hs_leader).unwrap();

                follower.mark_blind(hs_follower).unwrap();
                follower.commit(hs_follower).unwrap();
            }
        }

        let mut ks_leader = KeySchedule13::new();
        let mut ks_follower = KeySchedule13::new();

        let out_leader = ks_leader.alloc(&mut leader, hs_leader).unwrap();
        let out_follower = ks_follower.alloc(&mut follower, hs_follower).unwrap();

        let mut decoded_leader = decode_output(&mut leader, &out_leader);
        let mut decoded_follower = decode_output(&mut follower, &out_follower);

        let mut internal_leader =
            decode_internal.then(|| decode_internal_nodes(&mut leader, &ks_leader));
        let mut internal_follower =
            decode_internal.then(|| decode_internal_nodes(&mut follower, &ks_follower));

        // Phase 1: constants progress.
        flush(
            &mut ks_leader,
            &mut leader,
            &mut ctx_a,
            &mut ks_follower,
            &mut follower,
            &mut ctx_b,
        )
        .await;

        // Phase 2: handshake traffic secrets.
        ks_leader.set_sh_hash(h2).unwrap();
        ks_follower.set_sh_hash(h2).unwrap();
        flush(
            &mut ks_leader,
            &mut leader,
            &mut ctx_a,
            &mut ks_follower,
            &mut follower,
            &mut ctx_b,
        )
        .await;

        // Phase 3: application traffic secrets and keys.
        ks_leader.set_sf_hash(h3).unwrap();
        ks_follower.set_sf_hash(h3).unwrap();
        flush(
            &mut ks_leader,
            &mut leader,
            &mut ctx_a,
            &mut ks_follower,
            &mut follower,
            &mut ctx_b,
        )
        .await;

        let values_leader = recv_values(&mut decoded_leader, internal_leader.as_mut());
        let values_follower = recv_values(&mut decoded_follower, internal_follower.as_mut());

        assert_eq!(values_leader.c_hs, values_follower.c_hs);
        assert_eq!(values_leader.s_hs, values_follower.s_hs);
        assert_eq!(values_leader.internal, values_follower.internal);
        assert_eq!(
            values_leader.client_write_key,
            values_follower.client_write_key
        );
        assert_eq!(
            values_leader.server_write_key,
            values_follower.server_write_key
        );
        assert_eq!(values_leader.client_iv, values_follower.client_iv);
        assert_eq!(values_leader.server_iv, values_follower.server_iv);

        values_leader
    }

    type Decode32 = mpz_vm_core::memory::DecodeFutureTyped<mpz_core::bitvec::BitVec, [u8; 32]>;
    type Decode16 = mpz_vm_core::memory::DecodeFutureTyped<mpz_core::bitvec::BitVec, [u8; 16]>;
    type Decode12 = mpz_vm_core::memory::DecodeFutureTyped<mpz_core::bitvec::BitVec, [u8; 12]>;

    struct DecodedOutput {
        c_hs: Decode32,
        s_hs: Decode32,
        client_write_key: Decode16,
        server_write_key: Decode16,
        client_iv: Decode12,
        server_iv: Decode12,
    }

    fn decode_output(vm: &mut IdealVm, output: &ScheduleOutput13) -> DecodedOutput {
        let ScheduleOutput13 {
            keys:
                SessionKeys13 {
                    client_write_key,
                    server_write_key,
                    client_iv,
                    server_iv,
                },
            c_hs,
            s_hs,
        } = *output;

        DecodedOutput {
            c_hs: vm.decode(c_hs).unwrap(),
            s_hs: vm.decode(s_hs).unwrap(),
            client_write_key: vm.decode(client_write_key).unwrap(),
            server_write_key: vm.decode(server_write_key).unwrap(),
            client_iv: vm.decode(client_iv).unwrap(),
            server_iv: vm.decode(server_iv).unwrap(),
        }
    }

    fn decode_internal_nodes(vm: &mut IdealVm, ks: &KeySchedule13) -> InternalDecodes {
        let State::Setup { nodes } = &ks.state else {
            panic!("key schedule should be set up");
        };

        (
            vm.decode(nodes.derived.output).unwrap(),
            vm.decode(nodes.master.output).unwrap(),
            vm.decode(nodes.c_ap.output).unwrap(),
            vm.decode(nodes.s_ap.output).unwrap(),
        )
    }

    fn recv_values(
        decoded: &mut DecodedOutput,
        internal: Option<&mut InternalDecodes>,
    ) -> ScheduleValues {
        ScheduleValues {
            c_hs: decoded.c_hs.try_recv().unwrap().unwrap(),
            s_hs: decoded.s_hs.try_recv().unwrap().unwrap(),
            internal: internal.map(|(derived, master, c_ap, s_ap)| {
                (
                    derived.try_recv().unwrap().unwrap(),
                    master.try_recv().unwrap().unwrap(),
                    c_ap.try_recv().unwrap().unwrap(),
                    s_ap.try_recv().unwrap().unwrap(),
                )
            }),
            client_write_key: decoded.client_write_key.try_recv().unwrap().unwrap(),
            server_write_key: decoded.server_write_key.try_recv().unwrap().unwrap(),
            client_iv: decoded.client_iv.try_recv().unwrap().unwrap(),
            server_iv: decoded.server_iv.try_recv().unwrap().unwrap(),
        }
    }

    async fn flush(
        ks_leader: &mut KeySchedule13,
        leader: &mut IdealVm,
        ctx_a: &mut mpz_common::context::Context,
        ks_follower: &mut KeySchedule13,
        follower: &mut IdealVm,
        ctx_b: &mut mpz_common::context::Context,
    ) {
        while ks_leader.wants_flush() || ks_follower.wants_flush() {
            tokio::try_join!(
                async {
                    ks_leader.flush(leader).unwrap();
                    leader.execute_all(ctx_a).await
                },
                async {
                    ks_follower.flush(follower).unwrap();
                    follower.execute_all(ctx_b).await
                }
            )
            .unwrap();
        }
    }

    /// Tests the full derivation graph against the RFC 8448 §3 "Simple 1-RTT
    /// Handshake" vectors.
    #[tokio::test]
    async fn test_key_schedule13_rfc8448() {
        let values = run_key_schedule(
            Visibility::Public,
            true,
            hex_arr(RFC8448_HS),
            hex_arr(RFC8448_H2),
            hex_arr(RFC8448_H3),
        )
        .await;

        assert_eq!(values.c_hs, hex_arr::<32>(RFC8448_C_HS));
        assert_eq!(values.s_hs, hex_arr::<32>(RFC8448_S_HS));

        let (derived, master, c_ap, s_ap) = values.internal.unwrap();
        assert_eq!(derived, hex_arr::<32>(RFC8448_DERIVED));
        assert_eq!(master, hex_arr::<32>(RFC8448_MASTER));
        assert_eq!(c_ap, hex_arr::<32>(RFC8448_C_AP));
        assert_eq!(s_ap, hex_arr::<32>(RFC8448_S_AP));

        assert_eq!(values.client_write_key, hex_arr::<16>(RFC8448_CLIENT_KEY));
        assert_eq!(values.client_iv, hex_arr::<12>(RFC8448_CLIENT_IV));
        assert_eq!(values.server_write_key, hex_arr::<16>(RFC8448_SERVER_KEY));
        assert_eq!(values.server_iv, hex_arr::<12>(RFC8448_SERVER_IV));
    }

    /// Tests random inputs against the cleartext reference implementation.
    #[tokio::test]
    async fn test_key_schedule13_random() {
        let mut rng = StdRng::seed_from_u64(7);

        let hs: [u8; 32] = rng.random();
        let h2: [u8; 32] = rng.random();
        let h3: [u8; 32] = rng.random();

        let expected = reference_schedule(hs, h2, h3);
        let values = run_key_schedule(Visibility::Public, true, hs, h2, h3).await;

        assert_eq!(values.c_hs, expected.c_hs);
        assert_eq!(values.s_hs, expected.s_hs);

        let (derived, master, c_ap, s_ap) = values.internal.unwrap();
        assert_eq!(derived, expected.derived);
        assert_eq!(master, expected.master);
        assert_eq!(c_ap, expected.c_ap);
        assert_eq!(s_ap, expected.s_ap);

        assert_eq!(values.client_write_key, expected.client_write_key);
        assert_eq!(values.server_write_key, expected.server_write_key);
        assert_eq!(values.client_iv, expected.client_iv);
        assert_eq!(values.server_iv, expected.server_iv);
    }

    /// Tests the realistic proxy-mode visibility split: the leader provides
    /// the handshake secret as a private input, the follower is blind.
    #[tokio::test]
    async fn test_key_schedule13_private_hs() {
        let mut rng = StdRng::seed_from_u64(8);

        let hs: [u8; 32] = rng.random();
        let h2: [u8; 32] = rng.random();
        let h3: [u8; 32] = rng.random();

        let expected = reference_schedule(hs, h2, h3);
        let values = run_key_schedule(Visibility::Split, false, hs, h2, h3).await;

        assert_eq!(values.c_hs, expected.c_hs);
        assert_eq!(values.s_hs, expected.s_hs);
        assert_eq!(values.client_write_key, expected.client_write_key);
        assert_eq!(values.server_write_key, expected.server_write_key);
        assert_eq!(values.client_iv, expected.client_iv);
        assert_eq!(values.server_iv, expected.server_iv);
    }

    /// Tests the two-phase driver flow and that calls in the wrong state
    /// return errors instead of panicking.
    #[tokio::test]
    async fn test_key_schedule13_driver_order() {
        let mut rng = StdRng::seed_from_u64(9);

        let hs: [u8; 32] = rng.random();
        let h2: [u8; 32] = rng.random();
        let h3: [u8; 32] = rng.random();

        let expected = reference_schedule(hs, h2, h3);

        // Setters before allocation must fail.
        let mut ks = KeySchedule13::new();
        assert!(ks.set_sh_hash(h2).is_err());
        assert!(ks.set_sf_hash(h3).is_err());
        assert!(!ks.wants_flush());

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut leader = IdealVm::new();
        let mut follower = IdealVm::new();

        let hs_leader: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(hs_leader).unwrap();
        leader.assign(hs_leader, hs).unwrap();
        leader.commit(hs_leader).unwrap();

        let hs_follower: Array<U8, 32> = follower.alloc().unwrap();
        follower.mark_public(hs_follower).unwrap();
        follower.assign(hs_follower, hs).unwrap();
        follower.commit(hs_follower).unwrap();

        let mut ks_leader = KeySchedule13::new();
        let mut ks_follower = KeySchedule13::new();

        let _ = ks_leader.alloc(&mut leader, hs_leader).unwrap();
        let out_follower = ks_follower.alloc(&mut follower, hs_follower).unwrap();

        // Double allocation must fail.
        assert!(ks_leader.alloc(&mut leader, hs_leader).is_err());
        ks_leader = KeySchedule13::new();
        let out_leader = ks_leader.alloc(&mut leader, hs_leader).unwrap();

        let mut decoded_leader = decode_output(&mut leader, &out_leader);
        let mut decoded_follower = decode_output(&mut follower, &out_follower);

        // Constant-message nodes progress on the first flush.
        assert!(ks_leader.wants_flush());
        assert!(ks_follower.wants_flush());
        flush(
            &mut ks_leader,
            &mut leader,
            &mut ctx_a,
            &mut ks_follower,
            &mut follower,
            &mut ctx_b,
        )
        .await;

        // Without the transcript hashes, nothing is decodable yet.
        assert!(decoded_leader.c_hs.try_recv().unwrap().is_none());
        assert!(
            decoded_leader
                .client_write_key
                .try_recv()
                .unwrap()
                .is_none()
        );

        // h2 unblocks the handshake traffic secrets...
        ks_leader.set_sh_hash(h2).unwrap();
        ks_follower.set_sh_hash(h2).unwrap();
        assert!(ks_leader.wants_flush());
        flush(
            &mut ks_leader,
            &mut leader,
            &mut ctx_a,
            &mut ks_follower,
            &mut follower,
            &mut ctx_b,
        )
        .await;

        assert_eq!(
            decoded_leader.c_hs.try_recv().unwrap().unwrap(),
            expected.c_hs
        );
        assert_eq!(
            decoded_leader.s_hs.try_recv().unwrap().unwrap(),
            expected.s_hs
        );
        // ... but not the application keys.
        assert!(
            decoded_leader
                .client_write_key
                .try_recv()
                .unwrap()
                .is_none()
        );
        assert!(decoded_leader.server_iv.try_recv().unwrap().is_none());

        // h3 unblocks the application keys.
        ks_leader.set_sf_hash(h3).unwrap();
        ks_follower.set_sf_hash(h3).unwrap();
        flush(
            &mut ks_leader,
            &mut leader,
            &mut ctx_a,
            &mut ks_follower,
            &mut follower,
            &mut ctx_b,
        )
        .await;

        assert_eq!(
            decoded_leader.client_write_key.try_recv().unwrap().unwrap(),
            expected.client_write_key
        );
        assert_eq!(
            decoded_leader.server_write_key.try_recv().unwrap().unwrap(),
            expected.server_write_key
        );
        assert_eq!(
            decoded_leader.client_iv.try_recv().unwrap().unwrap(),
            expected.client_iv
        );
        assert_eq!(
            decoded_leader.server_iv.try_recv().unwrap().unwrap(),
            expected.server_iv
        );

        assert_eq!(
            decoded_follower
                .client_write_key
                .try_recv()
                .unwrap()
                .unwrap(),
            expected.client_write_key
        );

        // The schedule is complete: no more flushing, setters must fail.
        assert!(!ks_leader.wants_flush());
        assert!(ks_leader.set_sh_hash(h2).is_err());
        assert!(ks_leader.set_sf_hash(h3).is_err());
    }
}
