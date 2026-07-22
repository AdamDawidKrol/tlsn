use mpz_core::{Block, prg::Prg};
use mpz_ot_core::{
    kos::{self, SenderConfig},
    rcot::RCOTSender,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::Serialize;

const CSP: usize = kos::CSP;
const USEFUL: usize = 128;
const COUNT: usize = 256;
const ROW_BYTES: usize = COUNT / 8;
const BLOCKS_PER_ROW: usize = ROW_BYTES / 16;

fn prg_stream(seed: Block, n: usize) -> Vec<u8> {
    let mut prg = Prg::from_seed(seed);
    let mut out = vec![0u8; n];
    prg.fill_bytes(&mut out);
    out
}

fn delta_bit(delta: &Block, i: usize) -> bool {
    (delta.as_bytes()[i / 8] >> (i % 8)) & 1 == 1
}

fn block_from(bytes: &[u8]) -> Block {
    let a: [u8; 16] = bytes.try_into().expect("16 bytes");
    Block::new(a)
}

#[derive(Serialize)]
struct ExtendWire {
    count: usize,
    us: Vec<u8>,
}

#[derive(Serialize)]
struct CheckWire {
    x: Block,
    t: Vec<Block>,
}

struct MaliciousReceiver {
    t0_rows: Vec<[Block; BLOCKS_PER_ROW]>,
    us: Vec<u8>,
    x_blocks: [Block; BLOCKS_PER_ROW],
}

impl MaliciousReceiver {
    fn new(seed_pairs: &[[Block; 2]; CSP], cvec: &[u8; ROW_BYTES]) -> Self {
        let mut t0_rows = Vec::with_capacity(CSP);
        let mut us = vec![0u8; CSP * ROW_BYTES];
        for i in 0..CSP {
            let t0 = prg_stream(seed_pairs[i][0], ROW_BYTES);
            let t1 = prg_stream(seed_pairs[i][1], ROW_BYTES);
            let row = &mut us[i * ROW_BYTES..(i + 1) * ROW_BYTES];
            for b in 0..ROW_BYTES {
                row[b] = t0[b] ^ t1[b] ^ cvec[b];
            }
            t0_rows.push([block_from(&t0[0..16]), block_from(&t0[16..32])]);
        }
        let x_blocks = [block_from(&cvec[0..16]), block_from(&cvec[16..32])];
        Self {
            t0_rows,
            us,
            x_blocks,
        }
    }

    fn build_extend(&self) -> kos::Extend {
        let wire = ExtendWire {
            count: COUNT,
            us: self.us.clone(),
        };
        let bytes = bincode::serialize(&wire).unwrap();
        bincode::deserialize::<kos::Extend>(&bytes).expect("valid Extend")
    }

    fn build_check(&self, chi_seed: Block) -> kos::Check {
        let m = BLOCKS_PER_ROW - 1;
        let mut rng = Prg::from_seed(chi_seed);
        let chis: Vec<Block> = (0..m).map(|_| rng.random()).collect();

        let t: Vec<Block> = self
            .t0_rows
            .iter()
            .map(|row| Block::inn_prdt_red(&row[..m], &chis) ^ row[m])
            .collect();
        let x = Block::inn_prdt_red(&self.x_blocks[..m], &chis) ^ self.x_blocks[m];

        let wire = CheckWire { x, t };
        let bytes = bincode::serialize(&wire).unwrap();
        bincode::deserialize::<kos::Check>(&bytes).expect("valid Check")
    }
}

fn run_sender(delta: Block, seed_pairs: &[[Block; 2]; CSP], cvec: &[u8; ROW_BYTES]) -> Vec<Block> {
    let mut sender_seeds = [Block::ZERO; CSP];
    for i in 0..CSP {
        sender_seeds[i] = seed_pairs[i][delta_bit(&delta, i) as usize];
    }

    let sender = kos::Sender::new(SenderConfig::default(), delta);
    let mut sender = sender.setup(sender_seeds);
    sender.alloc(USEFUL).unwrap();

    let mr = MaliciousReceiver::new(seed_pairs, cvec);

    sender.extend(mr.build_extend()).unwrap();
    let chi = sender.check_start();
    sender
        .check(mr.build_check(chi))
        .expect("honest KOS consistency check must PASS");

    sender.try_send_rcot(USEFUL).unwrap().keys
}

#[test]
fn attack_shared_delta_recovers_delta() {
    let mut rng = ChaCha12Rng::seed_from_u64(0xC0FFEE);
    let delta = Block::random(&mut rng);

    let seed_pairs: [[Block; 2]; CSP] =
        std::array::from_fn(|_| [Block::random(&mut rng), Block::random(&mut rng)]);

    let mut x = [0u8; ROW_BYTES];
    rng.fill_bytes(&mut x);
    let mut x_compl = x;
    for b in x_compl.iter_mut() {
        *b ^= 0xFF;
    }

    let keys_a = run_sender(delta, &seed_pairs, &x);
    let keys_b = run_sender(delta, &seed_pairs, &x_compl);

    let recovered = keys_a[0] ^ keys_b[0];
    let matches = keys_a
        .iter()
        .zip(&keys_b)
        .filter(|(a, b)| (**a ^ **b) == delta)
        .count();

    let sample_bits: String = (0..16)
        .map(|i| if delta_bit(&recovered, i) { '1' } else { '0' })
        .collect();

    println!("both honest KOS consistency checks PASSED");
    println!("true delta      : {:?}", delta);
    println!(
        "recovered delta : {:?}  (= keys_A[0] ^ keys_B[0])",
        recovered
    );
    println!("recovered delta agrees with true delta on {matches}/{USEFUL} columns");
    println!("sampled first 16 delta bits (lsb0): {sample_bits}");
    println!("DELTA RECOVERED — shared-delta KOS instances leak the global MAC correlation");

    assert_eq!(recovered, delta, "malicious receiver must recover delta");
    assert_eq!(matches, USEFUL, "every column must leak delta");
}
