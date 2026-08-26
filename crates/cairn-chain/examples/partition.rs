//! Two nodes, a broken link, and what happens when it comes back.
//!
//! Run with `cargo run -p cairn-chain --example partition`.

#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const SPACING: u64 = 600;
const ATTEMPTS: u64 = 1 << 22;

/// Builds blocks on a private copy of the ledger.
#[derive(Clone)]
struct Miner {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Miner {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, who: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let height = self.state.next_height().expect("the chain has room");
        self.clock += SPACING;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, who.public_key())],
            [0; 8],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .expect("the block is valid");
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).expect("it connects");
        block
    }

    fn mine_empty(&mut self, who: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(who, Vec::new())).collect()
    }
}

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let other = SecretKey::from_bytes(&[9; 32]);
    let alice = SecretKey::from_bytes(&[2; 32]);

    let mut shared = Miner::new(params);
    let common = shared.mine_empty(&miner, 8);

    let mut north = ChainStore::new(params);
    let mut south = ChainStore::new(params);
    for block in &common {
        north.add_block(block.clone(), NOW).expect("north accepts");
        south.add_block(block.clone(), NOW).expect("south accepts");
    }

    // North's branch will pay alice. South's will do nothing, but run longer.
    let last_common = common.last().expect("eight blocks were mined");
    let funded = NoteId::new(last_common.coinbase.id(), 0);
    let funded_note = Note::new(params.initial_reward, miner.public_key());
    let mut payment = Transfer::new(
        vec![Input::hot(funded)],
        vec![Note::new(funded_note.value, alice.public_key())],
    );
    payment.sign_input(params.network, 0, &funded_note, &miner);
    let paid = NoteId::new(payment.id(), 0);

    println!("Two nodes, one chain.");
    println!();
    report(&north, "north", &paid);
    report(&south, "south", &paid);

    println!();
    println!("The link between them goes down. Each keeps working alone.");
    println!();

    let mut north_miner = shared.clone();
    let mut south_miner = shared.clone();
    let mut north_blocks = vec![north_miner.mine(&miner, vec![payment])];
    north_blocks.push(north_miner.mine(&miner, Vec::new()));
    let south_blocks = south_miner.mine_empty(&other, 5);

    for block in &north_blocks {
        north
            .add_block(block.clone(), NOW)
            .expect("north accepts its own");
    }
    for block in &south_blocks {
        south
            .add_block(block.clone(), NOW)
            .expect("south accepts its own");
    }

    println!("north  mined 2 blocks, one of them paying alice 50 CAIRN");
    println!("south  mined 5 blocks, quietly");
    println!();
    report(&north, "north", &paid);
    report(&south, "south", &paid);
    println!();
    println!("They disagree, and each is certain of what it saw.");
    println!();
    println!("The link comes back. Each sends the other everything it has.");
    println!();

    for block in &south_blocks {
        north
            .add_block(block.clone(), NOW)
            .expect("north accepts south's");
    }
    for block in &north_blocks {
        south
            .add_block(block.clone(), NOW)
            .expect("south accepts north's");
    }

    report(&north, "north", &paid);
    report(&south, "south", &paid);

    println!();
    println!("Same tip, same ledger, with no vote and no arbiter. The heavier branch");
    println!("won, so north undid its own payment.");
    println!();
    println!(
        "  state root agrees   {}",
        north.state().state_root() == south.state().state_root()
    );
    println!(
        "  the spent note is unspent again   {}",
        north.state().hot_note(&funded).is_some()
    );
    println!(
        "  north still holds {} blocks, including the ones it abandoned",
        north.len()
    );
}

fn report(store: &ChainStore, name: &str, paid: &NoteId) {
    let tip = store.tip().map(|id| id.to_string()).unwrap_or_default();
    let short = tip.get(..12).unwrap_or("none");
    let alice = match store.state().hot_note(paid) {
        Some(note) => note.value.to_string(),
        None => "nothing".to_owned(),
    };
    println!(
        "  {name:<6} height {:>2}   work {:>2}   tip {short}   alice holds {alice}",
        store.height().unwrap_or_default(),
        store.total_work(),
    );
}
