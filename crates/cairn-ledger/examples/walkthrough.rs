//! Runs a short chain with a deliberately tiny hot set, so notes fall to the
//! cold set within a few blocks and one of them is spent back out of it.
//!
//! Run with `cargo run -p cairn-ledger --example walkthrough`.

#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;

const NOW: u64 = 1_800_000_000;
const HOT_CAPACITY: usize = 4;

fn main() {
    let params = ConsensusParams::testnet().with_hot_capacity(HOT_CAPACITY);
    let miner = SecretKey::from_bytes(&[1; 32]);
    let alice = SecretKey::from_bytes(&[2; 32]);

    println!("network        {:#010x}", params.network.as_u32());
    println!("block reward   {}", params.block_reward);
    println!("hot capacity   {HOT_CAPACITY} notes");
    println!();
    println!(
        "{:<5} {:<36} {:>5} {:>6}",
        "block", "what happened", "hot", "cold"
    );
    println!("{}", "-".repeat(56));

    let mut state = LedgerState::new();
    let mut minted: Vec<(NoteId, Note)> = Vec::new();

    for _ in 0..8 {
        let block = mine(&mut state, &params, &miner, Vec::new());
        minted.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(params.block_reward, miner.public_key()),
        ));
        let note = if state.cold_len() == 0 {
            "the miner is paid"
        } else {
            "the miner is paid, the oldest fell"
        };
        report(&state, note);
    }

    println!();
    println!("The four oldest notes are no longer held by anyone. To spend one, its");
    println!("owner brings the note and a proof that it belongs to the commitment.");
    println!();

    let (fallen, note) = *minted.first().expect("eight blocks minted eight notes");
    let proof = state.cold().prove(&fallen);
    println!(
        "  note        {} {}",
        &fallen.source.to_string()[..16],
        note.value
    );
    println!(
        "  proof       {} bytes, {} levels",
        proof.size_in_bytes(),
        proof.depth()
    );
    println!("  checked against the {} byte commitment alone", 32);
    println!();

    let mut transfer = Transfer::new(
        vec![Input::cold(fallen, note, proof)],
        vec![Note::new(note.value, alice.public_key())],
    );
    transfer.sign_input(params.network, 0, &note, &miner);
    mine(&mut state, &params, &miner, vec![transfer]);
    report(&state, "a fallen note is spent to alice");

    println!();
    println!("Recovered value lands back in the hot set, and because the hot set was");
    println!("already full, two more notes took its place in the cold set.");
    println!();
    println!("state root  {}", state.state_root());
    println!("Every node followed all of this holding {HOT_CAPACITY} notes and two 32 byte roots.");
}

fn mine(
    state: &mut LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    transfers: Vec<Transfer>,
) -> cairn_ledger::Block {
    let height = state.next_height().expect("the chain has room");
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.block_reward, miner.public_key())],
        [0; 8],
    );
    let block = assemble_block(
        state,
        coinbase,
        transfers,
        params,
        1_700_000_000 + height * 600,
        0,
    )
    .expect("the block is valid");
    connect_block(state, &block, params, NOW).expect("the block connects");
    block
}

fn report(state: &LedgerState, what: &str) {
    let height = state.tip().expect("the chain has a tip").height;
    println!(
        "{height:<5} {what:<36} {:>5} {:>6}",
        state.hot_len(),
        state.cold_len()
    );
}
