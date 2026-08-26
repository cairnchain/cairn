//! Builds a short chain and prints what each block does to the ledger.
//!
//! Run with `cargo run -p cairn-ledger --example walkthrough`.

#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use cairn_crypto::SecretKey;
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::Amount;

const NOW: u64 = 1_800_000_000;

fn main() {
    let params = ConsensusParams::testnet();
    let miner = SecretKey::from_bytes(&[1; 32]);
    let alice = SecretKey::from_bytes(&[2; 32]);
    let bob = SecretKey::from_bytes(&[3; 32]);

    let mut state = LedgerState::new();
    println!("network        {:#010x}", params.network.as_u32());
    println!("block reward   {}", params.block_reward);
    println!();

    let coinbase = CoinbaseTransaction::new(
        0,
        vec![Note::new(params.block_reward, miner.public_key())],
        [0; 8],
    );
    let genesis = assemble_block(&state, coinbase, Vec::new(), &params, 1_700_000_000, 0)
        .expect("the genesis block is valid");
    connect_block(&mut state, &genesis, &params, NOW).expect("the genesis block connects");
    report(&state, "genesis", &genesis.id().to_string());

    let mut held_id = NoteId::new(genesis.coinbase.id(), 0);
    let mut held = Note::new(params.block_reward, miner.public_key());

    for (height, (recipient, label)) in [(&alice, "alice"), (&bob, "bob")].iter().enumerate() {
        let height = height as u64 + 1;
        let sent = Amount::from_pebbles(1_250_000_000).expect("amount is under the ceiling");
        let fee = Amount::from_pebbles(1_000).expect("amount is under the ceiling");
        let change = held
            .value
            .checked_sub(sent)
            .and_then(|rest| rest.checked_sub(fee))
            .expect("the held note covers the payment and the fee");

        let mut transfer = Transfer::new(
            vec![Input::unsigned(held_id)],
            vec![
                Note::new(sent, recipient.public_key()),
                Note::new(change, miner.public_key()),
            ],
        );
        transfer.sign_input(params.network, 0, &held, &miner);
        let transfer_id = transfer.id();

        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(
                params
                    .block_reward
                    .checked_add(fee)
                    .expect("reward plus fee is representable"),
                miner.public_key(),
            )],
            [0; 8],
        );
        let block = assemble_block(
            &state,
            coinbase,
            vec![transfer],
            &params,
            1_700_000_000 + height * 60,
            0,
        )
        .expect("the block is valid");
        connect_block(&mut state, &block, &params, NOW).expect("the block connects");

        report(
            &state,
            &format!("pays {sent} to {label}"),
            &block.id().to_string(),
        );

        held_id = NoteId::new(transfer_id, 1);
        held = Note::new(change, miner.public_key());
    }

    println!("The chain holds {} unspent notes.", state.len());
    println!("Every node above stored the state as one {} byte root.", 32);
}

fn report(state: &LedgerState, what: &str, block_id: &str) {
    let tip = state.tip().expect("the chain has a tip");
    println!("block {:<3} {}", tip.height, what);
    println!("  id         {block_id}");
    println!("  state root {}", state.state_root());
    println!("  notes      {}", state.len());
    println!();
}
