//! Consensus, handed blocks bent out of shape.
//!
//! Every other campaign in the workspace stops at a decoder, and
//! `invariants.rs` connects random sequences of blocks built to be valid. So
//! the code that decides money had met only blocks somebody meant it to take.
//! This hands `connect_block` the next block of a real chain, bent by every
//! operator `cairn_fuzz` has, and holds the two things a refusal and an
//! acceptance each promise:
//!
//! 1. Refused, the state is exactly what it was. A rule that is checked after
//!    part of the block has been applied, and does not put that part back,
//!    leaves a node holding a ledger no block produced.
//! 2. Taken, the state moved as the block says: its header is the tip, the
//!    state root is the one the header commits to, the work is the work it
//!    claims, and taking the same block again from the same state lands in
//!    the same place.
//!
//! Two arms. The block as bent, which is what a peer sends and what the header
//! rules and the root comparisons see. And the block bent and then resealed,
//! its transactions root worked out again from the bent body, which is how a
//! bent spend gets past the one comparison that would otherwise refuse every
//! change to a body and on into the rules about inputs, proofs, signatures
//! and amounts. Nothing here mines: the test network's first difficulty is
//! one, and the chain below is spaced to keep it there, so a changed header
//! costs nothing to seal.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

use cairn_crypto::SecretKey;
use cairn_fuzz::{mutate, Campaign};
use cairn_ledger::block::{Block, HeaderSummary};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::state::{HotEntry, Tip};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::{Decode, Encode};
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
/// The spacing the difficulty rule aims for on the test network, so the chain
/// below stays at a difficulty of one.
const SPACING: u64 = 60;
/// Blocks under the tip of the chain the bent blocks are offered to: enough for
/// the oldest rewards to have fallen out of the hot set and then out of the
/// grace window, so a spend can carry a proof.
const HEIGHT: u64 = 80;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(8)
        .with_max_evictions(8)
        .with_coinbase_maturity(2)
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// Everything two nodes have to agree on, and everything a refusal must leave
/// alone, in one comparable value.
///
/// The shape of `invariants.rs`'s fingerprint, with the supply and the
/// maturing rewards beside it: the root commits to six things, and the
/// structures that answer which note is oldest and what is spendable without
/// a proof are not among them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    state_root: Hash32,
    history_root: Hash32,
    grace_root: Hash32,
    headers_committed: u64,
    total_work: u128,
    tip: Option<Tip>,
    recent: Vec<HeaderSummary>,
    hot: Vec<(NoteId, HotEntry)>,
    cold_len: u64,
    next_cold_position: u64,
    grace: Vec<Vec<(NoteId, u64, Note)>>,
    maturing: Vec<(u64, Hash32)>,
    supply: Amount,
}

fn fingerprint(state: &LedgerState) -> Fingerprint {
    let mut hot: Vec<(NoteId, HotEntry)> = state.hot_notes().collect();
    hot.sort_by_key(|(id, _)| *id);
    Fingerprint {
        state_root: state.state_root(),
        history_root: state.history_root(),
        grace_root: state.grace_root(),
        headers_committed: state.headers_committed(),
        total_work: state.total_work(),
        tip: state.tip(),
        recent: state.recent_headers().to_vec(),
        hot,
        cold_len: state.cold_len(),
        next_cold_position: state.next_cold_position(),
        grace: state.grace_window(),
        maturing: state.maturing(),
        supply: state.supply(),
    }
}

/// A chain `HEIGHT` blocks long, every reward paid to one key, and the rewards
/// it paid in the order it paid them.
fn chain(params: &ConsensusParams) -> (LedgerState, Vec<(NoteId, Note)>) {
    let miner = wallet(1);
    let mut state = LedgerState::archiving();
    let mut paid = Vec::new();
    let mut clock = 1_000u64;
    for _ in 0..HEIGHT {
        let height = state.next_height().unwrap();
        clock += SPACING;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.reward_at(height), miner.public_key())],
        );
        paid.push((NoteId::new(coinbase.id(), 0), coinbase.outputs[0]));
        let block = assemble_block(&state, coinbase, Vec::new(), params, clock, 0).unwrap();
        connect_block(&mut state, &block, params, NOW).unwrap();
    }
    (state, paid)
}

/// The input that spends `id` from `state`, whichever tier holds it.
fn input(state: &LedgerState, id: NoteId, note: Note) -> Input {
    if state.hot_note(&id).is_some() || state.within_grace(&id).is_some() {
        return Input::hot(id);
    }
    let position = state.cold().locate(&id, &note).expect("it fell somewhere");
    let proof = state
        .cold()
        .prove(position)
        .expect("an archivist proves it");
    Input::cold(id, note, position, proof)
}

/// A signed transfer of `spent` to one new owner per note, keeping nothing
/// back.
fn transfer(state: &LedgerState, params: &ConsensusParams, spent: &[(NoteId, Note)]) -> Transfer {
    let inputs = spent
        .iter()
        .map(|(id, note)| input(state, *id, *note))
        .collect();
    let outputs = spent
        .iter()
        .enumerate()
        .map(|(index, (_, note))| {
            Note::new(
                note.value,
                wallet(10 + u8::try_from(index).unwrap()).public_key(),
            )
        })
        .collect();
    let mut transfer = Transfer::new(inputs, outputs);
    for (index, (_, note)) in spent.iter().enumerate() {
        transfer.sign_input(
            params.network,
            u32::try_from(index).unwrap(),
            note,
            &wallet(1),
        );
    }
    transfer
}

/// The next block of the chain, several ways, each of them valid.
///
/// A spend from each tier, one spending from all three at once, and an empty
/// one, so the operators have every kind of input to bend and to splice
/// between.
fn next_blocks(
    state: &LedgerState,
    params: &ConsensusParams,
    paid: &[(NoteId, Note)],
) -> Vec<Block> {
    let height = state.next_height().unwrap();
    let clock = state.tip().unwrap().timestamp + SPACING;
    let cold = paid[0];
    let grace = paid[40];
    let hot = paid[usize::try_from(HEIGHT).unwrap() - 4];
    assert!(
        state.hot_note(&hot.0).is_some(),
        "the fixture's hot note is not hot"
    );
    assert!(
        state.within_grace(&grace.0).is_some(),
        "the fixture's grace note is not in the window"
    );
    assert!(
        state.hot_note(&cold.0).is_none() && state.within_grace(&cold.0).is_none(),
        "the fixture's cold note is still spendable without a proof"
    );
    let bodies: Vec<Vec<Transfer>> = vec![
        vec![transfer(state, params, &[hot])],
        vec![transfer(state, params, &[grace])],
        vec![transfer(state, params, &[cold])],
        vec![transfer(state, params, &[hot, grace, cold])],
        vec![
            transfer(state, params, &[hot]),
            transfer(state, params, &[cold]),
        ],
        Vec::new(),
    ];
    bodies
        .into_iter()
        .map(|transfers| {
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.reward_at(height), wallet(2).public_key())],
            );
            assemble_block(state, coinbase, transfers, params, clock, 0)
                .expect("the fixture's next block is valid")
        })
        .collect()
}

/// The name of a refusal, without what it carries.
fn kind_of(refused: &impl std::fmt::Debug) -> String {
    let said = format!("{refused:?}");
    let end = said.find([' ', '(', '{']).unwrap_or(said.len());
    said[..end].to_owned()
}

/// What one arm fed `connect_block`, and what came back.
#[derive(Debug, Default)]
struct Tally {
    bent: usize,
    decoded: usize,
    taken: usize,
    refused: BTreeMap<String, usize>,
}

impl Tally {
    fn report(&self, what: &str) {
        eprintln!(
            "{what}: {} bent, {} decoded and connected, {} taken, refused as {:?}",
            self.bent, self.decoded, self.taken, self.refused
        );
    }
}

/// A bent block is refused and leaves the state as it was, or is taken and
/// moves the state as it says.
///
/// Nothing asked either half of this of a block nobody meant to be valid, so
/// a rule that applied part of a block before refusing it passed, and so did
/// an acceptance that moved the ledger somewhere its header does not commit
/// to.
#[test]
fn a_bent_block_is_refused_untouched_or_taken_as_it_says() {
    let campaign = Campaign::named("ledger: bent blocks through consensus");
    let params = params();
    let (base, paid) = chain(&params);
    let before = fingerprint(&base);
    let blocks = next_blocks(&base, &params, &paid);
    for block in &blocks {
        let mut state = base.clone();
        connect_block(&mut state, block, &params, NOW).expect("an unbent block is taken");
    }
    let corpus: Vec<Vec<u8>> = blocks.iter().map(Encode::encode).collect();
    let seed = campaign.seed();

    let mut as_sent = Tally::default();
    let mut resealed = Tally::default();
    let ran = campaign.run(2_000, |case, rng| {
        let from = rng.pick(&corpus).cloned().unwrap_or_default();
        let bytes = mutate(rng, &from, &corpus);
        let reseal = rng.bool();
        let tally = if reseal { &mut resealed } else { &mut as_sent };
        tally.bent += 1;
        let Ok(mut bent) = Block::decode(&bytes) else {
            return;
        };
        if reseal {
            bent.header.transactions_root = bent.transactions_root();
        }
        tally.decoded += 1;

        let mut state = base.clone();
        if let Err(refused) = connect_block(&mut state, &bent, &params, NOW) {
            *tally.refused.entry(kind_of(&refused)).or_default() += 1;
            assert!(
                fingerprint(&state) == before,
                "case {case} of seed {seed:#x}: a bent block was refused ({refused}) \
                 and the state it was offered to is not the state it was"
            );
            return;
        }
        tally.taken += 1;
        let header = &bent.header;
        assert_eq!(
            state.tip(),
            Some(Tip {
                id: bent.id(),
                height: header.height,
                timestamp: header.timestamp,
                total_work: header.total_work,
            }),
            "case {case} of seed {seed:#x}: a bent block was taken and the tip is not \
             its header"
        );
        assert_eq!(
            state.state_root(),
            header.state_root,
            "case {case} of seed {seed:#x}: a bent block was taken and the ledger is \
             not the one its header commits to"
        );
        let mut again = base.clone();
        connect_block(&mut again, &bent, &params, NOW).unwrap_or_else(|refused| {
            panic!(
                "case {case} of seed {seed:#x}: a bent block taken once was refused the \
                 second time, from the same state: {refused}"
            )
        });
        assert!(
            fingerprint(&again) == fingerprint(&state),
            "case {case} of seed {seed:#x}: the same bent block taken twice from the \
             same state left two different ledgers"
        );
    });

    as_sent.report("ledger: bent blocks as sent");
    resealed.report("ledger: bent blocks resealed");
    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    for (tally, what) in [(&as_sent, "as sent"), (&resealed, "resealed")] {
        assert!(
            tally.decoded.saturating_mul(1_000) >= tally.bent && tally.decoded > 0,
            "{} of {} bent blocks {what} decoded, so consensus was hardly asked anything",
            tally.decoded,
            tally.bent
        );
    }
    // The resealed arm is there to get past the transactions root and into
    // the rules about what a transfer spends. If none of its refusals is one
    // of those, it is not getting there.
    assert!(
        resealed.refused.contains_key("InvalidTransfer"),
        "no resealed block reached the rules about transfers: {:?}",
        resealed.refused
    );
}
