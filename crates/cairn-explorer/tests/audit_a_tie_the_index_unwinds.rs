//! What an ordinary reorganisation costs the explorer's index.
//!
//! Two miners finding a block at the same height is ordinary, and
//! `cairn-chain` says so at its tie rule: the split stands for one block
//! interval and then resolves. On the node that heard the loser first, that
//! resolution is a switch one block deep. The index answered every switch by
//! throwing itself away and reading every block the node holds again, off the
//! disk, while every page on the site said the index was partial. It now takes
//! back the blocks the switch undid and reads the ones it applied.
//!
//! Counted rather than timed: what a switch costs is how many blocks the walk
//! asks the node for, and every machine agrees on that number. And what it
//! leaves is compared, table by table, with an index that read the winning
//! branch from nothing, because a cheap unwind that leaves a note spent or an
//! owner paid is worse than the expensive rebuild it replaced.
//!
//! Blocks are built rather than mined. The index validates nothing, and what
//! is under test is what it does with a block, not whether the block is good.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code
)]

#[path = "../src/index.rs"]
mod index;

use std::cell::Cell;
use std::collections::HashMap;

use cairn_crypto::PublicKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::ConsensusParams;
use cairn_primitives::{Amount, Hash32};

use index::{
    read_to_the_end, Head, Held, Index, Reading, BYTES_PER_BLOCK, BYTES_PER_NOTE, UNDO_DEPTH,
};

/// A key for `seed`, and never the key for another seed.
fn key(seed: u64) -> PublicKey {
    let mut attempt = 0u64;
    loop {
        let mut hasher =
            cairn_primitives::hash::Hasher::new(cairn_primitives::hash::Domain::NoteKey);
        hasher.update(&seed.to_le_bytes());
        hasher.update(&attempt.to_le_bytes());
        if let Ok(found) = PublicKey::from_bytes(hasher.finalize().as_bytes()) {
            return found;
        }
        attempt += 1;
    }
}

fn finish(height: u64, coinbase: CoinbaseTransaction, transfers: Vec<Transfer>) -> Block {
    let params = ConsensusParams::testnet();
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            network: params.network,
            height,
            previous: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            state_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 1_000 + height,
            difficulty: 1,
            total_work: u128::from(height),
            nonce: height,
        },
        coinbase,
        transfers,
    };
    block.header.transactions_root = block.transactions_root();
    block
}

fn reward() -> Amount {
    ConsensusParams::testnet().initial_reward
}

/// A branch as the walk sees it: height to block.
#[derive(Clone)]
struct Branch {
    at: HashMap<u64, Block>,
}

impl Branch {
    fn tip(&self) -> u64 {
        self.at.keys().copied().max().unwrap_or(0)
    }

    fn id_at(&self, height: u64) -> Option<Hash32> {
        self.at.get(&height).map(Block::id)
    }

    fn held(&self, height: u64) -> Held {
        match self.at.get(&height) {
            Some(block) => Held::Block(Box::new(block.clone())),
            None => Held::Waiting,
        }
    }

    fn coinbase_note(&self, height: u64) -> NoteId {
        NoteId::new(self.at[&height].coinbase.id(), 0)
    }
}

/// `common` shared heights, then two branches of `own_a` and `own_b` heights
/// that part there.
///
/// Every height pays its miner. The shared part also moves money between
/// owners, so the branch that is undone has notes below it to spend. Each
/// branch then spends notes from under the fork, pays owners nobody else has
/// ever paid, and spends a note it made itself a block earlier: the three
/// things an undo has to take back, beside the blocks themselves.
fn two_branches(common: u64, own_a: u64, own_b: u64) -> (Branch, Branch) {
    let half = Amount::from_pebbles(reward().as_pebbles() / 2).unwrap();
    let mut shared = HashMap::new();
    for height in 0..common {
        let coinbase =
            CoinbaseTransaction::with_extra(height, vec![Note::new(reward(), key(0))], vec![0]);
        // At every odd height, the coinbase below is paid half to a holder of
        // the shared part and half back.
        let transfers = if height % 2 == 1 {
            let below: &Block = &shared[&(height - 1)];
            vec![Transfer::new(
                vec![Input::hot(NoteId::new(below.coinbase.id(), 0))],
                vec![Note::new(half, key(10)), Note::new(half, key(0))],
            )]
        } else {
            Vec::new()
        };
        shared.insert(height, finish(height, coinbase, transfers));
    }
    let shared = Branch { at: shared };

    let build = |tag: u64, own: u64| {
        let mut branch = shared.clone();
        let mut previous: Option<NoteId> = None;
        for step in 0..own {
            let height = common + step;
            let coinbase = CoinbaseTransaction::with_extra(
                height,
                vec![Note::new(reward(), key(tag))],
                vec![u8::try_from(tag).unwrap()],
            );
            let mut transfers = Vec::new();
            // A note from under the fork, so undoing the spend has to mark it
            // unspent again. The coinbases at odd heights are the ones the
            // shared part left unspent.
            let from_below = step * 2 + 1;
            if from_below < common {
                transfers.push(Transfer::new(
                    vec![Input::hot(shared.coinbase_note(from_below))],
                    vec![
                        Note::new(half, key(100 * tag + step)),
                        Note::new(half, key(tag)),
                    ],
                ));
            }
            // And the coinbase this branch made one block down, which only
            // this branch ever had.
            if let Some(note) = previous {
                transfers.push(Transfer::new(
                    vec![Input::hot(note)],
                    vec![Note::new(reward(), key(1_000 * tag + step))],
                ));
            }
            let block = finish(height, coinbase, transfers);
            previous = Some(NoteId::new(block.coinbase.id(), 0));
            branch.at.insert(height, block);
        }
        branch
    };
    let first = build(1, own_a);
    let second = build(2, own_b);
    assert_ne!(
        first.id_at(common),
        second.id_at(common),
        "the two branches part at the fork, or nothing below measures a switch"
    );
    (first, second)
}

/// One turn of the walk, driven the way `Explorer::read_a_batch` drives it,
/// counting every block the node is asked for.
fn a_turn(index: &mut Index, chain: &Branch, reads: &Cell<usize>) -> Reading {
    let head = Head {
        tip: chain.tip(),
        at_last_read: index.covers().and_then(|(_, through)| chain.id_at(through)),
    };
    index.refresh(
        &head,
        |height| {
            reads.set(reads.get() + 1);
            chain.held(height)
        },
        |height| chain.id_at(height),
        || Some(chain.tip()),
    )
}

fn read_level(index: &mut Index, chain: &Branch, reads: &Cell<usize>) {
    assert!(
        read_to_the_end(chain.tip(), || a_turn(index, chain, reads)),
        "the walk never said it had reached the tip"
    );
}

/// An index that read `chain` from nothing, which is what any other way of
/// arriving at the same branch has to be indistinguishable from.
fn fresh(chain: &Branch) -> Index {
    fresh_under(ConsensusParams::testnet(), chain)
}

/// The same, under `rules`.
fn fresh_under(rules: ConsensusParams, chain: &Branch) -> Index {
    let mut index = Index::under(rules);
    read_level(&mut index, chain, &Cell::new(0));
    index
}

/// Holds `index` to one that read `chain` from nothing, table by table.
fn same_as_fresh(index: &Index, chain: &Branch, what: &str) {
    same_as_fresh_under(ConsensusParams::testnet(), index, chain, what);
}

/// The same, for an index under `rules`.
fn same_as_fresh_under(rules: ConsensusParams, index: &Index, chain: &Branch, what: &str) {
    let fresh = fresh_under(rules, chain);
    assert_eq!(
        index.contents(),
        fresh.contents(),
        "{what}: the index that took the switch back says something about the \
         chain that an index which read the winning branch from nothing does not"
    );
    assert_eq!(
        (index.holders(), index.richest().to_vec()),
        (fresh.holders(), fresh.richest().to_vec()),
        "{what}: the table of the largest holders is still about the branch the \
         node left"
    );
}

/// Level with branch A, then switched to branch B: how many blocks the walk
/// asked for to follow the switch.
fn switch(first: &Branch, second: &Branch) -> (Index, usize) {
    switch_under(ConsensusParams::testnet(), first, second)
}

/// The same, for an index under `rules`.
fn switch_under(rules: ConsensusParams, first: &Branch, second: &Branch) -> (Index, usize) {
    let reads = Cell::new(0usize);
    let mut index = Index::under(rules);
    read_level(&mut index, first, &reads);
    assert_eq!(
        index.covers(),
        Some((0, first.tip())),
        "the walk is level with the branch it started on"
    );
    reads.set(0);
    read_level(&mut index, second, &reads);
    assert_eq!(
        index.covers(),
        Some((0, second.tip())),
        "the walk is level with the branch the node switched to"
    );
    (index, reads.get())
}

/// A one block tie costs the index the blocks the switch applied, and not the
/// chain.
///
/// The index threw itself away at any disagreement at the top of what it had
/// read, so the ordinary tie between two miners made it read every block the
/// node holds again, each one a seek and a decode off the disk, with every
/// page saying the index was partial for as long as it took. Nothing counted
/// the blocks a switch cost the walk: the tests of a reorganisation held that
/// the index ended on the right branch, which a rebuild from nothing does.
#[test]
fn a_one_block_tie_costs_the_index_the_blocks_it_applied_and_not_the_chain() {
    let (first, second) = two_branches(300, 1, 2);
    let (index, reads) = switch(&first, &second);
    assert_eq!(
        reads, 2,
        "a switch that undid one block and applied two made the walk ask for \
         {reads} blocks on a chain of 302; the two it applied are all it needs"
    );
    same_as_fresh(&index, &second, "one block undone");
}

/// A deeper switch, with spends on both sides of the fork, leaves the index
/// exactly as a fresh read of the winning branch would.
///
/// Undoing a block is where the new code can be wrong in ways a rebuild never
/// was: a note from under the fork left marked spent by a transfer that no
/// longer exists, an owner paid only on the losing branch left holding it, a
/// movement left on somebody's history. So the whole of it is compared.
#[test]
fn a_deeper_switch_is_taken_back_to_exactly_what_a_fresh_read_holds() {
    let (first, second) = two_branches(40, 20, 21);
    let (index, reads) = switch(&first, &second);
    assert_eq!(
        reads, 21,
        "the walk asked for the blocks the switch applied"
    );
    same_as_fresh(&index, &second, "twenty blocks undone");

    // And a switch back, onto the branch that lost, which is a shorter one.
    let reads = Cell::new(0usize);
    let mut index = index;
    read_level(&mut index, &first, &reads);
    assert_eq!(index.covers(), Some((0, first.tip())));
    assert_eq!(reads.get(), 20, "and back again costs the blocks applied");
    same_as_fresh(&index, &first, "switched back to a shorter branch");
}

/// A switch on a tier small enough for notes to fall every block leaves the
/// index's copy of the hot set, and what each block burned, exactly as a
/// fresh read of the winning branch would.
///
/// The copy moves on every block: the hot notes a block spent leave it, what
/// it made comes in, and the oldest fall out. Taking a block back has to put
/// every one of those back, and a note the block made and pushed straight out
/// is in two of the lists at once. A copy left wrong after a switch prices
/// every later spend of a fallen note as if it gave a place back, and every
/// block after says it destroyed the wrong amount.
#[test]
fn a_switch_takes_back_what_each_block_did_to_the_hot_set() {
    let rules = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_place_price(cairn_ledger::validation::PLACE_PRICE);
    let (first, second) = two_branches(40, 20, 21);
    let (index, reads) = switch_under(rules, &first, &second);
    assert_eq!(
        reads, 21,
        "the walk asked for the blocks the switch applied"
    );
    same_as_fresh_under(
        rules,
        &index,
        &second,
        "twenty blocks undone on a small tier",
    );
    assert!(
        index.burned().is_some_and(|burned| burned > Amount::ZERO),
        "fixture: the branches take places, so there is a burn to get wrong"
    );

    let reads = Cell::new(0usize);
    let mut index = index;
    read_level(&mut index, &first, &reads);
    same_as_fresh_under(rules, &index, &first, "switched back on a small tier");
}

/// A one block switch puts back every note the undone block took out of the
/// hot set, so the winning block's spends of them give their places back.
///
/// The block taken back spent a hot note and pushed two out; the block that
/// replaces it spends one of each. Read fresh, both were hot, so each of its
/// two spends takes one place. An index that took the block back and left
/// either note out of its copy of the tier reads that spend as one out of the
/// grace window, and says the block destroyed a place more than it did.
#[test]
fn a_switch_puts_back_the_notes_the_undone_block_took_out_of_the_hot_set() {
    let rules = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_place_price(cairn_ledger::validation::PLACE_PRICE);
    let one = |height: u64, tag: u8| {
        CoinbaseTransaction::with_extra(height, vec![Note::new(reward(), key(0))], vec![tag])
    };
    let mut shared = HashMap::new();
    for height in 0..4 {
        shared.insert(height, finish(height, one(height, 0), Vec::new()));
    }
    let shared = Branch { at: shared };
    let (pushed, spent) = (shared.coinbase_note(1), shared.coinbase_note(3));
    let half = Amount::from_pebbles(reward().as_pebbles() / 2).unwrap();
    let into_two = |note: NoteId, to: u64| {
        Transfer::new(
            vec![Input::hot(note)],
            vec![Note::new(half, key(to)), Note::new(half, key(to))],
        )
    };

    // The branch read first: one block spending a hot note and paying two,
    // which pushes the two oldest out.
    let mut first = shared.clone();
    first.at.insert(
        4,
        finish(
            4,
            CoinbaseTransaction::with_extra(
                4,
                vec![Note::new(half, key(1)), Note::new(half, key(1))],
                vec![1],
            ),
            vec![Transfer::new(
                vec![Input::hot(spent)],
                vec![Note::new(reward(), key(1))],
            )],
        ),
    );
    // The branch that wins: at the same height, a spend of a note the first
    // pushed out and of the note it spent, each into two, and one more block.
    let mut second = shared.clone();
    second.at.insert(
        4,
        finish(4, one(4, 2), vec![into_two(pushed, 2), into_two(spent, 3)]),
    );
    second.at.insert(5, finish(5, one(5, 2), Vec::new()));

    let (index, _) = switch_under(rules, &first, &second);
    same_as_fresh_under(rules, &index, &second, "one block undone on a tier of four");
    assert_eq!(
        index.burned_at(4),
        rules.burn_for(2),
        "the winning block's two spends of hot notes are said to burn other than a \
         place each"
    );
}

/// An index that did not read the chain from its first block says nothing
/// about what was burned, rather than a figure off an empty copy of the tier.
///
/// Its copy of the hot set starts with nothing in it, so every note spent
/// with a plain tag reads as one that had already fallen, and each block's
/// burn comes out as if no input gave a place back. Printed, that is a wrong
/// figure in the one column a reader has no other way to check.
#[test]
fn an_index_that_started_above_the_first_block_says_nothing_about_burns() {
    let rules = ConsensusParams::testnet()
        .with_hot_capacity(4)
        .with_place_price(cairn_ledger::validation::PLACE_PRICE);
    let (first, _) = two_branches(10, 4, 5);
    let mut index = Index::under(rules);
    let head = Head {
        tip: first.tip(),
        at_last_read: None,
    };
    let kept_from_three = |height: u64| {
        if height < 3 {
            Held::Dropped
        } else {
            first.held(height)
        }
    };
    assert!(read_to_the_end(first.tip(), || index.refresh(
        &head,
        kept_from_three,
        |height| first.id_at(height),
        || Some(first.tip())
    )));
    assert_eq!(
        index.covers(),
        Some((3, first.tip())),
        "fixture: a shorter index"
    );
    assert_eq!(
        index.burned(),
        None,
        "an index that started above the first block gave a total burned"
    );
    assert_eq!(
        index.burned_at(3),
        None,
        "an index that started above the first block gave a block's burn"
    );
}

/// A switch deeper than the index keeps the means to take back is read again
/// from the start, and still ends exactly where a fresh read does.
#[test]
fn a_switch_deeper_than_the_index_can_take_back_is_read_again() {
    let (first, second) = two_branches(10, 150, 151);
    let (index, reads) = switch(&first, &second);
    assert_eq!(
        reads, 161,
        "past what the index can take back, the whole branch is read again"
    );
    same_as_fresh(&index, &second, "a switch past the undo depth");
}

/// The deepest switch the index can take back is one block short of what it
/// keeps, and one deeper is read again.
///
/// Taking back a block leaves the one under it as the new top, so it has to
/// be one the index kept. Nothing held where the line falls, so an index that
/// kept one block fewer than it says passed every other test here.
#[test]
fn the_deepest_switch_taken_back_is_the_one_the_index_says() {
    let deepest = u64::try_from(UNDO_DEPTH).unwrap() - 1;
    let (first, second) = two_branches(10, deepest, deepest + 1);
    let (index, reads) = switch(&first, &second);
    assert_eq!(
        reads as u64,
        deepest + 1,
        "a switch {deepest} blocks deep was read again from the start"
    );
    same_as_fresh(&index, &second, "the deepest switch taken back");

    let (first, second) = two_branches(10, deepest + 1, deepest + 2);
    let (index, reads) = switch(&first, &second);
    assert_eq!(
        reads as u64,
        10 + deepest + 2,
        "a switch deeper than the index keeps was taken back all the same"
    );
    same_as_fresh(&index, &second, "one past the deepest");
}

/// A switch that lands inside a turn is taken back to where the branches
/// part and no further.
///
/// The check at the end of a turn finds the lowest height the turn read that
/// the branch no longer carries, and everything under it that the branch
/// still carries stays. Taking back one block more than that ends in the same
/// index, one block read again off a disk, so nothing that compared indexes
/// could see it; this counts the blocks.
#[test]
fn a_switch_inside_a_turn_is_taken_back_to_where_it_parted() {
    let (first, second) = two_branches(300, 1, 2);
    let reads = Cell::new(0usize);
    let mut index = Index::new();

    // Level with the shared part, one block short of its end.
    let short = Branch {
        at: first
            .at
            .iter()
            .filter(|(height, _)| **height <= 298)
            .map(|(height, block)| (*height, block.clone()))
            .collect(),
    };
    read_level(&mut index, &short, &reads);
    assert_eq!(index.covers(), Some((0, 298)));

    // The head is taken off A, the walk reads 299 and A's 300, and by the
    // time the turn ends the chain follows B.
    let head = Head {
        tip: first.tip(),
        at_last_read: first.id_at(298),
    };
    index.refresh(
        &head,
        |height| first.held(height),
        |height| second.id_at(height),
        || Some(second.tip()),
    );
    assert_eq!(
        index.covers(),
        Some((0, 299)),
        "the turn did not take back exactly the block the switch undid"
    );

    reads.set(0);
    read_level(&mut index, &second, &reads);
    assert_eq!(
        reads.get(),
        2,
        "the walk read more than the two blocks B applied"
    );
    same_as_fresh(&index, &second, "a switch inside a turn");
}

/// A head that disagrees with a chain that still carries every block read
/// takes nothing back.
///
/// The head is taken a moment before the turn, and the chain it was taken
/// from can have moved away and back since. The chain as it stands is what
/// decides how far to take back, and here it says nothing moved.
#[test]
fn a_head_that_disagrees_with_a_chain_that_does_not_takes_nothing_back() {
    let (first, _) = two_branches(40, 3, 4);
    let reads = Cell::new(0usize);
    let mut index = Index::new();
    read_level(&mut index, &first, &reads);
    reads.set(0);

    let head = Head {
        tip: first.tip(),
        at_last_read: Some(Hash32::ZERO),
    };
    index.refresh(
        &head,
        |height| {
            reads.set(reads.get() + 1);
            first.held(height)
        },
        |height| first.id_at(height),
        || Some(first.tip()),
    );
    assert_eq!(index.covers(), Some((0, first.tip())));
    assert_eq!(
        reads.get(),
        0,
        "a block the chain still carries was read again"
    );
    same_as_fresh(&index, &first, "a head that disagreed for a moment");
}

/// What the index says it costs counts the blocks it can find by identifier,
/// and a switch taken back takes them off again.
///
/// The table from identifier to height is new, and a table nothing counts is
/// the growing cost this index exists to publish rather than hide.
#[test]
fn what_the_index_costs_counts_its_blocks_as_well_as_its_notes() {
    let (first, second) = two_branches(10, 2, 3);
    let (index, _) = switch(&first, &second);
    let size = index.size();
    assert_eq!(
        size.blocks, 13,
        "the index does not count the blocks it keeps an identifier for, or kept \
         the ones the switch took back"
    );
    assert_eq!(
        size.bytes,
        size.notes * BYTES_PER_NOTE + size.blocks * BYTES_PER_BLOCK,
        "the bytes the index publishes leave out its blocks"
    );
}
