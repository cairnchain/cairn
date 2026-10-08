//! The fork choice on a tie in accumulated work.
//!
//! Two branches of exactly equal work are not ordered identically on every
//! node: each keeps the one that reached it first. That is a deliberate
//! choice. Breaking the tie on the lower identifier would settle it at once,
//! and costs more than it buys: a node catching up along a rival branch
//! passes through equal work on the way and would reorganise there, doing
//! extra rewinding to reach the same place one block later regardless.
//!
//! What this holds in place is the size of what that choice costs: the split
//! lasts one block interval, and the next block that extends either branch
//! ends it.
//!
//! Two tips of one height are a tie a little past equal work too: the branch
//! followed is kept unless the other carries more than half the followed
//! tip's difficulty in extra work. Under the retarget a block's difficulty
//! follows its parent's timestamp, so of two branches of one length forked
//! two or more blocks deep the earlier-dated one is heavier by a few percent
//! of a block, and switching on that surplus handed such races to whoever
//! dated its blocks earlier (T8-4). The band is held here to the unit, and so
//! is the rule that a branch of any other height is weighed by work alone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::ops::Range;

use cairn_chain::{Accepted, ChainStore};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, HeaderSummary};
use cairn_ledger::note::Note;
use cairn_ledger::pow::{median_time_past, next_difficulty};
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{
    assemble_block, connect_block, expected_difficulty, mine_block, ConsensusParams,
};
use cairn_ledger::LedgerState;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

#[derive(Clone)]
struct Forge {
    params: ConsensusParams,
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn new(params: ConsensusParams) -> Self {
        Self {
            params,
            state: LedgerState::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey) -> Block {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(self.params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).expect("a nonce exists");
        connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        block
    }

    fn mine_many(&mut self, miner: &SecretKey, count: usize) -> Vec<Block> {
        (0..count).map(|_| self.mine(miner)).collect()
    }

    fn fork(&self) -> Self {
        self.clone()
    }
}

/// Both branches are one block on the same parent, with the same timestamp and
/// so the same difficulty and the same work. They differ only in who mined
/// them. A node that saw A first keeps A; a node that saw B first keeps B.
/// Then one more block, and they agree again.
#[test]
fn an_equal_work_split_lasts_one_block_and_then_resolves() {
    let mut base = Forge::new(params());
    let common = base.mine_many(&wallet(1), 4);

    let mut forge_a = base.fork();
    let a = forge_a.mine(&wallet(2));
    let mut forge_b = base.fork();
    let b = forge_b.mine(&wallet(3));

    assert_ne!(a.id(), b.id(), "the two blocks must be genuinely different");
    assert_eq!(
        a.header.total_work, b.header.total_work,
        "the two branches carry exactly the same work"
    );

    // One node hears A, then B.
    let mut node_a = ChainStore::new(params());
    for block in &common {
        node_a.add_block(block.clone(), NOW).unwrap();
    }
    node_a.add_block(a.clone(), NOW).unwrap();
    node_a.add_block(b.clone(), NOW).unwrap();

    // Another hears B, then A.
    let mut node_b = ChainStore::new(params());
    for block in &common {
        node_b.add_block(block.clone(), NOW).unwrap();
    }
    node_b.add_block(b.clone(), NOW).unwrap();
    node_b.add_block(a.clone(), NOW).unwrap();

    assert_eq!(
        node_a.total_work(),
        node_b.total_work(),
        "both nodes carry the same work"
    );

    // Equal work is NOT ordered identically on every node: each keeps the
    // block that reached it first. That is a deliberate choice, not an
    // oversight, and what it costs is exactly this: for one block interval,
    // two honest nodes follow different tips.
    assert_ne!(
        node_a.tip(),
        node_b.tip(),
        "the split is the cost of keeping what arrived first"
    );

    // And what it must not cost is more than that interval. A block extending
    // either branch outweighs the other, and both nodes land on it.
    assert_eq!(node_a.tip(), Some(a.id()));
    assert_eq!(node_b.tip(), Some(b.id()));

    let after = forge_a.mine(&wallet(2));
    node_a.add_block(after.clone(), NOW).unwrap();
    node_b.add_block(after.clone(), NOW).unwrap();
    assert_eq!(
        node_a.tip(),
        node_b.tip(),
        "one more block and the two nodes agree again: a {:?} b {:?}",
        node_a.tip(),
        node_b.tip()
    );
    assert_eq!(
        node_b.tip(),
        Some(after.id()),
        "and it is the heavier branch"
    );
}

/// An opening difficulty at which one second of a parent's timestamp moves
/// the difficulty asked of the block after it by less than a unit, so that
/// every difficulty in reach is asked at some timestamp and a test can set a
/// surplus to the unit.
const OPENING: u64 = 1 << 11;

fn timed() -> ConsensusParams {
    ConsensusParams {
        genesis_difficulty: OPENING,
        ..params()
    }
}

/// A block on `state` dated `timestamp`, paying `miner`.
fn block_on(
    state: &LedgerState,
    params: &ConsensusParams,
    miner: &SecretKey,
    timestamp: u64,
) -> Block {
    let height = state.next_height().unwrap();
    let coinbase = CoinbaseTransaction::new(
        height,
        vec![Note::new(params.initial_reward, miner.public_key())],
    );
    let block = assemble_block(
        state,
        coinbase,
        Vec::<Transfer>::new(),
        params,
        timestamp,
        0,
    )
    .unwrap();
    mine_block(block, ATTEMPTS).expect("a nonce exists")
}

/// `block` on `state`, and the ledger it leaves.
fn after(state: &LedgerState, params: &ConsensusParams, block: &Block) -> LedgerState {
    let mut state = state.clone();
    connect_block(&mut state, block, params, NOW).unwrap();
    state
}

/// Six blocks dated on the schedule from the first, and the ledger they
/// leave.
fn on_schedule(params: &ConsensusParams) -> (Vec<Block>, LedgerState) {
    let mut state = LedgerState::new();
    let mut blocks = Vec::new();
    for height in 0..6 {
        let block = block_on(&state, params, &wallet(1), height * 60);
        state = after(&state, params, &block);
        blocks.push(block);
    }
    (blocks, state)
}

/// The earliest timestamp in `range` at which a parent at `height` carrying
/// `difficulty` asks exactly `wanted` of the block after it.
fn dated_for(
    params: &ConsensusParams,
    height: u64,
    difficulty: u64,
    wanted: u64,
    range: Range<u64>,
) -> u64 {
    range
        .clone()
        .find(|timestamp| {
            let parent = HeaderSummary {
                height,
                timestamp: *timestamp,
                difficulty,
            };
            next_difficulty(&parent, params.origin(), params.target_block_time) == wanted
        })
        .unwrap_or_else(|| panic!("no timestamp in {range:?} asks for {wanted}"))
}

/// A node that has taken `blocks` in order.
fn node_after(params: ConsensusParams, blocks: &[&Block]) -> ChainStore {
    let mut node = ChainStore::new(params);
    for block in blocks {
        node.add_block((*block).clone(), NOW).unwrap();
    }
    node
}

/// The fixture the band is measured on: six blocks on the schedule, and a
/// followed branch of two more whose first is dated late, so its tip is
/// asked well under the opening difficulty.
struct Race {
    params: ConsensusParams,
    base: Vec<Block>,
    state: LedgerState,
    followed: [Block; 2],
}

impl Race {
    const LATE: u64 = 3_000;

    fn new() -> Self {
        let params = timed();
        let (base, state) = on_schedule(&params);
        let first = block_on(&state, &params, &wallet(2), Self::LATE);
        let second = block_on(
            &after(&state, &params, &first),
            &params,
            &wallet(2),
            Self::LATE + 60,
        );
        Self {
            params,
            base,
            state,
            followed: [first, second],
        }
    }

    fn tip(&self) -> &Block {
        &self.followed[1]
    }

    /// Half the followed tip's difficulty, the most extra work a rival of
    /// its height can carry and still be a tie.
    fn band(&self) -> u64 {
        self.tip().header.difficulty / 2
    }

    /// The first timestamp a block on the fork point may carry.
    fn earliest(&self) -> u64 {
        median_time_past(self.state.recent_headers()).unwrap() + 1
    }

    /// A node that has followed the branch, block by block.
    fn node(&self) -> ChainStore {
        let blocks: Vec<&Block> = self.base.iter().chain(&self.followed).collect();
        node_after(self.params, &blocks)
    }

    /// A rival of the followed tip's height, carrying exactly `surplus` more
    /// work: its first block is dated earlier, so its second is asked more.
    fn rival_of_its_height(&self, surplus: u64) -> [Block; 2] {
        let params = &self.params;
        let fork = self.state.tip().unwrap();
        let wanted = self.tip().header.difficulty + surplus;
        let opening = expected_difficulty(&self.state, params);
        let dated = dated_for(
            params,
            fork.height + 1,
            opening,
            wanted,
            self.earliest()..Self::LATE,
        );
        let first = block_on(&self.state, params, &wallet(3), dated);
        let second = block_on(
            &after(&self.state, params, &first),
            params,
            &wallet(3),
            Self::LATE + 60,
        );
        assert_eq!(
            second.header.total_work - self.tip().header.total_work,
            u128::from(surplus),
            "fixture: the rival carries the surplus asked for"
        );
        [first, second]
    }
}

/// **Two tips of one height are a tie until one carries more than half the
/// followed tip's difficulty in extra work.**
///
/// The rival is built to carry exactly half the tip's difficulty more, which
/// is kept aside, and then one unit more, which is taken.
#[test]
fn two_tips_of_one_height_are_a_tie_until_one_carries_half_a_block_more() {
    let race = Race::new();
    let band = race.band();
    assert!(
        band > 100,
        "fixture: a band of {band} units leaves room on both sides of it"
    );

    for (surplus, taken) in [(1, false), (band, false), (band + 1, true)] {
        let rival = race.rival_of_its_height(surplus);
        let mut node = race.node();
        assert_eq!(
            node.add_block(rival[0].clone(), NOW).unwrap(),
            Accepted::SideBranch
        );
        let answer = node.add_block(rival[1].clone(), NOW).unwrap();
        if taken {
            assert!(
                matches!(answer, Accepted::Reorganised { .. }),
                "a rival of the tip's height {surplus} heavier, past half its difficulty \
                 {band}, was answered {answer:?}"
            );
            assert_eq!(node.tip(), Some(rival[1].id()));
        } else {
            assert_eq!(
                answer,
                Accepted::SideBranch,
                "a rival of the tip's height {surplus} heavier, within half its difficulty \
                 {band}, was not kept aside"
            );
            assert_eq!(node.tip(), Some(race.tip().id()));
        }
    }
}

/// **A rival one block longer is taken on any surplus of work, even one a
/// rival of the tip's own height would be kept aside for.**
///
/// The band is about two tips of one height and nothing else. The rival here
/// is three blocks to the followed branch's two, dated late so that it
/// carries exactly half the tip's difficulty more in all, which at the tip's
/// height would be a tie.
#[test]
fn a_longer_rival_is_taken_on_any_surplus() {
    let race = Race::new();
    let params = &race.params;
    let band = race.band();

    // The followed branch is dated late, so its tip is light; the rival's
    // first block is dated later still, so the two blocks above it together
    // can come to the followed tip and the band, to the unit.
    let first = block_on(&race.state, params, &wallet(4), Race::LATE + 1_200);
    let on_first = after(&race.state, params, &first);
    let second_difficulty = expected_difficulty(&on_first, params);
    let wanted = race.tip().header.difficulty + band - second_difficulty;
    let dated = dated_for(
        params,
        first.header.height + 1,
        second_difficulty,
        wanted,
        race.earliest()..Race::LATE * 4,
    );
    let second = block_on(&on_first, params, &wallet(4), dated);
    let third = block_on(
        &after(&on_first, params, &second),
        params,
        &wallet(4),
        Race::LATE * 4,
    );
    assert_eq!(
        third.header.height,
        race.tip().header.height + 1,
        "fixture: the rival is one block longer"
    );
    assert_eq!(
        third.header.total_work - race.tip().header.total_work,
        u128::from(band),
        "fixture: the rival carries half the tip's difficulty more"
    );

    let mut node = race.node();
    for block in [&first, &second] {
        assert_eq!(
            node.add_block(block.clone(), NOW).unwrap(),
            Accepted::SideBranch,
            "fixture: the rival's lower blocks are lighter than the tip"
        );
    }
    let answer = node.add_block(third.clone(), NOW).unwrap();
    assert!(
        matches!(answer, Accepted::Reorganised { .. }),
        "a rival one block longer and {band} heavier was answered {answer:?}"
    );
    assert_eq!(node.tip(), Some(third.id()));
}

/// **The fork choice, asked directly, over a table of rivals around one
/// tip.**
///
/// The one question every comparison on a node asks, `cairn-net`'s included:
/// the tip's height and the band at it, and work everywhere else. Equal work
/// is never taken at any height, more work always is at any other height,
/// and at the tip's height only past half its difficulty.
#[test]
fn the_fork_choice_over_rivals_around_one_tip() {
    let race = Race::new();
    let node = race.node();
    let height = race.tip().header.height;
    let work = race.tip().header.total_work;
    let band = u128::from(race.band());
    let table = [
        (height, work - 1, false),
        (height, work, false),
        (height, work + 1, false),
        (height, work + band, false),
        (height, work + band + 1, true),
        (height + 1, work - 1, false),
        (height + 1, work, false),
        (height + 1, work + 1, true),
        (height - 1, work, false),
        (height - 1, work + 1, true),
        (height + 5, work + band * 8, true),
    ];
    for (rival_height, rival_work, taken) in table {
        assert_eq!(
            node.outweighed_by(rival_height, rival_work),
            taken,
            "a rival at height {rival_height} worth {rival_work}, against a tip at {height} \
             worth {work} with a band of {band}"
        );
    }

    let empty = ChainStore::new(race.params);
    assert!(
        empty.outweighed_by(0, 1),
        "a node holding nothing takes any work"
    );
    assert!(
        !empty.outweighed_by(0, 0),
        "a node holding nothing takes no branch carrying none"
    );
}

/// Text with every run of whitespace made one space and the comment markers
/// of a Rust source left out, so that a phrase is found however it was
/// wrapped.
fn flat(text: &str) -> String {
    text.split_whitespace()
        .filter(|word| !matches!(*word, "///" | "//!" | "//"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The site states the fork choice in four strings, two in each language, and
/// the band reached the four documents and none of them: the site said ties
/// keep the followed branch and nothing of the rival of the tip's height that
/// carries up to half a block more, which is the whole of the band. So every
/// place a file says ties keep the followed branch, it says the band with it.
#[test]
fn the_site_states_the_band_wherever_it_states_the_tie() {
    for (name, text, tie, band) in [
        (
            "the site",
            include_str!("../../../web/i18n/en.json"),
            "Ties keep the branch already followed",
            "Ties keep the branch already followed, and two tips of one height are a tie until \
             one carries more than half a block of extra work.",
        ),
        (
            "le site",
            include_str!("../../../web/i18n/fr.json"),
            "la branche déjà suivie est conservée",
            "la branche déjà suivie est conservée, et deux pointes de même hauteur sont à égalité \
             tant que l'une ne porte pas plus d'un demi-bloc de travail en plus.",
        ),
    ] {
        let text = flat(text);
        assert_eq!(
            text.matches(band).count(),
            2,
            "{name} does not state the band in both places it states the fork choice"
        );
        assert_eq!(
            text.matches(tie).count(),
            text.matches(band).count(),
            "{name} says a tie keeps the followed branch somewhere without the band"
        );
    }
}

/// The documents say a branch dated earlier weighs "a little more", and that
/// within the band a race goes to the block heard first. Both are exact for
/// branches dated by their clocks and below seven blocks: a branch dated one
/// second past its own median every block carries 0.480 of the honest tip's
/// difficulty more at six blocks deep and 0.615 at seven, and is taken by a
/// node that heard the honest branch first, though the dating costs the
/// withholder more than the matches return (G1-3 of the testnet-9 audit). So
/// every place that states the lean says where it stops.
#[test]
fn every_place_that_states_the_lean_says_where_it_stops() {
    for (name, text, stated) in [
        (
            "lib.rs",
            include_str!("../src/lib.rs"),
            "a withholder that dates its blocks as early as the median allows takes matches \
             seven or more blocks deep, and loses more to the difficulty than it gains",
        ),
        (
            "the specification",
            include_str!("../../../docs/cairn-specification.md"),
            "a withholder that dates its blocks as early as the median allows takes matches \
             seven or more blocks deep, and loses more to the difficulty than it gains.",
        ),
        (
            "the threat model",
            include_str!("../../../docs/cairn-threat-model.md"),
            "A withholder that dates its blocks as early as the median allows takes matches \
             seven or more blocks deep, and loses more to the difficulty than it gains.",
        ),
        (
            "the whitepaper",
            include_str!("../../../docs/cairn-whitepaper.md"),
            "a withholder that dates its blocks as early as the median allows takes matches \
             seven or more blocks deep, and loses more to the difficulty than it gains.",
        ),
        (
            "the design document",
            include_str!("../../../docs/cairn-design.md"),
            "un mineur qui date ses blocs aussi tôt que la médiane le permet emporte les courses \
             de sept blocs ou plus, et y perd en difficulté plus qu'il n'y gagne.",
        ),
    ] {
        assert!(
            flat(text).contains(stated),
            "{name} states the lean of an earlier-dated branch without saying where it stops: \
             \"{stated}\""
        );
    }
}
