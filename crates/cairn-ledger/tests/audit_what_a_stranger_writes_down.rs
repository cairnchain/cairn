//! AUDIT: every field of a tip is a number a stranger writes down, so what does
//! each one cost to lie about?
//!
//! This is the question the sampling bound was broken by. `levels` was read off
//! `tip.height`, a height is not work, and the only rule tying the two together
//! priced an unopened run at one unit a block. Nobody had asked what the other
//! ten fields were worth, and the answer for one of them had been "almost
//! nothing" for six networks.
//!
//! So this asks it of all eleven, mechanically. For each field: change it,
//! re-mine the tip so its identifier meets its own target again, rebuild the
//! weighing honestly around the new tip, and record what refuses it. Re-mining
//! matters and is the half that is easy to skip: a forger who does not re-mine
//! is refused for a broken identifier whatever else it did, which is how
//! `adversarial_placement` spent a round reporting that every forgery was
//! caught.
//!
//! What comes out is a map rather than a verdict, and the map is the point: a
//! field nothing refuses is a field the weighing does not read, which may be
//! right and may be a hole, and either way is better written down than assumed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::print_stdout
)]

use cairn_accumulator::{Archive, Forest};
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::handover::{accept, Handover};
use cairn_ledger::note::Note;
use cairn_ledger::pow::RECENT_HEADERS;
use cairn_ledger::pow::{meets_target, DIFFICULTY_WINDOW};
use cairn_ledger::sampling::{
    check_start, covering, draw, levels_of, seed_of, work_before, Sample, SampledStart, StartError,
};
use cairn_ledger::state::header_leaf;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;
const COUNT: usize = 64;
/// Long enough that the draw has somewhere to land and the run up to the tip
/// is a real run, short enough that mining it is a second.
const HEIGHT: u64 = 300;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

/// A chain, and everything somebody who kept it can answer with.
struct Keeper {
    headers: Vec<BlockHeader>,
    before_tip: Archive,
}

impl Keeper {
    fn build(count: u64) -> Self {
        let params = params();
        let miner = SecretKey::from_bytes(&[1; 32]);
        let mut state = LedgerState::new();
        let mut headers = Vec::with_capacity(usize::try_from(count).unwrap());
        let mut clock = 1_000u64;

        for _ in 0..count {
            let height = state.next_height().unwrap();
            clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(params.initial_reward, miner.public_key())],
            );
            let block = assemble_block(&state, coinbase, Vec::<Transfer>::new(), &params, clock, 0)
                .unwrap();
            let block = mine_block(block, ATTEMPTS).unwrap();
            connect_block(&mut state, &block, &params, NOW).unwrap();
            headers.push(block.header);
        }

        let mut before_tip = Archive::new();
        for header in headers.iter().take(headers.len() - 1) {
            before_tip.add(header_leaf(&header.id()));
        }
        Self {
            headers,
            before_tip,
        }
    }

    fn tip(&self) -> BlockHeader {
        *self.headers.last().unwrap()
    }

    /// The best weighing that can be built around `tip`.
    ///
    /// The forest below a tip does not depend on the tip, so a forger that
    /// rewrites one field of its own tip still has every honest header under it
    /// to answer with. Only the draw moves, because the seed is the tip's
    /// identifier. This answers the new draw as well as the chain allows, which
    /// is what makes a refusal below a statement about the field rather than
    /// about a weighing built carelessly.
    fn open_around(&self, tip: BlockHeader, count: usize) -> SampledStart {
        let ledger: Vec<(u64, u128, u64)> = self
            .headers
            .iter()
            .rev()
            .map(|header| (header.height, header.total_work, header.difficulty))
            .collect();

        let samples: Vec<Sample> = draw(
            seed_of(&tip),
            count,
            work_before(&tip),
            levels_of(&tip, &params()),
        )
        .into_iter()
        .map(|work| {
            // The header that spans the value, or the deepest thing there is
            // when the tip's own arithmetic puts the draw somewhere no block
            // of this chain reaches.
            let height = covering(&ledger, work).unwrap_or(0);
            Sample {
                header: self.headers[usize::try_from(height).unwrap()],
                proof: self.before_tip.prove(height).unwrap(),
            }
        })
        .collect();

        let last = self.headers.len() - 1;
        let deepest = samples
            .iter()
            .map(|sample: &Sample| sample.header.height)
            .max()
            .unwrap_or(0);
        let from = usize::try_from(deepest.saturating_sub(DIFFICULTY_WINDOW as u64)).unwrap();
        // The run has to end at the tip actually offered, not at the one this
        // chain has, or every row below reads as a broken run.
        let mut tail = self.headers[from..last].to_vec();
        tail.push(tip);

        SampledStart {
            tip,
            tail,
            parent: Some(Sample {
                header: self.headers[last - 1],
                proof: self.before_tip.prove((last - 1) as u64).unwrap(),
            }),
            history: self.before_tip.forest().roots_only(),
            samples,
        }
    }
}

/// Nonces until the identifier meets the target again.
///
/// A forger that changes a field of its own tip has to pay for the tip again,
/// and that is the price this test wants out of the way: what is being measured
/// is what the rules refuse beyond the work, not the work.
fn re_mined(mut header: BlockHeader) -> BlockHeader {
    for nonce in 0..ATTEMPTS {
        header.nonce = nonce;
        if meets_target(&header.id(), header.difficulty) {
            return header;
        }
    }
    panic!("a header this cheap has a nonce");
}

/// What refuses a tip with one field rewritten, field by field.
///
/// Every row is a change a forger could really make, paid for with a fresh
/// identifier, answered by every honest header the chain has. What is pinned is
/// which rule catches it, so that a rule quietly ceasing to catch one of these
/// is a failing test rather than a discovery somebody makes later.
#[test]
fn every_field_of_a_tip_is_read_by_some_rule_or_named_as_read_by_none() {
    let keeper = Keeper::build(HEIGHT);
    let tip = keeper.tip();
    let params = params();

    check_start(&keeper.open_around(tip, COUNT), COUNT, NOW, &params)
        .expect("the honest chain has to pass, or every row below is meaningless");

    let rewritten = |what: &str, change: fn(&mut BlockHeader)| {
        let mut forged = tip;
        change(&mut forged);
        assert_ne!(forged, tip, "the change to {what} changed nothing");
        let forged = re_mined(forged);
        let refusal = check_start(&keeper.open_around(forged, COUNT), COUNT, NOW, &params);
        println!(
            "  {what:<19} {}",
            match &refusal {
                Ok(_) => "taken".to_owned(),
                Err(error) => format!("{error:?}")
                    .split_whitespace()
                    .next()
                    .unwrap_or("?")
                    .trim_end_matches('{')
                    .to_owned(),
            }
        );
        refusal.err()
    };

    println!("\n  What a rewritten field of the tip costs, once the work is paid again:\n");

    // The eight the weighing reads.
    assert!(matches!(
        rewritten("network", |h| h.network =
            cairn_ledger::note::NetworkId::DEVNET),
        Some(StartError::WrongNetwork { .. })
    ));
    assert!(matches!(
        rewritten("timestamp", |h| h.timestamp = NOW + 1_000_000),
        Some(StartError::TipFromTheFuture { .. })
    ));
    assert!(matches!(
        rewritten("height", |h| h.height += 1),
        Some(StartError::HistoryWrongLength { .. })
    ));
    assert!(matches!(
        rewritten("history", |h| h.history = Hash32::from_bytes([9; 32])),
        Some(StartError::HistoryMismatch)
    ));
    // Three fields, one rule. `check_the_parent` asks that the header below the
    // tip be at the height under it, be the one the tip names, carry real work,
    // sit in the tip's own history, and carry the work the tip's total leaves
    // for it. Rewriting the link, the difficulty or the total each breaks one
    // of those, and all three come back under the same name. That is worth
    // pinning rather than admiring: a weakening of this one check would take
    // three fields out of the weighing's reach at once, and nothing else here
    // would notice.
    for (what, change) in [
        (
            "previous",
            (|h: &mut BlockHeader| h.previous = Hash32::from_bytes([9; 32]))
                as fn(&mut BlockHeader),
        ),
        ("difficulty", |h: &mut BlockHeader| h.difficulty += 1),
        ("total_work", |h: &mut BlockHeader| h.total_work += 1),
    ] {
        assert!(
            matches!(
                rewritten(what, change),
                Some(StartError::ParentNotTheTipsOwn)
            ),
            "{what} is no longer read by the check that was reading it"
        );
    }
    assert!(matches!(
        rewritten("total_work (zero)", |h| h.total_work = 0),
        Some(StartError::TipClaimsNothing)
    ));

    // And the three it does not. Each is read by something else, and the point
    // of writing them down is that a reader of this exchange must not take them
    // as settled by it.
    let unread = [
        (
            "version",
            (|h: &mut BlockHeader| h.version += 1) as fn(&mut BlockHeader),
        ),
        ("transactions_root", |h: &mut BlockHeader| {
            h.transactions_root = Hash32::from_bytes([9; 32]);
        }),
        ("state_root", |h: &mut BlockHeader| {
            h.state_root = Hash32::from_bytes([9; 32]);
        }),
    ];
    for (what, change) in unread {
        assert!(
            rewritten(what, change).is_none(),
            "{what} is refused by the weighing after all, so the note below is wrong"
        );
    }

    println!(
        "\n  Eight of the eleven are refused, by six rules and not by eight: the parent\n  \
         check answers for three of them on its own, so it is the one piece of this\n  \
         exchange whose weakening would cost more than it looks. The nonce is the\n  \
         twelfth field and is meant to be free.\n\n  \
         Three are taken: the version, the transactions root and the state root. A\n  \
         weighing settles which chain is heaviest and nothing else, and each of those\n  \
         is read where it means something: the version and the transactions root when\n  \
         a block is connected, the state root when a ledger is handed over at an\n  \
         anchor a burial below the tip. What a reader of this exchange must not do is\n  \
         take any of the three as settled by it.\n"
    );
}

// ---------------------------------------------------------------------------
// The same question, asked of a handover.
// ---------------------------------------------------------------------------

/// The rules a handed ledger is judged under.
///
/// A short burial and a short maturity, because what is being measured is which
/// rule catches which field and not how long a wait is.
fn handover_rules() -> ConsensusParams {
    ConsensusParams {
        // Small enough that notes really fall to the cold set and the grace
        // window really carries proofs. The first version of this test left
        // both empty, so two of its thirteen rows rewrote a field that was
        // already what it was rewritten to and read the result as "taken".
        // A mutation that mutates nothing is the oldest way to measure nothing.
        hot_capacity: 16,
        max_evictions_per_block: 4,
        ..ConsensusParams::testnet()
            .with_burial(BURIAL)
            .with_coinbase_maturity(MATURITY)
    }
}

const BURIAL: u64 = 8;
const MATURITY: u64 = 4;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain, kept the way a node that has been running keeps one.
///
/// The ledger at every height is kept as well, which a real node does not need
/// to do: it rebuilds an old one by undoing blocks off the current one. Here
/// it is simply cheaper than writing that again.
struct Node {
    state: LedgerState,
    /// The ledger at each height.
    past: Vec<LedgerState>,
    /// And the block that produced it, so a newcomer can be given the ones it
    /// has to check for itself.
    blocks: Vec<Block>,
    /// Every header leaf, so this can prove where one sits. A real node reads
    /// that off its header log; here it is kept in memory.
    history: Archive,
    headers: Vec<BlockHeader>,
    clock: u64,
}

impl Node {
    fn new() -> Self {
        Self {
            state: LedgerState::archiving(),
            past: Vec::new(),
            blocks: Vec::new(),
            history: Archive::new(),
            headers: Vec::new(),
            clock: 1_000,
        }
    }

    fn mine(&mut self, miner: &SecretKey, transfers: Vec<Transfer>) -> Block {
        let params = handover_rules();
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block =
            assemble_block(&self.state, coinbase, transfers, &params, self.clock, 0).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        self.past.push(self.state.clone());
        self.blocks.push(block.clone());
        self.history
            .add(cairn_ledger::state::header_leaf(&block.header.id()))
            .unwrap();
        self.headers.push(block.header);
        block
    }

    fn mine_empty(&mut self, miner: &SecretKey, count: usize) {
        for _ in 0..count {
            self.mine(miner, Vec::new());
        }
    }

    /// What this node would hand to someone starting out.
    ///
    /// Never the ledger at the tip. One from `BURIAL` blocks below it, with
    /// the proof that it sits on the chain the tip ends.
    fn handover(&self) -> Handover {
        let tip = *self.headers.last().unwrap();
        let anchor_height = tip.height - BURIAL;
        let at = self.headers[anchor_height as usize];
        let state = &self.past[anchor_height as usize];
        let tip_history = self.state.headers_before_tip();
        let anchor = self
            .history
            .prove_in(anchor_height, tip.height)
            .expect("the header sits in the forest before the tip");
        let first = (anchor_height as usize + 1).saturating_sub(RECENT_HEADERS);
        state
            .handover(
                at,
                tip,
                tip_history,
                anchor,
                self.headers[(anchor_height as usize + 1)..].to_vec(),
                self.headers[first..=anchor_height as usize].to_vec(),
            )
            .expect("every note in the window has a path")
    }
}

/// A field of a handover and the change that rewrites it.
type Rewrite = (&'static str, fn(&mut Handover));

/// A hash nobody on this chain wrote.
fn stranger() -> Hash32 {
    Hash32::from_bytes([9; 32])
}

/// The same question, asked of every field of a handed ledger.
///
/// A weighing settles which chain is heaviest. A handover settles who owns
/// what, and it is the other half of joining: a newcomer takes it having
/// watched no transaction go past, so every field of it is a number a stranger
/// writes down and a reader has nothing of its own to compare against. Thirteen
/// fields, and the same mechanical question as above.
///
/// Nothing is re-mined here, because nothing in a handover is mined: what makes
/// one expensive is that the header it hangs off is `BURIAL` blocks below a tip
/// somebody had to keep mining over. So each row below is a change that costs a
/// forger nothing at all, which is the right way round: what is being measured
/// is what the rules refuse for free.
#[test]
fn every_field_of_a_handed_ledger_is_read_by_some_rule() {
    let params = handover_rules();
    let miner = wallet(1);
    let mut node = Node::new();
    node.mine_empty(&miner, RECENT_HEADERS + 40);

    let honest = node.handover();
    accept(&honest, &params).expect("the honest handover has to pass");

    let rewritten = |what: &str, change: fn(&mut Handover)| {
        let mut forged = honest.clone();
        change(&mut forged);
        assert_ne!(
            forged.encode(),
            honest.encode(),
            "the change to {what} changed nothing, so the row below measures nothing"
        );
        let refusal = accept(&forged, &params).err();
        println!(
            "  {what:<15} {}",
            refusal.as_ref().map_or_else(
                || "taken".to_owned(),
                |error| format!("{error:?}")
                    .split_whitespace()
                    .next()
                    .unwrap_or("?")
                    .trim_end_matches('{')
                    .to_owned()
            )
        );
        refusal
    };

    println!("\n  What a rewritten field of a handed ledger costs, and it costs no work:\n");

    let changes: [Rewrite; 13] = [
        ("at", |h| h.at.state_root = stranger()),
        ("tip", |h| h.tip.history = stranger()),
        ("tip_history", |h| h.tip_history = Forest::new()),
        ("anchor", |h| h.anchor.siblings.push(stranger())),
        ("hot", |h| {
            h.hot.pop();
        }),
        ("cold", |h| h.cold = Forest::new()),
        ("grace", |h| {
            h.grace.pop();
        }),
        ("grace_proofs", |h| {
            h.grace_proofs.pop();
        }),
        ("maturing", |h| {
            h.maturing.pop();
        }),
        ("supply", |h| h.supply = Amount::ZERO),
        ("headers", |h| h.headers = Forest::new()),
        ("buried", |h| {
            h.buried.pop();
        }),
        ("recent", |h| {
            h.recent.pop();
        }),
    ];

    let mut taken = Vec::new();
    for (what, change) in changes {
        if rewritten(what, change).is_none() {
            taken.push(what);
        }
    }
    assert!(
        taken.is_empty(),
        "a handed ledger takes {taken:?} rewritten, which is money somebody else \
         wrote down"
    );

    println!(
        "\n  Thirteen fields, thirteen refusals, and none of them cost the forger a\n  \
         hash: every one is caught by something the header already committed to or by\n  \
         the arithmetic of what the schedule can have paid.\n\n  \
         Six rules for thirteen fields, and the state root answers for five of them on\n  \
         its own. That is the same shape the weighing has, where the parent check\n  \
         answers for three: this exchange rests on a small number of load-bearing\n  \
         commitments, and which ones they are is what says where a weakening would\n  \
         cost more than it looks.\n"
    );
}
