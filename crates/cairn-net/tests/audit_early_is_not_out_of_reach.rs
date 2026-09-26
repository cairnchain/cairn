//! Told apart: a block this node has not caught up to, and one it never can.
//!
//! `on_block` answers `UnknownParent` and `NotGenesis` by asking
//! `below_everything_held` whether waiting would fix it, and names the block
//! unreachable when it would not. The alarm means the node is somewhere it
//! cannot get back from, which is a thing an operator acts on.
//!
//! `after_the_anchor.rs::a_chain_forking_below_the_anchor_is_refused_and_now_says_so`
//! offers two thousand blocks of a foreign chain and asks that at least one be
//! named. That measures the alarm going off. Most of those blocks are refused
//! by `ForkTooDeep` or `TooOld`, whose arm names them whatever
//! `below_everything_held` answers, so the answer itself went unmeasured: read
//! as always true, as always false, or with its comparison turned around, that
//! test stays green.
//!
//! Always true is the reading that costs something. A block whose parent has
//! not arrived is what an ordinary sync looks like when blocks come out of
//! order, and an operator told the node is lost on every ordinary sync has
//! been told nothing.
//!
//! The floor is only reachable through that arm on a node handed a ledger,
//! whose branch begins at the headers it was handed with and whose window has
//! not yet opened past them. On a node that read its way up the branch begins
//! at the deepest block a switch could land on, and `TooOld` answers first for
//! that block and everything under it: it used to answer only under it, which
//! left the floor itself to this arm, and is why this fixture used to read
//! eleven hundred blocks.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::Note;
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::sync::{on_message, Local, PeerState};
use cairn_net::Keeps;
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

/// A chain mined on its own ledger, so its blocks exist without a node having
/// followed them.
struct Chain {
    state: LedgerState,
    blocks: Vec<Block>,
    clock: u64,
}

impl Chain {
    fn new() -> Self {
        Self {
            state: LedgerState::new(),
            blocks: Vec::new(),
            clock: 1_000,
        }
    }

    fn run(&mut self, miner: &SecretKey, count: usize) -> &mut Self {
        let rules = params();
        for _ in 0..count {
            let height = self.state.next_height().unwrap();
            self.clock += 600;
            let coinbase = CoinbaseTransaction::new(
                height,
                vec![Note::new(rules.initial_reward, miner.public_key())],
            );
            let block =
                assemble_block(&self.state, coinbase, Vec::new(), &rules, self.clock, 0).unwrap();
            connect_block(&mut self.state, &block, &rules, NOW).unwrap();
            self.blocks.push(block);
        }
        self
    }

    /// The same first block, and everything above it mined by somebody else.
    ///
    /// Sharing the first block is what lets this chain be greeted at all: a
    /// node that read its way up turns away a chain whose first block is not
    /// its own, so a wholly foreign one never reaches the question this file
    /// is about.
    fn forked_from(&self, miner: &SecretKey, count: usize) -> Self {
        let genesis = self.blocks[0].clone();
        let mut fork = Self::new();
        connect_block(&mut fork.state, &genesis, &params(), NOW).unwrap();
        fork.clock = genesis.header.timestamp;
        fork.blocks.push(genesis);
        fork.run(miner, count);
        fork
    }

    /// A node handed this chain's ledger at its tip, with the last `tail`
    /// headers, which is what a handover leaves a node holding.
    fn handed_to_a_store(&self, tail: usize) -> ChainStore {
        let recent: Vec<BlockHeader> = self.blocks[self.blocks.len() - tail..]
            .iter()
            .map(|block| block.header)
            .collect();
        let mut store = ChainStore::new(params());
        store.adopt(self.state.clone(), &recent).unwrap();
        store
    }
}

/// Blocks of one rival chain either side of the floor, all refused for a
/// parent this node does not hold. Only the ones at and under the floor are
/// waiting on a parent it can never hold.
///
/// On a node handed a ledger, a short way up a young chain, so no block here
/// is old enough for `TooOld` to answer first and this arm answers for all of
/// them.
#[test]
fn a_block_this_node_is_early_for_is_not_one_it_can_never_reach() {
    let mut ours = Chain::new();
    ours.run(&wallet(9), 40);
    let mut store = ours.handed_to_a_store(12);
    let tip = store.height().expect("a chain to stand on");
    let floor = store
        .branch_start()
        .expect("a node holding a chain begins somewhere");
    assert!(
        floor > 1,
        "a node handed its ledger above the first block, or the floor is the first \
         block and the two questions never differ"
    );

    let rival = ours.forked_from(&wallet(1), usize::try_from(tip).unwrap() + 8);

    let mut peer = PeerState::new(None);
    let mut local = Local {
        chain: &mut store,
        keeps: Keeps {
            headers: false,
            cold_set: false,
        },
        listen: 9_000,
        nonce: 7,
    };

    // Greeted and asked for, because a block from a stranger that has done
    // neither is refused for that before any of this is reached.
    let hello = Handshake {
        version: PROTOCOL_VERSION,
        network: params().network,
        genesis: ours.blocks[0].id(),
        tip: Hash32::ZERO,
        height: u64::try_from(rival.blocks.len()).unwrap() - 1,
        total_work: rival.state.total_work(),
        listen: 0,
        nonce: 11,
        keeps: Keeps::default(),
    };
    assert_eq!(
        on_message(&mut local, &mut peer, Message::Hello(hello), NOW).drop_peer,
        None,
        "a chain that begins where this one does is greeted"
    );

    let early = rival.blocks[usize::try_from(tip + 5).unwrap()].clone();
    peer.awaiting.insert(early.header.height);
    let reaction = on_message(&mut local, &mut peer, Message::Block(Box::new(early)), NOW);
    assert_eq!(reaction.drop_peer, None, "the peer did nothing wrong");
    assert!(reaction.applied.is_none(), "and nothing was applied");
    assert_eq!(
        reaction.unreachable, None,
        "a block above everything this node holds is one whose parent may yet \
         arrive, and naming it unreachable tells an operator the node is \
         somewhere it cannot get back from"
    );

    let above = rival.blocks[usize::try_from(floor + 1).unwrap()].clone();
    peer.awaiting.insert(above.header.height);
    let reaction = on_message(&mut local, &mut peer, Message::Block(Box::new(above)), NOW);
    assert_eq!(
        reaction.unreachable, None,
        "a block one above the floor hangs on a height this node holds, and may yet \
         arrive with its parent"
    );

    for at in [floor, floor - 1] {
        let under = rival.blocks[usize::try_from(at).unwrap()].clone();
        peer.awaiting.insert(under.header.height);
        let reaction = on_message(&mut local, &mut peer, Message::Block(Box::new(under)), NOW);
        assert_eq!(reaction.drop_peer, None, "the peer still did nothing wrong");
        assert_eq!(
            reaction.unreachable,
            Some(at),
            "a block at or under the floor needs a parent under everything this node \
             holds, and nothing will ever put one there"
        );
    }
}
