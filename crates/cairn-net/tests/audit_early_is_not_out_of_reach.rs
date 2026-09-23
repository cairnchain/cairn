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
//! The floor is only reachable through that arm on a node whose branch begins
//! no further back than its own undo window, which is every node on a real
//! network and is why the burial here is the one the rules ship with. The
//! files that already greet foreign chains set it to eight for speed, which
//! puts the whole of the branch under `TooOld` and leaves this arm's floor
//! unreachable.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
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

    fn read_into_a_store(&self) -> ChainStore {
        let mut store = ChainStore::new(params());
        for block in &self.blocks {
            store.add_block(block.clone(), NOW).unwrap();
        }
        store
    }
}

/// Two blocks of one rival chain, either side of the floor, both refused for a
/// parent this node does not hold. Only one of them is a parent it can never
/// hold.
///
/// The floor and the depth a switch may reach are the same number on a node
/// that read its way up: the branch keeps `HELD_WINDOW` heights and
/// `undo_limit` is `MAX_REORG_DEPTH`, which is one less. So the floor is the
/// one height where `TooOld` does not answer first and this arm does, and that
/// is where the fixture stands.
#[test]
fn a_block_this_node_is_early_for_is_not_one_it_can_never_reach() {
    let mut ours = Chain::new();
    ours.run(&wallet(9), 1_100);
    let mut store = ours.read_into_a_store();
    let tip = store.height().expect("a chain to stand on");
    let floor = store
        .branch_start()
        .expect("a node holding a chain begins somewhere");
    assert!(
        floor > 0,
        "a chain longer than the window a switch may reach back over, or the          floor is the first block and the two questions never differ"
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

    let under = rival.blocks[usize::try_from(floor).unwrap()].clone();
    peer.awaiting.insert(under.header.height);
    let reaction = on_message(&mut local, &mut peer, Message::Block(Box::new(under)), NOW);
    assert_eq!(reaction.drop_peer, None, "the peer still did nothing wrong");
    assert_eq!(
        reaction.unreachable,
        Some(floor),
        "a block at the floor needs a parent under everything this node holds, \
         and nothing will ever put one there"
    );
}
