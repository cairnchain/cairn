//! A newcomer among peers that claim far more chain than they can show.
//!
//! Red team scenario R7 of the testnet-8 attack catalogue (C10). A node with
//! no chain asks the heaviest claim first, and a claim is a number in a
//! greeting. Strangers that claim enormous chains and never answer each cost
//! the newcomer one answering window before it gets to the honest peer. The
//! catalogue passes the scenario if the newcomer adopts the honest chain within
//! fifteen minutes and never adopts a lighter one.
//!
//! Two halves, because the loopback cannot carry the second.
//!
//! The first runs real nodes over the loopback: an honest peer, a peer with a
//! real but lighter chain, and strangers claiming two to the hundred units of
//! work that never answer. It measures what the node does: a window per
//! silent claim, one after another, the honest chain adopted only once every
//! heavier claim was asked, and the lighter chain never. Measured: two silent
//! claims cost sixty two seconds, the two of settling and thirty each, and the
//! strangers are kept afterwards, no longer believed rather than dropped.
//!
//! The second is about what a stranger has to spend for those windows, which
//! the module states in so many words: a failed claim pauses the address it
//! came from, the pause doubles with each further failure, and so "a turn now
//! costs a stranger an address it has not already spent". The loopback is
//! exempt from the pause, deliberately, since every node of a devnet wears it,
//! so that half is measured on the chooser itself with a clock it is handed,
//! as `tests/audit_owed_a_turn.rs` measures it.
//!
//! **The second half does not hold.** The pause doubles up to `MAX_HELD_OFF`,
//! half an hour, and stops there. A stranger whose addresses take longer than
//! that to go round once, at one answering window each, finds the first of
//! them out of its pause by the time the last has failed, and goes round
//! again for ever without a fresh address. Measured below with no more
//! connections than a node takes from outside: twenty addresses dialling back
//! cost a newcomer thirty five minutes, and from sixty two the honest peer
//! standing there the whole time is never asked at all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use cairn_chain::ChainStore;
use cairn_crypto::SecretKey;
use cairn_ledger::block::Block;
use cairn_ledger::note::Note;
use cairn_ledger::transaction::{CoinbaseTransaction, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, mine_block, ConsensusParams};
use cairn_ledger::LedgerState;
use cairn_net::choosing::{Chooser, JoinProgress, Step};
use cairn_net::message::{Handshake, Message, PROTOCOL_VERSION};
use cairn_net::node::MOST_FROM_OUTSIDE;
use cairn_net::sync::JOIN_RATHER_THAN_READ;
use cairn_net::wire::{read_message, write_message, Incoming, MAX_FRAME_BYTES};
use cairn_net::{Keeps, Node};
use cairn_primitives::Hash32;

const NOW: u64 = 2_000_000_000;
const ATTEMPTS: u64 = 1 << 22;

/// `choosing::SETTLING` and `choosing::FIRST_ANSWER_PATIENCE`, which are not
/// public. Restated, as `tests/audit_owed_a_turn.rs` restates the second.
const SETTLING: u64 = 2;
const FIRST_ANSWER: u64 = 30;

/// `choosing::MAX_HELD_OFF` and the start of the doubling under it, for the
/// stranger's side of the model: it knows the code it is attacking.
const MAX_HELD_OFF: u64 = 1_800;
const RETRY_PAUSE: u64 = 30;

/// The catalogue's pass line for R7.
const CATALOGUE_LINE: Duration = Duration::from_secs(15 * 60);

/// Liveness bound for anything this file waits on that is not the
/// measurement. Costs nothing when the condition is met.
const PATIENCE: Duration = Duration::from_secs(300);

/// Silent strangers in the run over sockets. Each costs a window, so two keep
/// the run near a minute and still show the windows adding up.
const SILENT: usize = 2;

/// What the strangers claim: two to the hundred units of work behind a chain
/// long enough that only a weighing and a handover would take it, which is
/// what opens the choice in the first place.
const CLAIMED_WORK: u128 = 1 << 100;
const CLAIMED_HEIGHT: u64 = JOIN_RATHER_THAN_READ + 976;

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn wait_until(patience: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// Builds blocks off to the side, as `tests/network.rs` does. Two forges
/// started at different moments build two different chains.
struct Forge {
    state: LedgerState,
    clock: u64,
}

impl Forge {
    fn starting_at(clock: u64) -> Self {
        Self {
            state: LedgerState::new(),
            clock,
        }
    }

    fn mine(&mut self) -> Block {
        let params = params();
        let miner = SecretKey::from_bytes(&[1; 32]);
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let coinbase = CoinbaseTransaction::new(
            height,
            vec![Note::new(params.initial_reward, miner.public_key())],
        );
        let block = assemble_block(
            &self.state,
            coinbase,
            Vec::<Transfer>::new(),
            &params,
            self.clock,
            0,
        )
        .unwrap();
        let block = mine_block(block, ATTEMPTS).unwrap();
        connect_block(&mut self.state, &block, &params, NOW).unwrap();
        block
    }
}

fn node_with(blocks: usize, clock: u64) -> Node {
    let mut forge = Forge::starting_at(clock);
    let node = Node::bind(params(), loopback()).unwrap();
    for _ in 0..blocks {
        node.submit_block(forge.mine()).unwrap();
    }
    node
}

/// A stranger that dials in, claims a chain it does not have, answers the
/// requests for addresses that keep a connection alive, and nothing else.
struct Claimant {
    /// When it was introduced, and when it was asked to show its chain.
    welcomed: Arc<Mutex<Option<Instant>>>,
    asked: Arc<Mutex<Vec<Instant>>>,
    open: Arc<AtomicBool>,
    socket: TcpStream,
}

impl Claimant {
    fn dial(newcomer: SocketAddr, nonce: u64) -> Self {
        let network = params().network;
        let mut socket = TcpStream::connect(newcomer).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let hello = Message::Hello(Handshake {
            version: PROTOCOL_VERSION,
            network,
            genesis: Hash32::ZERO,
            height: CLAIMED_HEIGHT,
            total_work: CLAIMED_WORK,
            listen: 0,
            nonce,
            keeps: Keeps {
                headers: true,
                cold_set: false,
            },
        });
        write_message(&mut socket, network, &hello).unwrap();
        let welcomed = Arc::new(Mutex::new(None));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let open = Arc::new(AtomicBool::new(true));
        {
            let mut socket = socket.try_clone().unwrap();
            let welcomed = Arc::clone(&welcomed);
            let asked = Arc::clone(&asked);
            let open = Arc::clone(&open);
            thread::spawn(move || loop {
                let message = match read_message(&mut socket, network, MAX_FRAME_BYTES) {
                    Ok(Incoming::Message(message)) => message,
                    Ok(Incoming::Quiet) => continue,
                    Err(_) => {
                        open.store(false, Ordering::SeqCst);
                        return;
                    }
                };
                let answer = match message {
                    Message::Welcome(_) => {
                        *welcomed.lock().unwrap() = Some(Instant::now());
                        None
                    }
                    Message::GetPeers => Some(Message::Peers(Vec::new())),
                    Message::Ping(nonce) => Some(Message::Pong(nonce)),
                    Message::GetJoin { .. } | Message::GetChain { .. } => {
                        asked.lock().unwrap().push(Instant::now());
                        None
                    }
                    _ => None,
                };
                if let Some(answer) = answer {
                    if write_message(&mut socket, network, &answer).is_err() {
                        open.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            });
        }
        Self {
            welcomed,
            asked,
            open,
            socket,
        }
    }

    /// The first and last time it was asked to show its chain before
    /// `moment`. The node asks again inside one turn, because the first
    /// question is the one most easily dropped, so a turn is a run of asks
    /// and not one.
    fn turn_before(&self, moment: Instant) -> Option<(Instant, Instant)> {
        let asked = self.asked.lock().unwrap();
        let before: Vec<Instant> = asked.iter().copied().filter(|at| *at <= moment).collect();
        Some((*before.first()?, *before.last()?))
    }
}

impl Drop for Claimant {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

/// **Over real sockets: each claim nobody shows costs a newcomer one
/// answering window, the honest chain is adopted once every heavier claim has
/// been asked, and the lighter chain beside it never is.**
#[test]
fn a_newcomer_asks_every_heavier_claim_once_and_then_takes_the_honest_chain() {
    let honest = node_with(6, 1_000);
    let lighter = node_with(3, 5_000_000);
    assert!(
        lighter.total_work() < honest.total_work(),
        "the fixture: the second chain is the lighter one"
    );
    let honest_tip = honest.with_chain(ChainStore::tip).unwrap();
    let lighter_first = lighter.id_at(0).unwrap();

    let newcomer = Node::bind(params(), loopback()).unwrap();
    // The strangers first, so their claims stand before any chain arrives:
    // a node with a chain of its own is past choosing, and the honest peer
    // answers a greeting with its chain at once.
    let strangers: Vec<Claimant> = (0..SILENT)
        .map(|at| Claimant::dial(newcomer.address(), 0xc1a1_0000 + at as u64))
        .collect();
    assert!(
        wait_until(PATIENCE, || strangers.iter().all(|stranger| stranger
            .welcomed
            .lock()
            .unwrap()
            .is_some())),
        "every stranger was taken in, so every claim is written down"
    );
    let claimed_at = Instant::now();
    newcomer.connect(honest.address()).unwrap();
    newcomer.connect(lighter.address()).unwrap();

    let mut took_the_lighter = false;
    let adopted = wait_until(PATIENCE, || {
        if newcomer.id_at(0) == Some(lighter_first) {
            took_the_lighter = true;
        }
        newcomer.with_chain(ChainStore::tip) == Some(honest_tip)
    });
    let waited = claimed_at.elapsed();
    let adopted_at = Instant::now();
    assert!(
        adopted,
        "the newcomer never took the honest chain in {PATIENCE:?}"
    );
    assert!(!took_the_lighter, "the newcomer followed the lighter chain");

    let mut asks = Vec::new();
    for stranger in &strangers {
        let times: Vec<f64> = stranger
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|at| at.saturating_duration_since(claimed_at).as_secs_f64())
            .collect();
        asks.push(times);
    }
    println!(
        "{SILENT} silent claims: honest chain adopted after {:.1}s (model: {}s settling and \
         {FIRST_ANSWER}s a claim); strangers asked at {asks:?} seconds",
        waited.as_secs_f64(),
        SETTLING
    );
    for (at, stranger) in strangers.iter().enumerate() {
        let Some((first, last)) = stranger.turn_before(adopted_at) else {
            panic!(
                "stranger {at} was never asked, and the newcomer took a lighter chain while \
                 a heavier claim stood unexamined"
            );
        };
        // Two seconds past the window for a round of upkeep that runs late:
        // a second turn would start a whole window after the first ended.
        let span = last.saturating_duration_since(first);
        assert!(
            span <= Duration::from_secs(FIRST_ANSWER + 2),
            "stranger {at} was asked over {span:?}, more than one turn: a claim that failed \
             was waited on twice"
        );
    }
    assert!(
        waited < CATALOGUE_LINE,
        "{SILENT} silent claims kept the newcomer off the honest chain for {waited:?}"
    );

    // What becomes of the strangers once the choice is made. Not a claim the
    // code makes either way, so printed rather than held.
    thread::sleep(Duration::from_secs(3));
    let still_open = strangers
        .iter()
        .filter(|stranger| stranger.open.load(Ordering::SeqCst))
        .count();
    let asked_since: usize = strangers
        .iter()
        .map(|stranger| {
            stranger
                .asked
                .lock()
                .unwrap()
                .iter()
                .filter(|at| **at > adopted_at)
                .count()
        })
        .sum();
    println!(
        "after the choice: {still_open} of {SILENT} strangers still connected, asked for \
         their chain {asked_since} more time(s)"
    );

    drop(strangers);
    newcomer.shutdown();
    lighter.shutdown();
    honest.shutdown();
}

// ---------------------------------------------------------------------------
// What the windows cost the stranger.
// ---------------------------------------------------------------------------

fn host(index: u64) -> IpAddr {
    let bytes = index.to_be_bytes();
    IpAddr::V4(Ipv4Addr::new(203, 0, bytes[6], bytes[7]))
}

/// How long the chooser leaves an address alone after `failures` claims of
/// its went unshown: `choosing::held_off_for`, as the stranger reads it.
fn pause_after(failures: u32) -> u64 {
    let steps = failures.saturating_sub(1).saturating_mul(2);
    RETRY_PAUSE
        .checked_shl(steps)
        .unwrap_or(MAX_HELD_OFF)
        .min(MAX_HELD_OFF)
}

/// One stranger address, as the stranger keeps track of it.
enum Seat {
    /// Connected, under this peer number, and asked to show its chain at this
    /// moment if it has been.
    Holding(u64, Option<u64>),
    /// Hung up after a claim failed, waiting out the pause it knows that
    /// earned.
    Away { back_at: u64 },
}

/// A newcomer beside one honest peer with a chain it can show, and a stranger
/// with `hosts` addresses it reuses and never adds to.
///
/// Each stranger connection claims far more than the honest chain, goes quiet
/// when asked, and hangs up once its answering window is spent. The address
/// dials back when its pause is over, and not before, so it never wastes a
/// claim inside one; and the stranger never holds more connections at once
/// than a node takes from outside, which is the most a real one could hold.
///
/// With `dial_back` false an address that failed stays away, which is the
/// catalogue's own arrangement: strangers that claim once each and are done.
///
/// Returns how long until the newcomer commits, and how many times the honest
/// peer was asked.
fn against_reused_addresses(hosts: u64, dial_back: bool, watch: u64) -> (Option<u64>, u32) {
    let mut chooser = Chooser::new();
    let start = 100u64;
    let long = JOIN_RATHER_THAN_READ + 10;
    chooser.noted(1, Some(host(1)), 1_000, long, true, start);
    let mut connected: Vec<u64> = vec![1];
    let mut next_id = 50u64;
    let mut failures: BTreeMap<u64, u32> = BTreeMap::new();
    let mut seats: BTreeMap<u64, Seat> = (0..hosts)
        .map(|index| (20 + index, Seat::Away { back_at: start }))
        .collect();

    let mut now = start;
    let mut asked_honest = 0u32;
    for _ in 0..watch {
        // Addresses whose pause is over dial back, while there is room.
        let holding = seats
            .values()
            .filter(|seat| matches!(seat, Seat::Holding(..)))
            .count();
        let mut room = MOST_FROM_OUTSIDE.saturating_sub(holding);
        for (address, seat) in &mut seats {
            if room == 0 {
                break;
            }
            if let Seat::Away { back_at } = seat {
                if *back_at <= now {
                    next_id += 1;
                    chooser.noted(
                        next_id,
                        Some(host(*address)),
                        u128::MAX / 2,
                        long,
                        true,
                        now,
                    );
                    connected.push(next_id);
                    *seat = Seat::Holding(next_id, None);
                    room -= 1;
                }
            }
        }

        now += 1;
        match chooser.step(now, true, 0, JoinProgress::NothingYet, &connected) {
            Step::Ask(1, _) => {
                asked_honest += 1;
                if chooser.shown(1, 1_000, now) {
                    return (Some(now - start), asked_honest);
                }
            }
            Step::Ask(peer, _) => {
                for seat in seats.values_mut() {
                    if let Seat::Holding(id, asked) = seat {
                        if *id == peer {
                            *asked = Some(now);
                        }
                    }
                }
            }
            Step::Nudge(_) => return (Some(now - start), asked_honest),
            Step::Quiet => {}
        }

        // A connection whose window is spent hangs up. The chooser writes the
        // claim off for leaving if it has not already, and the address waits
        // out the pause it has earned.
        for (address, seat) in &mut seats {
            if let Seat::Holding(id, Some(asked)) = *seat {
                if now.saturating_sub(asked) >= FIRST_ANSWER {
                    connected.retain(|other| *other != id);
                    let failed = failures.entry(*address).or_insert(0);
                    *failed += 1;
                    let back_at = if dial_back {
                        now + pause_after(*failed)
                    } else {
                        u64::MAX
                    };
                    *seat = Seat::Away { back_at };
                }
            }
        }
    }
    (None, asked_honest)
}

/// **Reusing addresses buys a stranger turns for ever once it has enough of
/// them to outlast the longest pause.**
///
/// `choosing::held_off_for` says the doubling makes "a turn now cost a
/// stranger an address it has not already spent", and
/// `reusing_a_handful_of_addresses_does_not_buy_turns_for_ever` holds it for
/// up to twenty three addresses. The doubling stops at `MAX_HELD_OFF`. Once
/// one round of the stranger's addresses, at one answering window each, takes
/// longer than half an hour, the first address is out of its pause before the
/// last has failed, and the round starts again with nothing new spent.
///
/// The honest peer is there from the start with a chain it can show. Sixty
/// two addresses, reused and never fresh, and never more than forty connected
/// at once, keep it from being asked for two days of the newcomer's clock,
/// which is the same as for ever: every pause has reached its ceiling within
/// the first few rounds, and from there each round is the one before it.
/// Sixty one cost four hours fifty two minutes. The catalogue's arrangement,
/// twenty strangers that claim once each, costs ten minutes against its
/// fifteen; the same twenty dialling back as their pauses end cost thirty five.
///
/// The smallest repair found ties the ceiling to the round: an address past
/// its first failure waits at least one answering window for every address
/// on the list, so none is back before all the others have had their turn.
/// Tried while writing this and not kept: sixty two addresses then cost two
/// hours fifty five minutes and the wait ends, and every chooser test in the
/// crate still passes. Ranking a claim from an address that failed behind
/// the rest also ends it, and breaks `tests/shared_address_claims.rs`, which
/// holds on purpose that a neighbour's claim past its pause is judged on its
/// work.
#[test]
fn reused_addresses_do_not_keep_a_newcomer_off_the_honest_chain_for_ever() {
    let watch = 2 * 24 * 3_600;
    for (hosts, dial_back) in [(20, false), (20, true), (61, true)] {
        let (waited, asked) = against_reused_addresses(hosts, dial_back, watch);
        println!(
            "{hosts} addresses{}: honest chain after {waited:?}s, honest asked {asked}",
            if dial_back {
                ", dialling back"
            } else {
                ", claiming once"
            }
        );
    }

    let enough = 62;
    let (waited, asked) = against_reused_addresses(enough, true, watch);
    println!(
        "{enough} addresses, dialling back: honest chain after {waited:?}s, honest asked {asked}"
    );
    assert!(
        waited.is_some(),
        "{enough} addresses, reused and never fresh, kept a newcomer from the honest chain \
         for {watch}s and the honest peer was asked {asked} times: a turn cost the stranger \
         no address it had not already spent"
    );
}
