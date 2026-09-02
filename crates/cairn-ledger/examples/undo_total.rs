//! What the undo records really weigh, measured rather than argued.
//!
//! The figures the papers publish for the undo window come from here. A
//! measurement with no assertion is not a test, so it is an example: run it to
//! reproduce the numbers, and read the run rather than a pass or a fail.

#![allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::note::{Note, NoteId};
use cairn_ledger::transaction::{CoinbaseTransaction, Input, Transfer};
use cairn_ledger::validation::{assemble_block, connect_block, ConsensusParams};
use cairn_ledger::{cold_leaf, ConnectedBlock, LedgerState};
use cairn_primitives::Amount;

const NOW: u64 = 2_000_000_000;
const RECORDS: usize = 1_024;

fn wallet(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

fn params() -> ConsensusParams {
    ConsensusParams::testnet()
        .with_hot_capacity(16)
        .with_coinbase_maturity(0)
}

/// Resident set of this process in kilobytes, as the operating system says.
/// The same reading `audit_index_cost.rs` uses.
fn rss_kb() -> u64 {
    // `ps -o rss=`, which `audit_index_cost.rs` uses, counts resident pages
    // only and misses anything this machine's memory compressor has taken.
    // The physical footprint is what the process really occupies.
    let out = std::process::Command::new("footprint")
        .arg("-p")
        .arg(std::process::id().to_string())
        .output();
    if let Ok(out) = out {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let Some(rest) = line.split("phys_footprint:").nth(1) else {
                continue;
            };
            let mut parts = rest.split_whitespace();
            let (Some(value), Some(unit)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(value) = value.parse::<f64>() else {
                continue;
            };
            return match unit {
                "GB" => (value * 1024.0 * 1024.0) as u64,
                "MB" => (value * 1024.0) as u64,
                "KB" => value as u64,
                _ => (value / 1024.0) as u64,
            };
        }
    }
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// What the transition beside the record costs, counted off its public
/// fields. A cold spend carries its whole proof, which is the term that grows
/// with the chain.
fn transition_bytes(block: &ConnectedBlock) -> (usize, usize) {
    let t = &block.transition;
    let note = std::mem::size_of::<(NoteId, Note)>();
    let mut cold = 0usize;
    for spend in &t.spent_cold {
        cold += std::mem::size_of::<NoteId>()
            + 8
            + std::mem::size_of::<Note>()
            + 24
            + spend.proof.siblings.len() * 32;
    }
    let rest = t.spent_hot.len() * std::mem::size_of::<NoteId>()
        + t.created.len() * note
        + t.evicted.len() * note;
    (cold, rest)
}

/// The same chain harness `audit_undo_record_size.rs` drives, copied so the
/// two are measuring the same blocks.
struct Chain {
    state: LedgerState,
    params: ConsensusParams,
    miner: SecretKey,
    other: SecretKey,
    purse: Vec<(NoteId, Note)>,
    clock: u64,
    share: u64,
}

impl Chain {
    fn new(watch: Option<PublicKey>, share: u64) -> Self {
        let mut state = LedgerState::new();
        if let Some(owner) = watch {
            state.watch_owner(owner);
        }
        Self {
            state,
            params: params(),
            miner: wallet(1),
            other: wallet(2),
            purse: Vec::new(),
            clock: 1_000,
            share,
        }
    }

    fn provable(&self, position: u64, id: &NoteId, note: &Note) -> bool {
        self.state.cold().proof_of(position).is_some_and(|proof| {
            self.state
                .cold()
                .verify(position, cold_leaf(id, note), &proof)
        })
    }

    fn spendable(&mut self) -> Option<(NoteId, Note)> {
        while let Some((id, note)) = self.purse.pop() {
            if self.state.hot_note(&id).is_some() {
                return Some((id, note));
            }
            if let Some((position, held)) = self.state.within_grace(&id) {
                if self.provable(position, &id, &held) {
                    return Some((id, note));
                }
            }
        }
        None
    }

    fn block(&mut self, landing: usize, spends: usize) -> ConnectedBlock {
        let height = self.state.next_height().unwrap();
        self.clock += 600;
        let mut transfers = Vec::new();
        let parts = landing.saturating_sub(1);
        let split = if parts > 0 { self.spendable() } else { None };
        if let Some((id, note)) = split {
            let each = note.value.as_pebbles() / parts as u64;
            if each > 0 {
                let outputs: Vec<Note> = (0..parts)
                    .map(|index| {
                        let owner = if (index as u64 % 4) < self.share {
                            self.miner.public_key()
                        } else {
                            self.other.public_key()
                        };
                        Note::new(Amount::from_pebbles(each).unwrap(), owner)
                    })
                    .collect();
                let mut transfer = Transfer::new(vec![Input::hot(id)], outputs);
                transfer.sign_input(self.params.network, 0, &note, &self.miner);
                transfers.push(transfer);
            }
        }

        let mut spent = 0usize;
        for (id, position, note) in self.state.grace_window().into_iter().flatten() {
            if spent >= spends {
                break;
            }
            if split.map(|(held, _)| held) == Some(id) || !self.provable(position, &id, &note) {
                continue;
            }
            let owner = if note.owner == self.miner.public_key() {
                &self.miner
            } else {
                &self.other
            };
            let mut transfer = Transfer::new(
                vec![Input::hot(id)],
                vec![Note::new(note.value, owner.public_key())],
            );
            transfer.sign_input(self.params.network, 0, &note, owner);
            transfers.push(transfer);
            spent += 1;
        }

        let reward = self.params.reward_at(height);
        let coinbase =
            CoinbaseTransaction::new(height, vec![Note::new(reward, self.miner.public_key())]);
        let block = assemble_block(
            &self.state,
            coinbase,
            transfers,
            &self.params,
            self.clock,
            0,
        )
        .unwrap();
        let connected = connect_block(&mut self.state, &block, &self.params, NOW).unwrap();
        self.purse.push((
            NoteId::new(block.coinbase.id(), 0),
            Note::new(reward, self.miner.public_key()),
        ));
        connected
    }

    fn fill_to(&mut self, target: u64, spends: usize) {
        while self.state.next_cold_position() < target {
            let want = target - self.state.next_cold_position();
            if want > 4 {
                self.block((want - 3).min(200) as usize, spends);
            } else {
                self.block(1, 0);
            }
        }
    }
}

/// What holding `RECORDS` copies of one record really costs the machine.
fn weigh(label: &str, one: &ConnectedBlock) {
    let baseline = rss_kb();
    let mut held: Vec<ConnectedBlock> = Vec::with_capacity(RECORDS);
    for _ in 0..RECORDS {
        held.push(one.clone());
    }
    let grew = rss_kb().saturating_sub(baseline);
    let (cold, rest) = transition_bytes(one);
    println!(
        "  {label}\n    published path_bytes()          {:>10} B  -> {:>8.2} MB over {RECORDS}\n    \
         transition, cold-spend proofs   {cold:>10} B\n    \
         transition, the rest            {rest:>10} B\n    \
         MEASURED whole record (RSS/1024){:>10} B  -> {:>8.2} MB over {RECORDS}\n    \
         understatement factor           {:>10.0}x",
        one.undo.path_bytes(),
        (one.undo.path_bytes() * RECORDS) as f64 / 1e6,
        grew * 1024 / RECORDS as u64,
        (grew * 1024) as f64 / 1e6,
        (grew * 1024) as f64 / RECORDS as f64 / (one.undo.path_bytes().max(1)) as f64,
    );
    // Kept alive across the reading so the allocator cannot hand the pages
    // back before `ps` is asked.
    std::hint::black_box(&held);
    drop(held);
}

/// Shape three of the published table: "one spend, window of 8192 in one
/// tree", which the release quotes at 8 B.
fn what_one_spend_really_costs() {
    const LEAVES: u64 = 8_192;
    let mut chain = Chain::new(None, 4);
    chain.fill_to(LEAVES, 1);
    let window = chain.state.grace_len();
    println!("\n== one spend, cold set {LEAVES} leaves in one tree, window {window} notes ==");
    let connected = chain.block(2, 1);
    weigh("one spend", &connected);
}

/// Shapes one and two: an ordinary chain, and the MAX beside the mean.
fn what_an_ordinary_chain_really_costs() {
    let mut chain = Chain::new(None, 4);
    let mut records: Vec<ConnectedBlock> = Vec::new();
    for _ in 0..48u64 {
        records.push(chain.block(200, 1));
    }

    let published: Vec<usize> = records.iter().map(|one| one.undo.path_bytes()).collect();
    let mean = published.iter().sum::<usize>() / published.len();
    let worst = *published.iter().max().unwrap();
    println!("\n== an ordinary chain, 48 blocks landing 200 notes and spending 1 ==");
    println!(
        "  published metric only: mean {mean} B ({:.2} MB over {RECORDS}), \
         MAX {worst} B ({:.2} MB over {RECORDS}), max/mean {:.1}x",
        (mean * RECORDS) as f64 / 1e6,
        (worst * RECORDS) as f64 / 1e6,
        worst as f64 / mean.max(1) as f64,
    );

    // The whole record, on the record whose published figure is the worst,
    // and on a middling one.
    let at_worst = published.iter().position(|b| *b == worst).unwrap();
    weigh(
        "the record with the largest path_bytes()",
        &records[at_worst],
    );
    weigh("a middling record (the 24th)", &records[24]);

    // And what 1024 DIFFERENT records cost, which is the real shape: a node
    // keeps a run of blocks, not a thousand copies of one.
    let baseline = rss_kb();
    let mut run: Vec<ConnectedBlock> = Vec::new();
    for _ in 0..256 {
        run.push(chain.block(200, 1));
    }
    let grew = rss_kb().saturating_sub(baseline);
    let sum: usize = run.iter().map(|one| one.undo.path_bytes()).sum();
    println!(
        "  a real run of 256 consecutive records: published sum {sum} B ({:.2} MB scaled to \
         {RECORDS}), MEASURED {} kB ({:.2} MB scaled to {RECORDS}), understatement {:.0}x",
        (sum * RECORDS / 256) as f64 / 1e6,
        grew,
        (grew * 1024 * RECORDS as u64 / 256) as f64 / 1e6,
        (grew * 1024) as f64 / sum.max(1) as f64,
    );
    std::hint::black_box(&run);
}

/// Shape four: a node following an owner, at the ceiling.
fn what_a_followed_owner_really_costs() {
    const LEAVES: u64 = 16_384;
    let followed = wallet(1).public_key();
    let mut chain = Chain::new(Some(followed), 2);
    chain.fill_to(LEAVES, 1);
    println!(
        "\n== a followed owner at the ceiling: {} notes followed, {} paths watched ==",
        chain.state.watched_notes().count(),
        chain.state.watched_paths(),
    );
    let mut worst = chain.block(2, 1);
    for _ in 0..8 {
        let one = chain.block(200, 1);
        if one.undo.path_bytes() > worst.undo.path_bytes() {
            worst = one;
        }
    }
    weigh("worst of the run", &worst);
}

/// Does the 48-block run the published mean comes from ever reach the state
/// a running node is in?
///
/// The grace window has to be FULL before a block can push anything off it,
/// and pushing something off is the only thing `disturbed` pays for. While
/// the window is still filling, every record is empty and costs 8 bytes. So
/// a mean taken over a run that is mostly warm-up is a mean over the cheapest
/// branch.
fn when_the_expensive_branch_starts() {
    let mut chain = Chain::new(None, 4);
    let mut per_block: Vec<(usize, usize, usize)> = Vec::new();
    for _ in 0..320u64 {
        let one = chain.block(200, 1);
        per_block.push((
            chain.state.grace_len(),
            one.undo.paths_held(),
            one.undo.path_bytes(),
        ));
    }

    println!("\n== when does a record start costing anything? ==");
    println!("  block   window   paths     bytes");
    for (at, (window, paths, bytes)) in per_block.iter().enumerate() {
        if at % 20 == 0 || at == per_block.len() - 1 {
            println!("  {at:>5}   {window:>6}   {paths:>5}   {bytes:>7}");
        }
    }

    let first_paid = per_block.iter().position(|(_, _, b)| *b > 64).unwrap_or(0);
    println!("  the first record costing more than 64 B is block {first_paid}");

    let all: Vec<usize> = per_block.iter().map(|(_, _, b)| *b).collect();
    let over = |from: usize| -> (usize, usize) {
        let slice = &all[from..];
        (
            slice.iter().sum::<usize>() / slice.len(),
            *slice.iter().max().unwrap(),
        )
    };
    let (mean48, worst48) = (
        all[..48].iter().sum::<usize>() / 48,
        *all[..48].iter().max().unwrap(),
    );
    let (mean_all, worst_all) = over(0);
    let (mean_steady, worst_steady) = over(160);
    println!(
        "\n  the published window (blocks 0..48):  mean {mean48:>7} B -> {:>7.2} MB over {RECORDS}, \
         max {worst48:>7} B -> {:>7.2} MB",
        (mean48 * RECORDS) as f64 / 1e6,
        (worst48 * RECORDS) as f64 / 1e6
    );
    println!(
        "  the whole 320-block run:              mean {mean_all:>7} B -> {:>7.2} MB over {RECORDS}, \
         max {worst_all:>7} B -> {:>7.2} MB",
        (mean_all * RECORDS) as f64 / 1e6,
        (worst_all * RECORDS) as f64 / 1e6
    );
    println!(
        "  STEADY STATE (blocks 160..320):       mean {mean_steady:>7} B -> {:>7.2} MB over {RECORDS}, \
         max {worst_steady:>7} B -> {:>7.2} MB",
        (mean_steady * RECORDS) as f64 / 1e6,
        (worst_steady * RECORDS) as f64 / 1e6
    );
    println!(
        "  steady mean / published mean: {:.1}x",
        mean_steady as f64 / mean48.max(1) as f64
    );
    // At a mature cold set the paths are longer, and the record is linear in
    // the depth, exactly as `audit_undo_record_size.rs` says.
    let depth = (chain.state.next_cold_position() as f64).log2();
    println!(
        "  cold set here is {} leaves (depth {depth:.0}); at a mature depth of 30 the steady \
         mean is {:.1} MB over {RECORDS}",
        chain.state.next_cold_position(),
        (mean_steady * RECORDS) as f64 / 1e6 * 30.0 / depth
    );
}

/// The published "8 bytes for one spend" is taken with the grace window at
/// 8133 of its 8192 ceiling and a block that lands two notes: nothing can age
/// off it, so the branch that costs anything is never entered. This runs the
/// same shape with the window at the ceiling.
fn one_spend_with_the_window_actually_full() {
    const LEAVES: u64 = 8_192;
    let mut chain = Chain::new(None, 4);
    chain.fill_to(LEAVES, 1);
    println!(
        "\n== one spend, published shape: window {} of 8192, block lands 2 ==",
        chain.state.grace_len()
    );
    let published = chain.block(2, 1);
    println!(
        "  window {} -> record {} paths, {} B",
        chain.state.grace_len(),
        published.undo.paths_held(),
        published.undo.path_bytes()
    );

    // Now run the window up to its ceiling and hold it there.
    for _ in 0..120 {
        chain.block(200, 1);
    }
    println!(
        "\n== the same one spend with the window held at its ceiling ({}) ==",
        chain.state.grace_len()
    );
    for landing in [2usize, 20, 200] {
        let one = chain.block(landing, 1);
        println!(
            "  a block landing {landing:>3} notes and spending 1: {:>4} paths, {:>7} B \
             -> {:>6.2} MB over {RECORDS}",
            one.undo.paths_held(),
            one.undo.path_bytes(),
            (one.undo.path_bytes() * RECORDS) as f64 / 1e6
        );
    }
}

/// The whole-record cost as a SLOPE, so the baseline and the allocator's own
/// pool drop out, with three repeats so the noise is visible.
///
/// One test, one process: `--exact what_a_record_weighs_by_slope`.
fn what_a_record_weighs_by_slope() {
    const LEAVES: u64 = 8_192;
    let mut chain = Chain::new(None, 4);
    chain.fill_to(LEAVES, 1);
    let one = chain.block(2, 1);
    println!(
        "\n== the published \"one spend\" record, weighed by slope ==\n  \
         path_bytes() says {} B",
        one.undo.path_bytes()
    );

    for repeat in 0..3 {
        let mut held: Vec<ConnectedBlock> = Vec::with_capacity(8_192);
        let mut marks: Vec<(usize, u64)> = Vec::new();
        for step in 0..8_192 {
            held.push(one.clone());
            if (step + 1) % 2_048 == 0 {
                marks.push((step + 1, rss_kb()));
            }
        }
        let (n0, r0) = marks[0];
        let (n1, r1) = marks[marks.len() - 1];
        println!(
            "  run {repeat}: {n0} records at {r0} kB, {n1} at {r1} kB -> \
             {} B a record ({:.2} MB over {RECORDS})",
            (r1.saturating_sub(r0)) * 1024 / (n1 - n0) as u64,
            (r1.saturating_sub(r0)) as f64 * 1024.0 / (n1 - n0) as f64 * RECORDS as f64 / 1e6,
        );
        std::hint::black_box(&held);
        drop(held);
    }
}

/// The same slope for a steady-state ordinary block, which is the record a
/// running node actually keeps a thousand of.
fn what_a_steady_state_record_weighs_by_slope() {
    let mut chain = Chain::new(None, 4);
    for _ in 0..200 {
        chain.block(200, 1);
    }
    let one = chain.block(200, 1);
    println!(
        "\n== a steady-state ordinary record, weighed by slope ==\n  \
         path_bytes() says {} B ({:.2} MB over {RECORDS}); window {}",
        one.undo.path_bytes(),
        (one.undo.path_bytes() * RECORDS) as f64 / 1e6,
        chain.state.grace_len(),
    );
    for repeat in 0..3 {
        let mut held: Vec<ConnectedBlock> = Vec::with_capacity(4_096);
        let mut marks: Vec<(usize, u64)> = Vec::new();
        for step in 0..4_096 {
            held.push(one.clone());
            if (step + 1) % 1_024 == 0 {
                marks.push((step + 1, rss_kb()));
            }
        }
        let (n0, r0) = marks[0];
        let (n1, r1) = marks[marks.len() - 1];
        println!(
            "  run {repeat}: {n0} records at {r0} kB, {n1} at {r1} kB -> \
             {} B a record ({:.2} MB over {RECORDS})",
            (r1.saturating_sub(r0)) * 1024 / (n1 - n0) as u64,
            (r1.saturating_sub(r0)) as f64 * 1024.0 / (n1 - n0) as f64 * RECORDS as f64 / 1e6,
        );
        std::hint::black_box(&held);
        drop(held);
    }
}

/// The fixed floor of a record, counted rather than measured.
///
/// `BlockUndo` holds three `Forest`s: `cold_before`, `headers_before` and
/// `headers_before_before_tip`. A `Forest`'s roots are `vec![None; 64]`
/// whatever it holds, so each one is a fixed heap allocation that no figure
/// in `audit_undo_record_size.rs` counts. This is deterministic: no resident
/// set, no allocator, no noise.
fn the_floor_nothing_counts() {
    let one = std::mem::size_of::<Option<cairn_primitives::Hash32>>();
    let roots = one * 64;
    println!("\n== the part of a record that is fixed and uncounted ==");
    println!("  size_of::<Option<Hash32>>() = {one} B");
    println!("  one Forest's roots          = 64 x {one} = {roots} B on the heap");
    println!(
        "  a BlockUndo holds three     = {} B, before a single path is written down",
        roots * 3
    );
    println!(
        "  over {RECORDS} records that is {:.2} MB of roots alone, against a published \
         headline of 3.3 MB for the whole undo window",
        (roots * 3 * RECORDS) as f64 / 1e6
    );
}

/// Is 200 notes a block the typical case, or a small one?
///
/// The rules allow `max_evictions_per_block = DEFAULT_HOT_CAPACITY >> 7`,
/// which is 1024 notes falling in one block, and a block at the 128 kB
/// ceiling makes about three thousand notes. `audit_undo_record_size.rs`
/// drives 200 a block. This drives the run at the cap.
fn at_the_eviction_cap_the_rules_allow() {
    for landing in [200usize, 500, 1_000] {
        let mut chain = Chain::new(None, 4);
        let mut all: Vec<usize> = Vec::new();
        for _ in 0..140u64 {
            all.push(chain.block(landing, 1).undo.path_bytes());
        }
        let steady = &all[80..];
        let mean = steady.iter().sum::<usize>() / steady.len();
        let worst = *steady.iter().max().unwrap();
        let depth = (chain.state.next_cold_position() as f64).log2();
        println!(
            "  landing {landing:>4} notes a block: steady mean {mean:>7} B, max {worst:>7} B \
             -> {:>6.1} MB / {:>6.1} MB over {RECORDS}; at a mature depth of 30, \
             {:>6.1} MB / {:>6.1} MB",
            (mean * RECORDS) as f64 / 1e6,
            (worst * RECORDS) as f64 / 1e6,
            (mean * RECORDS) as f64 / 1e6 * 30.0 / depth,
            (worst * RECORDS) as f64 / 1e6 * 30.0 / depth,
        );
    }
}

fn main() {
    what_one_spend_really_costs();
    what_an_ordinary_chain_really_costs();
    what_a_followed_owner_really_costs();
    when_the_expensive_branch_starts();
    one_spend_with_the_window_actually_full();
    what_a_record_weighs_by_slope();
    what_a_steady_state_record_weighs_by_slope();
    the_floor_nothing_counts();
    at_the_eviction_cap_the_rules_allow();
}
