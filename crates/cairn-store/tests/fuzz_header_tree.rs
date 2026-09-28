//! The header forest on disk, damaged, against the forest it was written as.
//!
//! `headers.tree.<k>` is one of the two formats a shipped program reads back
//! that no campaign had touched (18-I1, 33-I2). It is what a node proves a
//! header's place from when a newcomer asks, and what a node writes with no
//! sync, so any level can stop mid-write under a power cut.
//!
//! What the forest can promise on its own is narrower than it sounds. It
//! cannot know that a leaf is the wrong leaf: the leaves come from the header
//! log, and a torn leaf is put right from there, by the node, through
//! `mend_below`. What it can promise is everything above the leaves. Every
//! node over them is either folded from the two beneath or refused, so damage
//! to the levels alone must never reach a proof: with the leaves intact, a
//! proof it hands out verifies against the forest it was written as, or it
//! refuses. That is the oracle here, beside no panic and an open that fails
//! only for a file it could not reach.
//!
//! It did not hold in one shape, which this campaign found and allowed by
//! name until it was mended. The repair at every open, `mend_levels`, built a
//! missing node from the two nodes beneath it, so a node torn in place under
//! a level whose write never landed was folded into a new node above it, and
//! from then on the forest agreed with itself and handed out proofs of a
//! root nobody has, with every leaf intact. It builds from the leaves now, as
//! `mend_below` does and for the reason `cairn_net`'s `proof_off_disk` gives,
//! and the allowance is gone.
//!
//! Two arms: a forest written by `append` and left alone, which has to prove
//! every position against every length exactly as `cairn_accumulator::Archive`
//! does; and the same forest with levels zero to three bent, truncated,
//! lengthened or overwritten before it is opened again.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};

use cairn_accumulator::forest::Forest;
use cairn_accumulator::Archive;
use cairn_fuzz::{Campaign, Rng};
use cairn_primitives::Hash32;
use cairn_store::{HeaderTree, StoreError, HEADER_TREE};

/// Most leaves a case writes: enough for trees four levels tall, which is
/// every level the bending reaches.
const MOST_LEAVES: usize = 40;

fn scratch() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cairn-fuzz-header-tree-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn level(directory: &Path, height: usize) -> PathBuf {
    directory.join(format!("{HEADER_TREE}.{height}"))
}

/// Damages one level file the way a torn write or a stray byte would.
fn bend(rng: &mut Rng, path: &Path) {
    let Ok(mut bytes) = std::fs::read(path) else {
        return;
    };
    match rng.below(5) {
        // Cut short, at a node's edge or inside one.
        0 => bytes.truncate(rng.below(bytes.len() + 1)),
        // Grown by bytes nobody wrote.
        1 => {
            let more = rng.between(1, 70);
            bytes.extend(rng.bytes(more));
        }
        // A node overwritten where it stands, so the length still agrees.
        2 if !bytes.is_empty() => {
            let at = rng.below(bytes.len());
            let run = rng.between(1, 32).min(bytes.len() - at);
            let fresh = rng.bytes(run);
            bytes[at..at + run].copy_from_slice(&fresh);
        }
        // Emptied.
        3 => bytes.clear(),
        // One bit.
        _ if !bytes.is_empty() => {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }
        _ => {}
    }
    std::fs::write(path, bytes).unwrap();
}

/// The forest of the first `count` leaves, as written.
fn forest_of(leaves: &[Hash32], count: usize) -> Forest {
    let mut forest = Forest::new();
    for leaf in &leaves[..count] {
        forest.add(*leaf);
    }
    forest
}

/// What one arm did.
#[derive(Debug, Default)]
struct Tally {
    cases: usize,
    opened: usize,
    proved: usize,
    refused: usize,
    /// Proofs over a torn leaf that disagree with the forest as written,
    /// which the forest cannot know about. Counted, so the arm is seen to
    /// reach the case the oracle has to allow.
    torn_and_vouched: usize,
}

/// With its leaves intact, a proof the forest on disk hands out verifies
/// against the forest as written, however its levels were damaged, and an
/// undamaged forest proves everything the archive does.
///
/// Nothing had ever opened this format after damaging it, so a forest that
/// handed out a proof over a node it had never checked, or that could not
/// open over a torn level it is meant to mend, passed.
#[test]
fn a_forest_on_disk_proves_only_what_its_leaves_prove() {
    let campaign = Campaign::named("store: header forest");
    let directory = scratch();
    let seed = campaign.seed();
    let mut whole = Tally::default();
    let mut bent = Tally::default();

    let ran = campaign.run(400, |case, rng| {
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let count = rng.between(1, MOST_LEAVES);
        let leaves: Vec<Hash32> = (0..count)
            .map(|_| Hash32::from_bytes(rng.array()))
            .collect();
        {
            let mut tree = HeaderTree::open(&directory).unwrap();
            for leaf in &leaves {
                tree.append(*leaf).unwrap();
            }
        }

        let damaged = rng.bool();
        if damaged {
            for height in 0..4 {
                if rng.chance(2) {
                    bend(rng, &level(&directory, height));
                }
            }
        }
        let tally = if damaged { &mut bent } else { &mut whole };
        tally.cases += 1;

        let tree = match HeaderTree::open(&directory) {
            Ok(tree) => tree,
            Err(StoreError::Io(_)) => return,
            Err(other) => panic!(
                "case {case} of seed {seed:#x}: a forest whose levels were bent would not \
                 open, for {other}, which is not a file that could not be reached"
            ),
        };
        tally.opened += 1;

        // The leaves as they stand now, which is what any proof has to agree
        // with: a bent leaf is a different leaf, not a reason to vouch for the
        // old one.
        let held = usize::try_from(tree.len()).unwrap();
        let mut now = Vec::with_capacity(held);
        for position in 0..held {
            match tree.leaf_at(position as u64) {
                Ok(Some(leaf)) => now.push(leaf),
                other => panic!(
                    "case {case} of seed {seed:#x}: leaf {position} of {held} held answered \
                     {other:?}"
                ),
            }
        }
        if !damaged {
            assert_eq!(held, count, "case {case}: the forest lost leaves");
            assert_eq!(
                now, leaves,
                "case {case}: the forest's leaves are not the ones written"
            );
        }

        // Whether any leaf the forest holds is not the one written. When one
        // is, a proof over it can disagree with the forest as written and the
        // forest cannot know: that is the node's to put right from the header
        // log. When none is, a disagreement is damage above the leaves that
        // the forest vouched for.
        // Leaves past the ones written are bytes nobody wrote, which is a torn
        // leaf too.
        let torn = held > count
            || now
                .iter()
                .zip(&leaves)
                .any(|(held, written)| held != written);
        let mut archive = Archive::new();
        for leaf in &leaves {
            archive.add(*leaf).unwrap();
        }
        // Every position against the whole forest, and against three shorter
        // lengths drawn at random: every length against every position is
        // the square of the forest, and a campaign that spends its budget
        // there runs a tenth of the forests.
        let mut lengths = vec![held];
        for _ in 0..3 {
            if held > 1 {
                lengths.push(rng.between(1, held - 1));
            }
        }
        for length in lengths {
            let written = (length <= count).then(|| forest_of(&leaves, length));
            for position in 0..length {
                let at = position as u64;
                match tree.prove_in(at, length as u64) {
                    Ok(Some(proof)) => {
                        tally.proved += 1;
                        let sound = written
                            .as_ref()
                            .zip(leaves.get(position))
                            .is_some_and(|(written, leaf)| written.verify(at, *leaf, &proof));
                        if !sound && torn {
                            tally.torn_and_vouched += 1;
                        }
                        assert!(
                            sound || torn,
                            "case {case} of seed {seed:#x}: with every leaf as written, the \
                             forest handed out a proof of leaf {position} among {length} that \
                             the forest as written does not make, so damage above the leaves \
                             was vouched for"
                        );
                        if !damaged {
                            assert_eq!(
                                Some(proof),
                                archive.prove_in(at, length as u64),
                                "case {case}: an undamaged forest proves otherwise than the \
                                 archive"
                            );
                        }
                    }
                    Ok(None) => panic!(
                        "case {case} of seed {seed:#x}: leaf {position} among {length} is \
                         held and was answered with nothing, which is the answer for a leaf \
                         that is not"
                    ),
                    Err(refused) => {
                        tally.refused += 1;
                        assert!(
                            damaged,
                            "case {case}: an undamaged forest refused a proof: {refused}"
                        );
                    }
                }
            }
        }
        assert!(
            matches!(tree.prove_in(held as u64, held as u64), Ok(None)),
            "case {case}: a position past the leaves held was answered with something"
        );
    });

    let _ = std::fs::remove_dir_all(&directory);
    eprintln!("store: header forest, left whole: {whole:?}; bent: {bent:?}");
    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    assert!(whole.proved > 0, "no undamaged forest proved anything");
    assert!(
        bent.opened > 0,
        "no bent forest opened, so nothing was proved from one"
    );
    assert!(
        bent.proved > 0,
        "no bent forest proved anything, so soundness was not asked"
    );
    assert!(
        bent.refused > 0,
        "no bent forest refused a proof, so the bending never reached a node a proof reads"
    );
}
