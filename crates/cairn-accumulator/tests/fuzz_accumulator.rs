//! The accumulator under structured nonsense.
//!
//! Two questions, and the second is the one that matters. The first is whether
//! `Key`, `Proof`, `ForestProof` and `Forest` survive arbitrary bytes, which
//! they have to because all four arrive inside messages a stranger sends.
//!
//! The second is soundness. A proof that verifies against a root it should not
//! is the worst outcome in this crate: a forged membership proof mints money
//! from nothing, undetectably, and a forged absence proof spends a note twice.
//! So the campaign builds a real tree and a real forest, holds a shadow copy of
//! what is really in them, and asserts the implication that matters in the
//! direction that matters:
//!
//! - if a proof verifies membership of `(key, value)` under a root, the tree
//!   with that root really maps `key` to `value`,
//! - if a proof verifies absence of `key` under a root, the tree with that root
//!   really maps `key` to nothing,
//! - if a forest verifies `leaf` at `position`, the forest really holds that
//!   leaf there.
//!
//! The proofs fed in are not random hashes only. They are real proofs bent out
//! of shape, real proofs offered for the wrong key, proofs from a different
//! tree, and proofs whose sibling list has been lengthened or cut, because a
//! forgery that works is one that is nearly right.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::fmt::Debug;

use cairn_accumulator::forest::{empty_leaf, forest_leaf, Forest, ForestProof, MAX_HEIGHT};
use cairn_accumulator::key::MAX_DEPTH;
use cairn_accumulator::{Key, Proof, SparseMerkleTree};
use cairn_fuzz::{mutate, Campaign, Rng};
use cairn_primitives::codec::{Decode, Encode, Reader};
use cairn_primitives::Hash32;

/// Whatever decodes has to re-encode to the bytes it came from, and has to
/// read a settled number of them.
fn holds<T: Encode + Decode + PartialEq + Debug>(bytes: &[u8], what: &str, case: usize) -> bool {
    let Ok(value) = T::decode(bytes) else {
        return false;
    };
    assert_eq!(
        value.encode(),
        bytes,
        "{what} accepted an encoding it does not itself produce (case {case}, bytes {})",
        hex::encode(bytes)
    );

    // Nothing after the value may change it, since all four of these are read
    // inside larger frames.
    let mut reader = Reader::new(bytes);
    let inside = T::decode_from(&mut reader).expect("it decoded a moment ago");
    assert_eq!(
        inside, value,
        "{what} read one value alone and another inside"
    );
    assert_eq!(reader.remaining(), 0);
    true
}

/// The weaker claim, for the one type that does not hold the stronger one.
///
/// Stated as a fixed point rather than as a round trip, which is the weaker of
/// the two and the one that holds for every type here: encoding a decoded value
/// gives bytes that decode to the same value and encode to themselves. A
/// decoder that lost or reordered anything on the way through fails here.
///
/// It was written this way to work around a forest that took its roots in any
/// order and wrote them in one, so a decoded forest need not have re-encoded to
/// the bytes it came from. That is closed, and
/// `a_forest_refuses_roots_in_an_order_it_would_not_write` is where. The
/// weaker statement is kept because it is the one that says what a campaign
/// over arbitrary bytes can ask of every type it is pointed at.
fn settles<T: Encode + Decode + PartialEq + Debug>(bytes: &[u8], what: &str, case: usize) -> bool {
    let Ok(value) = T::decode(bytes) else {
        return false;
    };
    let canonical = value.encode();
    let again = T::decode(&canonical).unwrap_or_else(|error| {
        panic!("{what} will not read back what it wrote: {error} (case {case})")
    });
    assert_eq!(
        again, value,
        "{what} changed value on its way through its own encoder (case {case})"
    );
    assert_eq!(
        again.encode(),
        canonical,
        "{what} has no fixed point (case {case}, bytes {})",
        hex::encode(bytes)
    );
    true
}

fn a_key(rng: &mut Rng) -> Key {
    Key::from_bytes(rng.array::<32>())
}

fn a_hash(rng: &mut Rng) -> Hash32 {
    Hash32::from_bytes(rng.array::<32>())
}

/// A tree with a handful of entries, and what is really in it.
fn a_tree(rng: &mut Rng) -> (SparseMerkleTree, BTreeMap<Key, Hash32>) {
    let mut tree = SparseMerkleTree::new();
    let mut truth = BTreeMap::new();
    for _ in 0..rng.between(0, 24) {
        // Keys that share a prefix land near each other, which is where a
        // proof for one is nearest to being a proof for the other.
        let mut bytes = rng.array::<32>();
        if rng.bool() {
            bytes[0] = 0;
            bytes[1] = 0;
        }
        let key = Key::from_bytes(bytes);
        let value = a_hash(rng);
        tree.insert(key, value);
        truth.insert(key, value);
    }
    for _ in 0..rng.between(0, 4) {
        let Some(key) = truth.keys().nth(rng.below(truth.len().max(1))).copied() else {
            continue;
        };
        tree.remove(key);
        truth.remove(&key);
    }
    (tree, truth)
}

/// A forest with a handful of leaves, and what is really at each place.
///
/// Every place is watched, so a genuine path can be asked for at any of them.
fn a_forest(rng: &mut Rng) -> (Forest, Vec<Hash32>) {
    let mut forest = Forest::new();
    let mut truth: Vec<Hash32> = Vec::new();
    for index in 0..rng.between(0, 40) {
        let leaf = forest_leaf(&[u8::try_from(index & 0xff).unwrap_or(0), rng.byte()]);
        let Some((position, proof)) = forest.add(leaf) else {
            break;
        };
        forest.watch(position, proof);
        truth.push(leaf);
    }
    for _ in 0..rng.between(0, 6) {
        if truth.is_empty() {
            break;
        }
        let position = rng.below(truth.len());
        let at = u64::try_from(position).unwrap_or(0);
        let leaf = truth[position];
        if leaf == empty_leaf() {
            continue;
        }
        let Some(proof) = forest.proof_of(at).cloned() else {
            continue;
        };
        if forest.remove(at, leaf, &proof) {
            truth[position] = empty_leaf();
        }
    }
    (forest, truth)
}

/// Encodings the mutation campaign starts from.
fn corpus(rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut seeds = vec![
        Key::from_bytes([0; 32]).encode(),
        Key::from_bytes([0xff; 32]).encode(),
        ForestProof::default().encode(),
        ForestProof {
            siblings: vec![Hash32::ZERO; 3],
        }
        .encode(),
        ForestProof {
            siblings: vec![Hash32::from_bytes([7; 32]); MAX_HEIGHT],
        }
        .encode(),
        Forest::new().encode(),
    ];

    let (tree, truth) = a_tree(rng);
    for key in truth.keys().take(4) {
        seeds.push(tree.prove(*key).encode());
    }
    seeds.push(tree.prove(a_key(rng)).encode());

    let (forest, _) = a_forest(rng);
    seeds.push(forest.encode());
    seeds.push(forest.roots_only().encode());
    for position in 0..4u64 {
        if let Some(proof) = forest.proof_of(position) {
            seeds.push(proof.encode());
        }
    }
    seeds
}

#[test]
fn arbitrary_bytes_reach_the_four_decoders_and_are_refused_or_canonical() {
    let campaign = Campaign::named("accumulator: arbitrary bytes");
    let seeds = corpus(&mut campaign.stream(0));
    let mut accepted = [0usize; 4];

    let ran = campaign.run(20_000, |case, rng| {
        let bytes = if rng.bool() {
            let len = rng.between(0, 300);
            rng.plausible_bytes(len)
        } else {
            let seed = rng.pick(&seeds).cloned().unwrap_or_default();
            mutate(rng, &seed, &seeds)
        };

        if holds::<Key>(&bytes, "Key", case) {
            accepted[0] += 1;
        }
        if holds::<Proof>(&bytes, "Proof", case) {
            accepted[1] += 1;
        }
        if holds::<ForestProof>(&bytes, "ForestProof", case) {
            accepted[2] += 1;
        }
        if settles::<Forest>(&bytes, "Forest", case) {
            accepted[3] += 1;
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    for (index, count) in accepted.iter().enumerate() {
        assert!(
            *count > 0,
            "decoder {index} was never reached in {} cases",
            ran.cases
        );
    }
}

/// Nothing a decoder accepts may be past the depth its verifier will fold.
///
/// Both proof types cap their sibling list, and both caps exist so a folder
/// cannot be handed a walk longer than the tree is deep.
#[test]
fn a_decoded_proof_is_never_deeper_than_its_own_ceiling() {
    let campaign = Campaign::named("accumulator: proof depth");
    let seeds = corpus(&mut campaign.stream(0));

    let ran = campaign.run(20_000, |_, rng| {
        let seed = rng.pick(&seeds).cloned().unwrap_or_default();
        let bytes = mutate(rng, &seed, &seeds);
        if let Ok(proof) = Proof::decode(&bytes) {
            assert!(proof.depth() <= MAX_DEPTH, "a Proof {} deep", proof.depth());
        }
        if let Ok(proof) = ForestProof::decode(&bytes) {
            assert!(
                proof.depth() <= MAX_HEIGHT,
                "a ForestProof {} deep",
                proof.depth()
            );
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// A membership proof that verifies is a proof of something that is there.
///
/// The forgery test. Every proof offered is a real one bent, which is the only
/// kind with any chance: a random sibling list folds to a random hash and is
/// refused by arithmetic rather than by any rule worth testing.
#[test]
fn a_membership_proof_that_verifies_names_something_the_tree_holds() {
    let campaign = Campaign::named("accumulator: membership soundness");
    let mut verified = 0usize;
    let mut offered = 0usize;

    let ran = campaign.run(4_000, |case, rng| {
        let (tree, truth) = a_tree(rng);
        let root = tree.root();
        let keys: Vec<Key> = truth.keys().copied().collect();

        // A proof for a key in the tree, for a key that is not, and one from a
        // different tree entirely.
        let (other, _) = a_tree(rng);
        let sources: Vec<Vec<u8>> = keys
            .iter()
            .take(4)
            .map(|key| tree.prove(*key).encode())
            .chain(std::iter::once(tree.prove(a_key(rng)).encode()))
            .chain(std::iter::once(other.prove(a_key(rng)).encode()))
            .collect();
        if sources.is_empty() {
            return;
        }

        for _ in 0..8 {
            let seed = rng.pick(&sources).cloned().unwrap_or_default();
            let bytes = if rng.chance(4) {
                seed
            } else {
                mutate(rng, &seed, &sources)
            };
            let Ok(proof) = Proof::decode(&bytes) else {
                continue;
            };
            offered += 1;

            // The key and the value are drawn from what is in the tree as
            // often as not, because a forgery is only interesting when it
            // names something worth naming.
            let key = if rng.bool() && !keys.is_empty() {
                keys[rng.below(keys.len())]
            } else {
                a_key(rng)
            };
            let value = if rng.bool() {
                truth.get(&key).copied().unwrap_or_else(|| a_hash(rng))
            } else {
                a_hash(rng)
            };

            if proof.verify_membership(root, key, value) {
                verified += 1;
                assert_eq!(
                    tree.get(key),
                    Some(value),
                    "a proof carried {key} to a value the tree does not hold (case {case}, \
                     proof {})",
                    hex::encode(&bytes)
                );
            }
            if proof.verify_absence(root, key) {
                assert_eq!(
                    tree.get(key),
                    None,
                    "a proof showed {key} absent from a tree that holds it (case {case}, \
                     proof {})",
                    hex::encode(&bytes)
                );
            }
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    assert!(offered > ran.cases, "only {offered} proofs decoded at all");
    // A campaign where nothing ever verified would have tested that hashing
    // is hard and nothing else.
    assert!(
        verified > 0,
        "not one of {offered} proofs verified, so the check was never exercised"
    );
}

/// The same claim for the forest, which is where the money actually sits.
#[test]
fn a_forest_proof_that_verifies_names_the_leaf_that_is_there() {
    let campaign = Campaign::named("accumulator: forest soundness");
    let mut verified = 0usize;
    let mut offered = 0usize;

    let ran = campaign.run(4_000, |case, rng| {
        let (forest, truth) = a_forest(rng);
        if truth.is_empty() {
            return;
        }
        let (other, _) = a_forest(rng);

        let mut sources: Vec<Vec<u8>> = (0..truth.len().min(6))
            .filter_map(|position| forest.proof_of(u64::try_from(position).ok()?))
            .map(Encode::encode)
            .collect();
        sources.push(other.proof_of(0).cloned().unwrap_or_default().encode());
        sources.push(ForestProof::default().encode());

        for _ in 0..8 {
            let seed = rng.pick(&sources).cloned().unwrap_or_default();
            let bytes = if rng.chance(4) {
                seed
            } else {
                mutate(rng, &seed, &sources)
            };
            let Ok(proof) = ForestProof::decode(&bytes) else {
                continue;
            };
            offered += 1;

            let position = if rng.bool() {
                u64::try_from(rng.below(truth.len())).unwrap_or(0)
            } else {
                rng.edgy_u64()
            };
            let leaf = if rng.bool() {
                usize::try_from(position)
                    .ok()
                    .and_then(|at| truth.get(at).copied())
                    .unwrap_or_else(|| a_hash(rng))
            } else {
                a_hash(rng)
            };

            if forest.verify(position, leaf, &proof) {
                verified += 1;
                let at = usize::try_from(position).ok().and_then(|at| truth.get(at));
                assert_eq!(
                    at,
                    Some(&leaf),
                    "a path carried a leaf to place {position}, which does not hold it \
                     (case {case}, path {})",
                    hex::encode(&bytes)
                );
            }
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    assert!(offered > ran.cases, "only {offered} paths decoded at all");
    assert!(
        verified > 0,
        "not one of {offered} paths verified, so the check was never exercised"
    );
}

/// A removal that is refused leaves nothing behind it.
///
/// The forest is the one structure here that a stranger's bytes can be made to
/// change: a block carries removals, and each carries a proof the sender wrote.
/// A refused one that had already moved a root would leave a node holding a
/// commitment nobody else has, which is a fork with nobody at fault.
#[test]
fn a_refused_removal_leaves_the_forest_exactly_as_it_was() {
    let campaign = Campaign::named("accumulator: refused removals");
    let mut refused = 0usize;
    let mut taken = 0usize;

    let ran = campaign.run(4_000, |case, rng| {
        let (mut forest, truth) = a_forest(rng);
        if truth.is_empty() {
            return;
        }
        let sources: Vec<Vec<u8>> = (0..truth.len().min(6))
            .filter_map(|position| forest.proof_of(u64::try_from(position).ok()?))
            .map(Encode::encode)
            .collect();
        if sources.is_empty() {
            return;
        }

        for _ in 0..6 {
            let before = forest.encode();
            let commitment = forest.commitment();
            let seed = rng.pick(&sources).cloned().unwrap_or_default();
            let bytes = mutate(rng, &seed, &sources);
            let Ok(proof) = ForestProof::decode(&bytes) else {
                continue;
            };
            let position = if rng.bool() {
                u64::try_from(rng.below(truth.len())).unwrap_or(0)
            } else {
                rng.edgy_u64()
            };
            let leaf = if rng.bool() {
                usize::try_from(position)
                    .ok()
                    .and_then(|at| truth.get(at).copied())
                    .unwrap_or_else(|| a_hash(rng))
            } else {
                a_hash(rng)
            };

            if forest.remove(position, leaf, &proof) {
                taken += 1;
                assert_ne!(
                    forest.commitment(),
                    commitment,
                    "a removal that was taken did not move the commitment (case {case})"
                );
                // A place can only be emptied once, and the second attempt is
                // exactly the one that folds to the same roots.
                assert!(
                    !forest.remove(position, empty_leaf(), &proof),
                    "an emptied place was emptied a second time (case {case})"
                );
            } else {
                refused += 1;
                assert_eq!(
                    forest.encode(),
                    before,
                    "a refused removal changed the forest (case {case}, path {})",
                    hex::encode(&bytes)
                );
            }
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    assert!(refused > 0 && taken > 0, "{refused} refused, {taken} taken");
}

/// Every leaf a forest holds proves itself, and proves nothing else.
///
/// Not a mutation campaign. This is the honest half, and it is here because a
/// soundness test whose forest verifies nothing at all would pass.
#[test]
fn a_genuine_path_verifies_at_its_own_place_and_nowhere_else() {
    let campaign = Campaign::named("accumulator: genuine paths");

    let ran = campaign.run(2_000, |case, rng| {
        let (forest, truth) = a_forest(rng);
        for (index, leaf) in truth.iter().enumerate() {
            let position = u64::try_from(index).unwrap_or(0);
            let Some(proof) = forest.proof_of(position) else {
                continue;
            };
            assert!(
                forest.verify(position, *leaf, proof),
                "a forest could not verify its own leaf at {position} (case {case})"
            );
            for (elsewhere, other) in truth.iter().enumerate() {
                if elsewhere == index {
                    continue;
                }
                let there = u64::try_from(elsewhere).unwrap_or(0);
                if other == leaf {
                    // Two emptied places really do hold the same leaf, and a
                    // path is per place rather than per leaf, so this only
                    // says the two are not the same place.
                    continue;
                }
                assert!(
                    !forest.verify(there, *leaf, proof),
                    "a path for {position} verified a leaf at {there} (case {case})"
                );
            }
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
}

/// The defect that was pinned here, and the rule that closed it.
///
/// `Forest::decode` read its roots as a list of (height, root) pairs and put
/// each one into the slot its height named. Nothing required the list to be in
/// order, and `Forest::encode` writes it in ascending height, so a forest with
/// two or more roots had as many encodings as there are ways to arrange them
/// and every one of them decoded to the same forest. That contradicts the first
/// line of `cairn-primitives::codec`: the format "admits exactly one
/// representation of any value". A forest travels inside `Handover` three times
/// over and inside `SampledStart` once, so a stranger handing a newcomer a
/// ledger had a factorial number of byte strings that all meant the same thing.
///
/// What it never did, checked rather than assumed: `Forest::commitment` hashes
/// the roots in canonical order and never touches the encoding, so no header
/// committed to those bytes and two nodes could not be made to disagree.
/// Nothing hashes an encoded forest anywhere in the workspace. That is why it
/// was pinned rather than left failing, and why closing it needs no network
/// number: no honest encoder ever wrote what is now refused.
///
/// Found by the mutation campaign above at seed 0xca12f0221d05ca12, case 6349,
/// through the operator that exchanges two runs of equal length. Reduced by
/// `cairn_fuzz::smallest` to the 119 bytes below, and stated again underneath
/// in the smallest shape that could show it at all: two roots, swapped.
#[test]
fn a_forest_refuses_roots_in_an_order_it_would_not_write() {
    // Leaf count 26, which is 0b11010, so the forest holds roots at heights 1,
    // 3 and 4. Written here as 1, 4, 3.
    let out_of_order = hex::decode(concat!(
        "1a00000000000000",
        "0000000000000000",
        "03000000",
        "01",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "03",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ))
    .unwrap();
    assert_eq!(out_of_order.len(), 119);
    assert!(
        Forest::decode(&out_of_order).is_err(),
        "a forest was decoded out of the bytes its encoder would not write"
    );

    // The same three roots in the order the encoder writes them, which is the
    // half that has to keep working.
    let mut in_order = 26u64.encode();
    in_order.extend_from_slice(&0u64.encode());
    in_order.extend_from_slice(&3u32.encode());
    for height in [1u8, 3, 4] {
        in_order.extend_from_slice(&height.encode());
        in_order.extend_from_slice(Hash32::ZERO.encode().as_slice());
    }
    assert_eq!(in_order.len(), 119);
    let forest = Forest::decode(&in_order).expect("the order an encoder writes");
    assert_eq!(
        forest.encode(),
        in_order,
        "one value, and the bytes it came from are the bytes it writes"
    );

    // The smallest shape that could show it: two roots, in either order. Now
    // one byte string and one value rather than two of the first.
    let mut ascending = 3u64.encode();
    ascending.extend_from_slice(&0u64.encode());
    ascending.extend_from_slice(&2u32.encode());
    ascending.extend_from_slice(&0u8.encode());
    ascending.extend_from_slice(Hash32::from_bytes([0xaa; 32]).encode().as_slice());
    ascending.extend_from_slice(&1u8.encode());
    ascending.extend_from_slice(Hash32::from_bytes([0xbb; 32]).encode().as_slice());
    assert_eq!(ascending.len(), 86);

    let mut descending = 3u64.encode();
    descending.extend_from_slice(&0u64.encode());
    descending.extend_from_slice(&2u32.encode());
    descending.extend_from_slice(&1u8.encode());
    descending.extend_from_slice(Hash32::from_bytes([0xbb; 32]).encode().as_slice());
    descending.extend_from_slice(&0u8.encode());
    descending.extend_from_slice(Hash32::from_bytes([0xaa; 32]).encode().as_slice());

    assert!(Forest::decode(&ascending).is_ok(), "the written order");
    assert!(Forest::decode(&descending).is_err(), "and no other");
}

/// The half of the same rule that does hold, so a fix does not break it.
///
/// Two roots at one height would leave a reader choosing between them, and
/// that is refused. A height past the sixty four a forest can hold is refused
/// too, and so is any set of roots that is not the set the leaf count calls
/// for.
#[test]
fn a_forest_refuses_roots_that_no_forest_could_have_had() {
    let root = Hash32::from_bytes([0xaa; 32]).encode();

    // Two roots at height zero.
    let mut twice = 3u64.encode();
    twice.extend_from_slice(&0u64.encode());
    twice.extend_from_slice(&2u32.encode());
    twice.extend_from_slice(&0u8.encode());
    twice.extend_from_slice(&root);
    twice.extend_from_slice(&0u8.encode());
    twice.extend_from_slice(&root);
    assert!(Forest::decode(&twice).is_err());

    // A height no forest reaches.
    let mut deep = 3u64.encode();
    deep.extend_from_slice(&0u64.encode());
    deep.extend_from_slice(&1u32.encode());
    deep.extend_from_slice(&200u8.encode());
    deep.extend_from_slice(&root);
    assert!(Forest::decode(&deep).is_err());

    // A leaf count whose bits do not name the roots offered.
    let mut mismatched = 4u64.encode();
    mismatched.extend_from_slice(&0u64.encode());
    mismatched.extend_from_slice(&1u32.encode());
    mismatched.extend_from_slice(&0u8.encode());
    mismatched.extend_from_slice(&root);
    assert!(Forest::decode(&mismatched).is_err());

    // More alive than were ever handed out.
    let mut overfull = 1u64.encode();
    overfull.extend_from_slice(&2u64.encode());
    overfull.extend_from_slice(&1u32.encode());
    overfull.extend_from_slice(&0u8.encode());
    overfull.extend_from_slice(&root);
    assert!(Forest::decode(&overfull).is_err());
}
