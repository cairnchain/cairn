//! An append only forest, and why the cold set needs one.
//!
//! A sparse Merkle tree cannot be added to without knowing the path to the new
//! key, which means holding the tree. That is fatal for the cold set: every
//! node has to fold an evicted note into the commitment, and if that required
//! the tree then every node would hold the whole cold set and the cost of
//! running one would grow without limit. Exactly what this design exists to
//! avoid.
//!
//! A forest of perfect Merkle trees has the property that is needed instead.
//! Adding a leaf is a binary increment over the roots: the new leaf becomes a
//! tree of one, and while a tree of the same size already exists the two merge.
//! Nothing but the roots is touched, so a node holding sixty four hashes can
//! add a leaf.
//!
//! Removing one still needs a proof, which is right: the proof comes from
//! whoever is spending, who is the one party with a reason to have kept it.
//!
//! Positions are assigned in order and never reused. A removed leaf is
//! replaced by an empty one rather than the forest being reshaped around the
//! hole, so a proof taken today describes the same place tomorrow. That costs
//! a forest that never shrinks, and buys a holder who can keep their own proof
//! current from what every block already carries.

use std::collections::BTreeMap;
use std::fmt;

use cairn_primitives::codec::{CodecError, Decode, Encode, Reader};
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::Hash32;

/// Trees a forest can hold, one per bit of the leaf count.
pub const MAX_HEIGHT: usize = 64;

/// Hashes one item into a forest leaf.
pub fn forest_leaf(item: &[u8]) -> Hash32 {
    hash(Domain::ForestLeaf, item)
}

/// What sits where a leaf was removed.
pub fn empty_leaf() -> Hash32 {
    hash(Domain::ForestLeaf, &[])
}

/// Hashes two children into the node above them.
///
/// Public for the same reason as `tree_of`: a forest kept on disk has to
/// produce the same hashes as one kept in memory, and there must be one
/// definition of that rather than two.
pub fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let mut hasher = Hasher::new(Domain::ForestNode);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

/// Which tree holds `position`, and where that tree starts.
///
/// Public because a forest kept on disk rather than in memory has to lay its
/// nodes out the same way, and there must be one answer to this rather than
/// two that agree until they do not.
///
/// Trees are laid out largest first, so the oldest leaves sit in the biggest
/// tree and a merge only ever extends a tree upward. Positions therefore keep
/// their order for good.
pub fn tree_of(leaves: u64, position: u64) -> Option<(usize, u64)> {
    if position >= leaves {
        return None;
    }
    let mut offset = 0u64;
    for height in (0..MAX_HEIGHT).rev() {
        let shift = u32::try_from(height).unwrap_or(u32::MAX);
        if leaves.checked_shr(shift).unwrap_or(0) & 1 != 1 {
            continue;
        }
        let size = 1u64.checked_shl(shift).unwrap_or(0);
        let end = offset.checked_add(size)?;
        if position < end {
            return Some((height, offset));
        }
        offset = end;
    }
    None
}

/// Folds a leaf up to the root of its tree using the siblings beside it.
fn fold(leaf: Hash32, index_in_tree: u64, siblings: &[Hash32]) -> Hash32 {
    let mut current = leaf;
    let mut index = index_in_tree;
    for sibling in siblings {
        current = if index & 1 == 0 {
            node_hash(current, *sibling)
        } else {
            node_hash(*sibling, current)
        };
        index = index.checked_shr(1).unwrap_or(0);
    }
    current
}

/// Everything needed to show a leaf sits at a position, without the forest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForestProof {
    /// Siblings from the leaf up to the root of its tree.
    pub siblings: Vec<Hash32>,
}

impl ForestProof {
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Bytes this proof takes on the wire.
    pub fn size_in_bytes(&self) -> usize {
        self.siblings.len().saturating_mul(32).saturating_add(4)
    }
}

impl Encode for ForestProof {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.siblings.encode_to(out);
    }
}

impl Decode for ForestProof {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let siblings = Vec::<Hash32>::decode_from(reader)?;
        if siblings.len() > MAX_HEIGHT {
            return Err(CodecError::InvalidValue {
                type_name: "ForestProof",
            });
        }
        Ok(Self { siblings })
    }
}

impl Encode for Forest {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.leaves.encode_to(out);
        self.live.encode_to(out);
        // One byte of height per root, so a mostly empty forest is small and
        // the reader knows which tree each root belongs to.
        let held: Vec<(u8, Hash32)> = self
            .roots
            .iter()
            .enumerate()
            .filter_map(|(height, root)| Some((u8::try_from(height).ok()?, (*root)?)))
            .collect();
        u32::try_from(held.len()).unwrap_or(u32::MAX).encode_to(out);
        for (height, root) in held {
            height.encode_to(out);
            root.encode_to(out);
        }
    }
}

impl Decode for Forest {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let leaves = u64::decode_from(reader)?;
        let live = u64::decode_from(reader)?;
        let count = usize::try_from(u32::decode_from(reader)?).unwrap_or(usize::MAX);
        if count > MAX_HEIGHT {
            return Err(CodecError::InvalidValue {
                type_name: "Forest",
            });
        }
        let mut held = Vec::with_capacity(count);
        for _ in 0..count {
            let height = u8::decode_from(reader)?;
            let root = Hash32::decode_from(reader)?;
            held.push((height, root));
        }

        let mut roots = vec![None; MAX_HEIGHT];
        for (height, root) in held {
            let Some(slot) = roots.get_mut(usize::from(height)) else {
                return Err(CodecError::InvalidValue {
                    type_name: "Forest",
                });
            };
            if slot.is_some() {
                // One root per height, or a reader could be handed two and
                // have to choose.
                return Err(CodecError::InvalidValue {
                    type_name: "Forest",
                });
            }
            *slot = Some(root);
        }

        // The trees a forest holds are the set bits of its leaf count, so the
        // roots and the count check each other. What is decoded here has to be
        // a forest something could have produced, not merely a well formed
        // message.
        for (height, root) in roots.iter().enumerate() {
            let shift = u32::try_from(height).unwrap_or(u32::MAX);
            let expected = leaves.checked_shr(shift).unwrap_or(0) & 1 == 1;
            if root.is_some() != expected {
                return Err(CodecError::InvalidValue {
                    type_name: "Forest",
                });
            }
        }
        if live > leaves {
            return Err(CodecError::InvalidValue {
                type_name: "Forest",
            });
        }

        Ok(Self {
            roots,
            leaves,
            live,
            // Proofs are not part of a forest on the wire. Whoever needs one
            // is handed it separately and checks it against these roots.
            watched: BTreeMap::new(),
        })
    }
}

/// The whole cold set, as a node holds it.
///
/// At most sixty four hashes and two counters, whatever the forest contains.
#[derive(Clone, PartialEq, Eq)]
pub struct Forest {
    roots: Vec<Option<Hash32>>,
    /// Positions handed out so far. Set bits of this are exactly the trees.
    leaves: u64,
    /// Leaves not yet removed.
    live: u64,
    /// Positions whose proofs are kept current as the forest moves.
    ///
    /// Everything it takes to do that is already passing through: a leaf that
    /// is added brings the roots it merged with, and a leaf that is removed
    /// brings the proof of whoever removed it. So a holder who says which
    /// places it cares about never has to ask anyone anything again.
    ///
    /// Watching nothing costs nothing, which is what a plain node does.
    watched: BTreeMap<u64, ForestProof>,
}

impl Default for Forest {
    fn default() -> Self {
        Self::new()
    }
}

impl Forest {
    pub fn new() -> Self {
        Self {
            roots: vec![None; MAX_HEIGHT],
            leaves: 0,
            live: 0,
            watched: BTreeMap::new(),
        }
    }

    /// Starts keeping the proof for `position` current.
    ///
    /// Everything it takes is already passing through the forest: a leaf that
    /// arrives brings the trees it merged with, and a leaf that leaves brings
    /// the proof of whoever removed it. A holder that says which places it
    /// cares about never has to ask anyone anything again.
    pub fn watch(&mut self, position: u64, proof: ForestProof) {
        self.watched.insert(position, proof);
    }

    pub fn unwatch(&mut self, position: u64) -> Option<ForestProof> {
        self.watched.remove(&position)
    }

    /// The proof for a watched position, as it stands now.
    pub fn proof_of(&self, position: u64) -> Option<&ForestProof> {
        self.watched.get(&position)
    }

    pub fn watched_count(&self) -> usize {
        self.watched.len()
    }

    /// The same forest with nothing watched.
    ///
    /// Kept for the window of recent states a spender's proof may be checked
    /// against, where what anyone is watching is beside the point.
    #[must_use]
    pub fn roots_only(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            leaves: self.leaves,
            live: self.live,
            watched: BTreeMap::new(),
        }
    }

    /// Positions handed out, including those since emptied.
    pub fn leaves(&self) -> u64 {
        self.leaves
    }

    /// Leaves still standing.
    pub fn len(&self) -> u64 {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// The thirty two bytes a block header carries for the whole cold set.
    pub fn commitment(&self) -> Hash32 {
        let mut hasher = Hasher::new(Domain::ForestRoots);
        hasher.update(&self.leaves.to_le_bytes());
        hasher.update(&self.live.to_le_bytes());
        for (height, root) in self.roots.iter().enumerate() {
            if let Some(root) = root {
                hasher.update(&u8::try_from(height).unwrap_or(u8::MAX).to_le_bytes());
                hasher.update(root.as_bytes());
            }
        }
        hasher.finalize()
    }

    /// Appends a leaf and returns the position it took.
    ///
    /// Only the roots are read and written, which is what lets a node that
    /// holds nothing else keep the commitment current.
    pub fn add(&mut self, leaf: Hash32) -> Option<(u64, ForestProof)> {
        let position = self.leaves;
        let next = self.leaves.checked_add(1)?;

        let mut siblings = Vec::new();
        let mut carry = leaf;
        let mut height = 0usize;
        loop {
            let slot = self.roots.get_mut(height)?;
            match slot.take() {
                None => {
                    *slot = Some(carry);
                    break;
                }
                Some(existing) => {
                    // The new leaf rides on the right of every merge, so the
                    // trees it swallows are its own siblings, in order. Its
                    // proof therefore falls out of the addition itself and
                    // costs nothing to produce.
                    siblings.push(existing);
                    self.extend_watched(height, existing, carry);
                    carry = node_hash(existing, carry);
                    height = height.checked_add(1)?;
                }
            }
        }

        self.leaves = next;
        self.live = self.live.saturating_add(1);
        Some((position, ForestProof { siblings }))
    }

    /// Gives every watched position inside a merged pair its new sibling.
    ///
    /// At this step the left half is the tree that stood at `level` and the
    /// right half is everything smaller plus the leaf being added. A watched
    /// place in one half gains the other half as its sibling.
    fn extend_watched(&mut self, level: usize, left: Hash32, right: Hash32) {
        let shift = u32::try_from(level.saturating_add(1)).unwrap_or(u32::MAX);
        let Some(start) = self
            .leaves
            .checked_shr(shift)
            .and_then(|high| high.checked_shl(shift))
        else {
            return;
        };
        let Some(span) = 1u64.checked_shl(u32::try_from(level).unwrap_or(u32::MAX)) else {
            return;
        };
        let Some(middle) = start.checked_add(span) else {
            return;
        };
        let Some(end) = middle.checked_add(span) else {
            return;
        };

        for (position, proof) in &mut self.watched {
            if (start..middle).contains(position) {
                proof.siblings.push(right);
            } else if (middle..end).contains(position) {
                proof.siblings.push(left);
            }
        }
    }

    /// Whether `leaf` sits at `position`, according to `proof`.
    pub fn verify(&self, position: u64, leaf: Hash32, proof: &ForestProof) -> bool {
        let Some((height, offset)) = tree_of(self.leaves, position) else {
            return false;
        };
        if proof.siblings.len() != height {
            return false;
        }
        let Some(index) = position.checked_sub(offset) else {
            return false;
        };
        let computed = fold(leaf, index, &proof.siblings);
        self.roots.get(height).copied().flatten() == Some(computed)
    }

    /// Empties the leaf at `position`, given a proof of what is there.
    ///
    /// The proof comes from whoever is spending. Nobody else has a reason to
    /// have kept it, and nobody else needs to.
    pub fn remove(&mut self, position: u64, leaf: Hash32, proof: &ForestProof) -> bool {
        if !self.verify(position, leaf, proof) {
            return false;
        }
        let Some((height, offset)) = tree_of(self.leaves, position) else {
            return false;
        };
        let Some(index) = position.checked_sub(offset) else {
            return false;
        };

        let emptied = fold(empty_leaf(), index, &proof.siblings);
        match self.roots.get_mut(height) {
            Some(slot) => *slot = Some(emptied),
            None => return false,
        }
        self.live = self.live.saturating_sub(1);
        self.refresh_watched(height, offset, index, proof);
        true
    }

    /// Brings every watched proof in the same tree up to date after a removal.
    fn refresh_watched(
        &mut self,
        height: usize,
        offset: u64,
        emptied: u64,
        emptied_proof: &ForestProof,
    ) {
        let leaves = self.leaves;
        for (position, proof) in &mut self.watched {
            let Some((other_height, other_offset)) = tree_of(leaves, *position) else {
                continue;
            };
            if other_height != height || other_offset != offset {
                continue;
            }
            let Some(index) = position.checked_sub(offset) else {
                continue;
            };
            if index == emptied {
                continue;
            }
            refresh(index, proof, emptied, emptied_proof);
        }
    }

    /// Empties several leaves at once, all proved against the roots as they
    /// stand now.
    ///
    /// Removing one leaf moves the siblings of every other leaf in its tree, so
    /// proofs taken against the same root cannot simply be applied one after
    /// another. They are checked together first, then applied in order, each
    /// application bringing the proofs still waiting up to date. Validity
    /// therefore does not depend on the order the spends appear in a block.
    pub fn remove_batch(&mut self, removals: &[(u64, Hash32, ForestProof)]) -> bool {
        for (position, leaf, proof) in removals {
            if !self.verify(*position, *leaf, proof) {
                return false;
            }
        }

        let mut pending: Vec<(u64, Hash32, ForestProof)> = removals.to_vec();
        pending.sort_by_key(|(position, _, _)| *position);
        pending.dedup_by_key(|(position, _, _)| *position);

        let mut index = 0usize;
        while index < pending.len() {
            let Some((position, leaf, proof)) = pending.get(index).cloned() else {
                return false;
            };
            if !self.remove(position, leaf, &proof) {
                return false;
            }
            let Some((height, offset)) = tree_of(self.leaves, position) else {
                return false;
            };
            let Some(emptied) = position.checked_sub(offset) else {
                return false;
            };

            let next = index.saturating_add(1);
            if let Some(rest) = pending.get_mut(next..) {
                for (other, _, other_proof) in rest {
                    let Some((other_height, other_offset)) = tree_of(self.leaves, *other) else {
                        continue;
                    };
                    if other_height != height {
                        continue;
                    }
                    let Some(other_index) = other.checked_sub(other_offset) else {
                        continue;
                    };
                    refresh(other_index, other_proof, emptied, &proof);
                }
            }
            index = next;
        }
        true
    }
}

/// Updates one proof after another leaf in the same tree was emptied.
///
/// The two paths run together from the root down to the level where they part.
/// Everything above that is untouched, everything below is inside the target's
/// own subtree, and the one sibling that moved is the subtree the other leaf
/// sits in. That subtree's new root folds out of the other leaf's own proof,
/// which is why a block carrying both proofs carries enough.
fn refresh(target: u64, proof: &mut ForestProof, changed: u64, changed_proof: &ForestProof) {
    let mut level = 0usize;
    while level < proof.siblings.len() {
        let shift = u32::try_from(level).unwrap_or(u32::MAX);
        if target.checked_shr(shift).unwrap_or(0) == changed.checked_shr(shift).unwrap_or(0) {
            break;
        }
        level = level.saturating_add(1);
    }
    let Some(below) = level.checked_sub(1) else {
        return;
    };
    let Some(prefix) = changed_proof.siblings.get(..below) else {
        return;
    };
    let updated = fold(empty_leaf(), changed, prefix);
    if let Some(slot) = proof.siblings.get_mut(below) {
        *slot = updated;
    }
}

impl fmt::Debug for Forest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The roots are summarised by the commitment, which is the thing worth
        // reading when comparing two nodes.
        f.debug_struct("Forest")
            .field("leaves", &self.leaves)
            .field("live", &self.live)
            .field("commitment", &self.commitment())
            .finish_non_exhaustive()
    }
}

/// A forest together with every leaf it has held.
///
/// This is what an archivist keeps, and the only thing that can produce a
/// proof for someone who lost theirs. A plain node keeps the [`Forest`] alone.
#[derive(Clone, Debug, Default)]
pub struct Archive {
    forest: Forest,
    leaves: Vec<Hash32>,
    /// The inner nodes, by height, so a proof does not have to hash them all
    /// again.
    ///
    /// `inner[h][i]` is the node covering leaves `i << (h + 1)` through
    /// `(i + 1) << (h + 1)`, and it is only there once every one of those
    /// leaves is. Without it a proof costs a pass over everything the archive
    /// holds, which on a chain of a million blocks is eighty seconds for the
    /// five hundred and twelve a newcomer asks for: longer than the tip it was
    /// built for lasts, so the answer would never be finished. With it a proof
    /// is one hash per level.
    ///
    /// It costs another thirty two bytes a block, on top of the thirty two the
    /// leaves already cost. That is the archivist's own bargain and nobody
    /// else's, which is the point of the role.
    inner: Vec<Vec<Hash32>>,
}

impl Archive {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn forest(&self) -> &Forest {
        &self.forest
    }

    pub fn commitment(&self) -> Hash32 {
        self.forest.commitment()
    }

    pub fn len(&self) -> u64 {
        self.forest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forest.is_empty()
    }

    pub fn add(&mut self, leaf: Hash32) -> Option<(u64, ForestProof)> {
        let added = self.forest.add(leaf)?;
        self.leaves.push(leaf);
        self.close_nodes_ending_at(self.leaves.len());
        Some(added)
    }

    /// Records every inner node that the leaf count `filled` has just
    /// completed.
    ///
    /// A node of height `h` is complete exactly when the count is a multiple
    /// of `2^h`, and they complete from the bottom up, so this walks upward
    /// and stops at the first height that is not.
    fn close_nodes_ending_at(&mut self, filled: usize) {
        for height in 1..MAX_HEIGHT {
            let Some(span) = 1usize.checked_shl(u32::try_from(height).unwrap_or(u32::MAX)) else {
                return;
            };
            if filled.checked_rem(span).is_none_or(|rest| rest != 0) {
                return;
            }
            let Some(start) = filled.checked_sub(span) else {
                return;
            };
            let start = u64::try_from(start).unwrap_or(u64::MAX);
            let half = u64::try_from(span / 2).unwrap_or(0);
            let value = node_hash(
                self.subtree(start, height.saturating_sub(1)),
                self.subtree(start.saturating_add(half), height.saturating_sub(1)),
            );
            let level = height.saturating_sub(1);
            while self.inner.len() <= level {
                self.inner.push(Vec::new());
            }
            // Nodes of one height complete in order, so this is the next slot
            // in its row. Written at its own index all the same, since a
            // rebuild walks the same rows a second time.
            let index = filled.checked_div(span).unwrap_or(0).saturating_sub(1);
            if let Some(row) = self.inner.get_mut(level) {
                match row.len().cmp(&index) {
                    std::cmp::Ordering::Equal => row.push(value),
                    std::cmp::Ordering::Greater => {
                        if let Some(slot) = row.get_mut(index) {
                            *slot = value;
                        }
                    }
                    std::cmp::Ordering::Less => {
                        row.resize(index, empty_leaf());
                        row.push(value);
                    }
                }
            }
        }
    }

    /// Recomputes every inner node standing above `position`.
    ///
    /// For a leaf that changed rather than one that arrived. Only the nodes
    /// that are complete are held, so only those are rebuilt.
    fn refresh_above(&mut self, position: u64) {
        let filled = self.leaves.len();
        for height in 1..MAX_HEIGHT {
            let Some(span) = 1u64.checked_shl(u32::try_from(height).unwrap_or(u32::MAX)) else {
                return;
            };
            if span == 0 {
                return;
            }
            let start = position.saturating_sub(position.checked_rem(span).unwrap_or(0));
            let Some(end) = start.checked_add(span) else {
                return;
            };
            if end > u64::try_from(filled).unwrap_or(u64::MAX) {
                return;
            }
            let half = span / 2;
            let value = node_hash(
                self.subtree(start, height.saturating_sub(1)),
                self.subtree(start.saturating_add(half), height.saturating_sub(1)),
            );
            let level = height.saturating_sub(1);
            let index = usize::try_from(start.checked_div(span).unwrap_or(0)).unwrap_or(usize::MAX);
            if let Some(slot) = self.inner.get_mut(level).and_then(|row| row.get_mut(index)) {
                *slot = value;
            }
        }
    }

    /// Takes the last leaf back off, as though it had never been added.
    ///
    /// For an archive of headers rather than of notes. A note is emptied where
    /// it sits and its place is never reused, but a header that a
    /// reorganisation undid was never part of the chain at all, so the forest
    /// has to be the one from before it.
    ///
    /// An append cannot be undone from roots alone, but it can be undone from
    /// the inner nodes, which this holds: the roots of a forest of `n` leaves
    /// are the perfect trees named by the set bits of `n`, and every one of
    /// those is a node already standing. So this is one lookup per level.
    ///
    /// It used to build the forest again from every leaf. Measured on a chain
    /// of a million blocks, that was a third of a second per block undone and
    /// six minutes for a full window, with the chain held throughout, and it
    /// grew from there.
    pub fn remove_last(&mut self) -> bool {
        let Some(dropped) = self.leaves.pop() else {
            return false;
        };
        self.truncate_inner(self.leaves.len());

        // A holder watching a position has a proof that this may have changed,
        // and what it takes to mend one is not here. Nobody watches a header
        // archive; the slow way is kept for the case that arrives later rather
        // than being a wrong answer waiting to be found.
        if self.forest.watched_count() > 0 {
            let mut rebuilt = Forest::new();
            for leaf in &self.leaves {
                rebuilt.add(*leaf);
            }
            self.forest = rebuilt;
            return true;
        }

        let live = if dropped == empty_leaf() {
            self.forest.live
        } else {
            self.forest.live.saturating_sub(1)
        };
        self.forest = self.forest_of(u64::try_from(self.leaves.len()).unwrap_or(0), live);
        true
    }

    /// The forest that `leaves` of what this holds would make.
    ///
    /// Trees are laid out largest first and are exactly the set bits of the
    /// count, so each root is a subtree already standing here.
    fn forest_of(&self, leaves: u64, live: u64) -> Forest {
        let mut roots = vec![None; MAX_HEIGHT];
        let mut offset = 0u64;
        for height in (0..MAX_HEIGHT).rev() {
            let shift = u32::try_from(height).unwrap_or(u32::MAX);
            if leaves.checked_shr(shift).unwrap_or(0) & 1 != 1 {
                continue;
            }
            if let Some(slot) = roots.get_mut(height) {
                *slot = Some(self.subtree(offset, height));
            }
            offset = offset.saturating_add(1u64.checked_shl(shift).unwrap_or(0));
        }
        Forest {
            roots,
            leaves,
            live,
            watched: BTreeMap::new(),
        }
    }

    /// Drops every inner node that `filled` leaves no longer complete.
    fn truncate_inner(&mut self, filled: usize) {
        for (level, row) in self.inner.iter_mut().enumerate() {
            let Some(span) =
                1usize.checked_shl(u32::try_from(level).unwrap_or(u32::MAX).saturating_add(1))
            else {
                row.clear();
                continue;
            };
            row.truncate(filled.checked_div(span.max(1)).unwrap_or(0));
        }
    }

    /// Removes the leaf at `position`, building the proof itself.
    pub fn remove(&mut self, position: u64) -> bool {
        let Some(leaf) = self.leaf_at(position) else {
            return false;
        };
        let Some(proof) = self.prove(position) else {
            return false;
        };
        if !self.forest.remove(position, leaf, &proof) {
            return false;
        }
        if let Some(slot) = usize::try_from(position)
            .ok()
            .and_then(|i| self.leaves.get_mut(i))
        {
            *slot = empty_leaf();
        }
        self.refresh_above(position);
        true
    }

    /// The inner node at `start` of this height, if it is one that is held.
    fn held_node(&self, start: u64, height: usize) -> Option<Hash32> {
        let span = 1u64.checked_shl(u32::try_from(height).ok()?)?;
        if start.checked_rem(span).is_none_or(|rest| rest != 0) {
            return None;
        }
        if start.checked_add(span)? > u64::try_from(self.leaves.len()).ok()? {
            return None;
        }
        let index = usize::try_from(start.checked_div(span)?).ok()?;
        self.inner.get(height.checked_sub(1)?)?.get(index).copied()
    }

    /// Where a leaf sits, if it is still standing.
    ///
    /// This is the question a wallet that lost its record asks an archivist,
    /// and the reason an archivist is worth paying.
    pub fn locate(&self, leaf: Hash32) -> Option<u64> {
        self.leaves
            .iter()
            .position(|held| *held == leaf)
            .and_then(|index| u64::try_from(index).ok())
    }

    pub fn leaf_at(&self, position: u64) -> Option<Hash32> {
        usize::try_from(position)
            .ok()
            .and_then(|index| self.leaves.get(index))
            .copied()
    }

    /// Builds the proof for `position`.
    ///
    /// Each sibling is a subtree hashed from its leaves, so one proof costs a
    /// pass over the forest. An archivist serving many would keep the internal
    /// nodes instead; nothing about the proof it produces would change.
    pub fn prove(&self, position: u64) -> Option<ForestProof> {
        self.prove_in(position, self.forest.leaves)
    }

    /// Builds the proof for `position` as it stood when the forest held
    /// `leaves` of them.
    ///
    /// A forest of this shape is a list of perfect trees decided by how many
    /// leaves it holds, so a proof is only valid against the count it was
    /// built for. What a chain commits to is the forest from before its tip,
    /// while an archive holds the tip too, and proving against the wrong one
    /// of those two produces a proof that checks out nowhere.
    ///
    /// The tree a position belongs to is contained in the leaves before it, so
    /// no sibling here reaches past `leaves`.
    pub fn prove_in(&self, position: u64, leaves: u64) -> Option<ForestProof> {
        if position >= leaves || leaves > self.forest.leaves {
            return None;
        }
        let (height, offset) = tree_of(leaves, position)?;
        let mut siblings = Vec::with_capacity(height);
        let mut index = position.checked_sub(offset)?;

        for level in 0..height {
            let shift = u32::try_from(level).unwrap_or(u32::MAX);
            let span = 1u64.checked_shl(shift)?;
            let sibling_start = offset.checked_add((index ^ 1).checked_mul(span)?)?;
            siblings.push(self.subtree(sibling_start, level));
            index = index.checked_shr(1).unwrap_or(0);
        }
        Some(ForestProof { siblings })
    }

    /// Puts the archive back as it stood before a batch of changes.
    ///
    /// `before` is the roots from that moment, `appended` is how many leaves
    /// were added since, and `restored` names the leaves that were emptied and
    /// what they held. All three are things a node already has: it computed
    /// the first, it decided the second, and the third travelled in the block.
    pub fn rewind(&mut self, before: &Forest, appended: usize, restored: &[(u64, Hash32)]) {
        let keep = self.leaves.len().saturating_sub(appended);
        self.leaves.truncate(keep);
        for (position, leaf) in restored {
            if let Some(slot) = usize::try_from(*position)
                .ok()
                .and_then(|index| self.leaves.get_mut(index))
            {
                *slot = *leaf;
            }
        }
        self.forest = before.clone();
        // The nodes above what moved have to say what the leaves now say.
        // Only two things moved: the tail that left, and the leaves put back.
        // Building every node again instead would be a pass over the whole
        // archive, once per block undone, which is what an archivist cannot
        // afford on an old chain.
        self.truncate_inner(self.leaves.len());
        for (position, _) in restored {
            self.refresh_above(*position);
        }
    }

    fn subtree(&self, start: u64, height: usize) -> Hash32 {
        if height == 0 {
            return self.leaf_at(start).unwrap_or_else(empty_leaf);
        }
        // Held whenever every leaf under it is here, which is every node a
        // proof asks for. The walk below is what answers for the rest: a
        // subtree reaching past the last leaf, which only the paths that
        // rebuild use.
        if let Some(held) = self.held_node(start, height) {
            return held;
        }
        let Some(lower) = height.checked_sub(1) else {
            return empty_leaf();
        };
        let shift = u32::try_from(lower).unwrap_or(u32::MAX);
        let half = 1u64.checked_shl(shift).unwrap_or(0);
        let right_start = start.checked_add(half).unwrap_or(start);
        node_hash(self.subtree(start, lower), self.subtree(right_start, lower))
    }
}
