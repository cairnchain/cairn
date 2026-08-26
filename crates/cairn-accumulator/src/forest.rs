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

fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let mut hasher = Hasher::new(Domain::ForestNode);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

/// Which tree holds `position`, and where that tree starts.
///
/// Trees are laid out largest first, so the oldest leaves sit in the biggest
/// tree and a merge only ever extends a tree upward. Positions therefore keep
/// their order for good.
fn tree_of(leaves: u64, position: u64) -> Option<(usize, u64)> {
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
    pub fn add(&mut self, leaf: Hash32) -> Option<u64> {
        let position = self.leaves;
        let next = self.leaves.checked_add(1)?;

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
                    carry = node_hash(existing, carry);
                    height = height.checked_add(1)?;
                }
            }
        }

        self.leaves = next;
        self.live = self.live.saturating_add(1);
        Some(position)
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
        true
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

    pub fn add(&mut self, leaf: Hash32) -> Option<u64> {
        let position = self.forest.add(leaf)?;
        self.leaves.push(leaf);
        Some(position)
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
        true
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
        let (height, offset) = tree_of(self.forest.leaves, position)?;
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

    fn subtree(&self, start: u64, height: usize) -> Hash32 {
        if height == 0 {
            return self.leaf_at(start).unwrap_or_else(empty_leaf);
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
