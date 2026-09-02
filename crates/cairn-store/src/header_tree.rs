//! The forest of headers, kept on disk rather than in memory.
//!
//! Showing a newcomer which chain carries the most work means proving that a
//! header sits where it claims, and proving that means holding a path through
//! the forest the tip commits to. Held in memory that is a gigabyte at thirty
//! years, which is the one thing a node's cost may not do; held here it is
//! thirty two bytes a block of disk and a handful of reads per proof.
//!
//! One file per height. Level zero holds the leaves, level `k` the nodes
//! covering `2^k` leaves each, and every record is thirty two bytes, so a
//! node's place in its file is its index. A node appears only once every leaf
//! beneath it has, which is exactly the nodes a proof asks for.
//!
//! The layout and the hashing come from `cairn_accumulator`, not from here. A
//! forest on disk that produced different hashes from one in memory would put
//! a node on a chain of its own.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cairn_accumulator::forest::{node_hash, tree_of, MAX_HEIGHT};
use cairn_accumulator::ForestProof;
use cairn_primitives::Hash32;

use crate::StoreError;

/// What the files are called, with the height appended.
pub const HEADER_TREE: &str = "headers.tree";

/// Bytes one node takes.
const NODE_BYTES: u64 = 32;

/// The forest of header leaves, one file per height.
#[derive(Debug)]
pub struct HeaderTree {
    directory: PathBuf,
    /// Open files by height, level zero first. Grown as heights are reached.
    levels: Vec<File>,
    /// Leaves held.
    leaves: u64,
}

impl HeaderTree {
    /// Opens the forest inside `directory`, creating it if needed.
    ///
    /// How many leaves it holds comes from the size of level zero. Every level
    /// above that one is a function of it, so a level that disagrees is put
    /// back into line rather than believed: one that reaches too far is cut,
    /// one that falls short has the nodes it is missing worked out again from
    /// the level beneath it.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StoreError> {
        let directory = directory.as_ref().to_path_buf();
        std::fs::create_dir_all(&directory)?;
        let mut tree = Self {
            directory,
            levels: Vec::new(),
            leaves: 0,
        };
        tree.leaves = tree
            .level(0)?
            .metadata()?
            .len()
            .checked_div(NODE_BYTES)
            .unwrap_or(0);
        tree.mend_levels()?;
        Ok(tree)
    }

    /// Leaves held.
    pub fn len(&self) -> u64 {
        self.leaves
    }

    pub fn is_empty(&self) -> bool {
        self.leaves == 0
    }

    /// Adds one leaf, recording every node it completes.
    ///
    /// The nodes this leaf completes are folded up in memory first, then
    /// written, and the leaf itself goes down last. That order is what makes
    /// an interrupted append cheap to recover from: level zero is where the
    /// leaf count is read back from, so publishing the leaf last leaves nodes
    /// reaching past the leaves rather than leaves reaching past their nodes,
    /// and nodes that reach too far are simply cut. Folding in memory is what
    /// the order costs, since the node directly above this leaf cannot be
    /// built from a disk the leaf is not on yet.
    pub fn append(&mut self, leaf: Hash32) -> Result<(), StoreError> {
        let at = self.leaves;
        let after = self.leaves.saturating_add(1);

        // Each entry is a node the leaf completes, and `carry` is the one
        // beneath the next of them: the leaf to start with, then what the last
        // fold produced.
        let mut pending = Vec::new();
        let mut carry = leaf;
        for height in 1..MAX_HEIGHT {
            let Some(span) = 1u64.checked_shl(u32::try_from(height).unwrap_or(u32::MAX)) else {
                break;
            };
            if span == 0 || after.checked_rem(span).is_none_or(|rest| rest != 0) {
                break;
            }
            let start = after.saturating_sub(span);
            let lower = height.saturating_sub(1);
            let left = self.node(lower, start)?;
            carry = node_hash(left, carry);
            let index = after.checked_div(span).unwrap_or(0).saturating_sub(1);
            pending.push((height, index, carry));
        }

        for (height, index, value) in pending {
            self.write(height, index, value)?;
        }
        self.write(0, at, leaf)?;
        self.leaves = after;
        Ok(())
    }

    /// Cuts the forest back to `leaves` of them, as though the rest had never
    /// been added.
    ///
    /// For a reorganisation, which takes headers off the branch this node was
    /// following. Every node above what is left goes with them, and they are
    /// written again as the new branch is applied.
    pub fn keep_first(&mut self, leaves: u64) -> Result<(), StoreError> {
        if leaves >= self.leaves {
            return Ok(());
        }
        self.leaves = leaves;
        self.mend_levels()
    }

    /// The proof for `position` as it stood when the forest held `leaves`.
    ///
    /// `leaves` rather than what is held now, because what a chain commits to
    /// is the forest from before its tip. A proof built against the wrong one
    /// of those two checks out nowhere.
    ///
    /// The path is folded as it is gathered and every fold is compared with
    /// the node the forest holds in that place. Every one of them is held: the
    /// tree a position belongs to is complete, so each node above the leaf was
    /// written when the leaf beneath it completed it, and there is no
    /// arithmetic here that the forest does not already have an answer for.
    ///
    /// That is what turns a level of the right length holding the wrong bytes
    /// from something believed into something refused. `mend_levels` measures
    /// agreement in length alone, so it cannot see a node changed in place;
    /// one node zeroed used to give a forest that opened with the right leaf
    /// count and served a proof with a zero where a hash belongs, and the only
    /// symptom was on the machine of whoever was handed it.
    ///
    /// Nothing is repaired here, on purpose. A node that disagrees with the
    /// two beneath it is one of the three that is wrong, and which one is not
    /// knowable from inside this file: rewriting the node from its children
    /// would launder a bad leaf into a forest that is consistent and still
    /// serves a root nobody has, and would erase the disagreement that is the
    /// only evidence there was. Refusing one proof leaves the node running,
    /// following the chain and serving headers, which is not the same kind of
    /// cost as refusing to start.
    ///
    /// It costs one read of the leaf, one more node read per level, and one
    /// hash per level, against a path that was already one read per level.
    pub fn prove_in(&self, position: u64, leaves: u64) -> Result<Option<ForestProof>, StoreError> {
        if position >= leaves || leaves > self.leaves {
            return Ok(None);
        }
        let Some((height, offset)) = tree_of(leaves, position) else {
            return Ok(None);
        };
        let mut siblings = Vec::with_capacity(height);
        let Some(mut index) = position.checked_sub(offset) else {
            return Ok(None);
        };
        let mut carry = self.node(0, position)?;
        for level in 0..height {
            let Some(span) = 1u64.checked_shl(u32::try_from(level).unwrap_or(u32::MAX)) else {
                return Ok(None);
            };
            let Some(start) = (index ^ 1)
                .checked_mul(span)
                .and_then(|at| offset.checked_add(at))
            else {
                return Ok(None);
            };
            let sibling = self.node(level, start)?;
            siblings.push(sibling);
            carry = if index & 1 == 0 {
                node_hash(carry, sibling)
            } else {
                node_hash(sibling, carry)
            };
            index = index.checked_shr(1).unwrap_or(0);

            let above = level.saturating_add(1);
            let Some(covers) = 1u64.checked_shl(u32::try_from(above).unwrap_or(u32::MAX)) else {
                return Ok(None);
            };
            let Some(from) = index
                .checked_mul(covers)
                .and_then(|at| offset.checked_add(at))
            else {
                return Ok(None);
            };
            if self.node(above, from)? != carry {
                return Err(StoreError::Unfolded {
                    height: above,
                    start: from,
                });
            }
        }
        Ok(Some(ForestProof { siblings }))
    }

    /// The leaf at `position`, if it is held.
    ///
    /// For telling where this forest and the log it follows part company.
    pub fn leaf_at(&self, position: u64) -> Result<Option<Hash32>, StoreError> {
        if position >= self.leaves {
            return Ok(None);
        }
        self.read(0, position)
    }

    /// The node of this height covering the leaves from `start`.
    fn node(&self, height: usize, start: u64) -> Result<Hash32, StoreError> {
        let Some(span) = 1u64.checked_shl(u32::try_from(height).unwrap_or(u32::MAX)) else {
            return Err(StoreError::MissingNode { height, start });
        };
        let index = start.checked_div(span).unwrap_or(0);
        self.read(height, index)?
            .ok_or(StoreError::MissingNode { height, start })
    }

    /// How many nodes of this height `self.leaves` completes.
    fn filled(&self, height: usize) -> u64 {
        1u64.checked_shl(u32::try_from(height).unwrap_or(u32::MAX))
            .and_then(|span| self.leaves.checked_div(span))
            .unwrap_or(0)
    }

    /// Puts every level back into agreement with the leaves beneath it.
    ///
    /// Two kinds of disagreement, and they need opposite answers. A level that
    /// reaches past what the leaves account for is cut, which is what a
    /// reorganisation asks for and what an interrupted append leaves behind. A
    /// level that falls short is written again from the level beneath it,
    /// which is the one thing `set_len` must never be asked to do: it extends
    /// a short file with zero bytes as readily as it truncates a long one, and
    /// a zero where a node hash belongs is a proof that folds to the wrong
    /// root, served silently and for good.
    ///
    /// Only the nodes actually missing are worked out again, so an ordinary
    /// open touches nothing and an append torn between two levels costs a
    /// handful of hashes. Damage deeper than that costs proportionally more,
    /// which is the price of not trusting a file that cannot account for
    /// itself.
    ///
    /// What this cannot see is a node of the right length holding the wrong
    /// bytes, and it is not going to: seeing that means rehashing the history
    /// at every start, which is the cost this forest exists to avoid.
    /// [`HeaderTree::prove_in`] catches it instead, on the path it is asked
    /// for and nowhere else.
    ///
    /// Trailing bytes that do not make a whole node are not a node, so they
    /// are dropped before anything is counted. A flush is not a sync, and
    /// under a power cut any level can stop mid-write.
    fn mend_levels(&mut self) -> Result<(), StoreError> {
        for height in 0..MAX_HEIGHT {
            let want = self.filled(height);
            let path = self.path(height);
            if height > 0 && want == 0 && !path.exists() {
                // Nothing above this height can hold anything either.
                break;
            }
            let held = self.level(height)?.metadata()?.len();
            let keep = held.checked_div(NODE_BYTES).unwrap_or(0).min(want);
            let cut = keep.saturating_mul(NODE_BYTES);
            if held != cut {
                let file = self.level(height)?;
                file.set_len(cut)?;
                // Waited for, unlike the writes: a cut that does not land is a
                // level that comes back holding nodes this decided the leaves
                // do not account for, and being cut is the whole of what says
                // they are gone.
                file.sync_data()?;
            }
            // Level zero is the record itself, and there is nothing beneath it
            // to rebuild from. Above it the loop runs upward so that a level
            // is only ever built from one that has already been put right.
            if height == 0 {
                continue;
            }
            for index in keep..want {
                self.rebuild(height, index)?;
            }
        }
        Ok(())
    }

    /// Writes the node at this height and index from the two beneath it.
    fn rebuild(&mut self, height: usize, index: u64) -> Result<(), StoreError> {
        let Some(span) = 1u64.checked_shl(u32::try_from(height).unwrap_or(u32::MAX)) else {
            return Err(StoreError::MissingNode { height, start: 0 });
        };
        let Some(start) = index.checked_mul(span) else {
            return Err(StoreError::MissingNode { height, start: 0 });
        };
        let half = span.checked_div(2).unwrap_or(0);
        let lower = height.saturating_sub(1);
        let left = self.node(lower, start)?;
        let right = self.node(lower, start.saturating_add(half))?;
        self.write(height, index, node_hash(left, right))
    }

    fn path(&self, height: usize) -> PathBuf {
        self.directory.join(format!("{HEADER_TREE}.{height}"))
    }

    /// The file for this height, opening it if this is the first time.
    fn level(&mut self, height: usize) -> Result<&mut File, StoreError> {
        while self.levels.len() <= height {
            let at = self.levels.len();
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(self.path(at))?;
            self.levels.push(file);
        }
        self.levels
            .get_mut(height)
            .ok_or(StoreError::MissingNode { height, start: 0 })
    }

    fn write(&mut self, height: usize, index: u64, value: Hash32) -> Result<(), StoreError> {
        let at = index.saturating_mul(NODE_BYTES);
        let file = self.level(height)?;
        file.seek(SeekFrom::Start(at))?;
        file.write_all(value.as_bytes())?;
        file.flush()?;
        Ok(())
    }

    fn read(&self, height: usize, index: u64) -> Result<Option<Hash32>, StoreError> {
        let Some(mut file) = self.levels.get(height) else {
            return Ok(None);
        };
        let at = index.saturating_mul(NODE_BYTES);
        if file.metadata()?.len() < at.saturating_add(NODE_BYTES) {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(at))?;
        let mut bytes = [0u8; 32];
        file.read_exact(&mut bytes)?;
        Ok(Some(Hash32::from_bytes(bytes)))
    }
}
