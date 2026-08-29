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
    /// How many leaves it holds comes from the size of level zero. Anything
    /// above it that reaches further is a write that was interrupted between
    /// two levels, and is cut back to what the leaves can account for.
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
        tree.trim_levels()?;
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
    /// Bottom up, and each node is built from the two beneath it, both of
    /// which are complete and already here.
    pub fn append(&mut self, leaf: Hash32) -> Result<(), StoreError> {
        let at = self.leaves;
        self.write(0, at, leaf)?;
        self.leaves = self.leaves.saturating_add(1);

        for height in 1..MAX_HEIGHT {
            let Some(span) = 1u64.checked_shl(u32::try_from(height).unwrap_or(u32::MAX)) else {
                break;
            };
            if span == 0 || self.leaves.checked_rem(span).is_none_or(|rest| rest != 0) {
                break;
            }
            let start = self.leaves.saturating_sub(span);
            let half = span.checked_div(2).unwrap_or(0);
            let lower = height.saturating_sub(1);
            let left = self.node(lower, start)?;
            let right = self.node(lower, start.saturating_add(half))?;
            let index = self.leaves.checked_div(span).unwrap_or(0).saturating_sub(1);
            self.write(height, index, node_hash(left, right))?;
        }
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
        self.trim_levels()
    }

    /// The proof for `position` as it stood when the forest held `leaves`.
    ///
    /// `leaves` rather than what is held now, because what a chain commits to
    /// is the forest from before its tip. A proof built against the wrong one
    /// of those two checks out nowhere.
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
            siblings.push(self.node(level, start)?);
            index = index.checked_shr(1).unwrap_or(0);
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

    /// Cuts every level back to what the leaves account for.
    fn trim_levels(&mut self) -> Result<(), StoreError> {
        for height in 0..MAX_HEIGHT {
            let want = self.filled(height).saturating_mul(NODE_BYTES);
            let path = self.path(height);
            if height > 0 && want == 0 && !path.exists() {
                // Nothing above this height can hold anything either.
                break;
            }
            let file = self.level(height)?;
            if file.metadata()?.len() != want {
                file.set_len(want)?;
                file.flush()?;
            }
        }
        Ok(())
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
