//! The compact sparse Merkle tree.

use std::sync::OnceLock;

use cairn_primitives::codec::Encode;
use cairn_primitives::hash::{hash, Domain, Hasher};
use cairn_primitives::Hash32;

use crate::key::{Key, MAX_DEPTH};
use crate::proof::Proof;

/// The commitment of a subtree holding nothing.
pub fn empty_hash() -> Hash32 {
    static EMPTY: OnceLock<Hash32> = OnceLock::new();
    *EMPTY.get_or_init(|| hash(Domain::AccumulatorEmpty, &[]))
}

pub(crate) fn leaf_hash(key: &Key, value: &Hash32) -> Hash32 {
    let mut hasher = Hasher::new(Domain::AccumulatorLeaf);
    hasher.update(&key.encode());
    hasher.update(value.as_bytes());
    hasher.finalize()
}

pub(crate) fn node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let mut hasher = Hasher::new(Domain::AccumulatorNode);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finalize()
}

#[derive(Clone, Debug)]
enum Node {
    Empty,
    Leaf {
        key: Key,
        value: Hash32,
    },
    Internal {
        hash: Hash32,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Node {
    fn hash(&self) -> Hash32 {
        match self {
            Self::Empty => empty_hash(),
            Self::Leaf { key, value } => leaf_hash(key, value),
            Self::Internal { hash, .. } => *hash,
        }
    }

    fn internal(left: Self, right: Self) -> Self {
        let hash = node_hash(left.hash(), right.hash());
        Self::Internal {
            hash,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

/// Rebuilds an internal node, dissolving it when a lone leaf is left below.
///
/// Without this, a tree would remember that a sibling once existed and its root
/// would depend on the order operations were applied. Two nodes holding the
/// same set would then disagree, which is the whole thing the accumulator has
/// to get right.
fn collapse(left: Node, right: Node) -> Node {
    let left_empty = matches!(left, Node::Empty);
    let right_empty = matches!(right, Node::Empty);
    let left_leaf = matches!(left, Node::Leaf { .. });
    let right_leaf = matches!(right, Node::Leaf { .. });

    if left_empty && right_empty {
        Node::Empty
    } else if left_empty && right_leaf {
        right
    } else if right_empty && left_leaf {
        left
    } else {
        Node::internal(left, right)
    }
}

/// Grows the shared prefix of two keys into a chain of nodes.
fn split(existing_key: Key, existing_value: Hash32, key: Key, value: Hash32, depth: usize) -> Node {
    if depth >= MAX_DEPTH {
        // Unreachable for distinct keys, which diverge before the last bit.
        return Node::Leaf { key, value };
    }
    let existing_bit = existing_key.bit(depth);
    let new_bit = key.bit(depth);
    let existing = Node::Leaf {
        key: existing_key,
        value: existing_value,
    };
    let fresh = Node::Leaf { key, value };

    if existing_bit == new_bit {
        let child = split(
            existing_key,
            existing_value,
            key,
            value,
            depth.saturating_add(1),
        );
        if new_bit {
            Node::internal(Node::Empty, child)
        } else {
            Node::internal(child, Node::Empty)
        }
    } else if new_bit {
        Node::internal(existing, fresh)
    } else {
        Node::internal(fresh, existing)
    }
}

fn insert_at(node: Node, depth: usize, key: Key, value: Hash32) -> (Node, Option<Hash32>) {
    match node {
        Node::Empty => (Node::Leaf { key, value }, None),
        Node::Leaf {
            key: existing_key,
            value: existing_value,
        } => {
            if existing_key == key {
                (Node::Leaf { key, value }, Some(existing_value))
            } else {
                (split(existing_key, existing_value, key, value, depth), None)
            }
        }
        Node::Internal { left, right, .. } => {
            let deeper = depth.saturating_add(1);
            let (left, right, replaced) = if key.bit(depth) {
                let (right, replaced) = insert_at(*right, deeper, key, value);
                (*left, right, replaced)
            } else {
                let (left, replaced) = insert_at(*left, deeper, key, value);
                (left, *right, replaced)
            };
            (Node::internal(left, right), replaced)
        }
    }
}

fn remove_at(node: Node, depth: usize, key: Key) -> (Node, Option<Hash32>) {
    match node {
        Node::Empty => (Node::Empty, None),
        Node::Leaf {
            key: existing_key,
            value,
        } => {
            if existing_key == key {
                (Node::Empty, Some(value))
            } else {
                (
                    Node::Leaf {
                        key: existing_key,
                        value,
                    },
                    None,
                )
            }
        }
        Node::Internal { left, right, .. } => {
            let deeper = depth.saturating_add(1);
            let (left, right, removed) = if key.bit(depth) {
                let (right, removed) = remove_at(*right, deeper, key);
                (*left, right, removed)
            } else {
                let (left, removed) = remove_at(*left, deeper, key);
                (left, *right, removed)
            };
            (collapse(left, right), removed)
        }
    }
}

/// One edit to apply to the accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Insert { key: Key, value: Hash32 },
    Remove { key: Key },
}

/// A set of key and value pairs committed to by a single 32 byte root.
///
/// The root depends only on the set's contents, never on the order the entries
/// were added or removed.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    root: Node,
    len: usize,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            root: Node::Empty,
            len: 0,
        }
    }

    /// The commitment. This is the only part a node has to store.
    pub fn root(&self) -> Hash32 {
        self.root.hash()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds or replaces an entry, returning the value it displaced.
    pub fn insert(&mut self, key: Key, value: Hash32) -> Option<Hash32> {
        let root = std::mem::replace(&mut self.root, Node::Empty);
        let (root, replaced) = insert_at(root, 0, key, value);
        self.root = root;
        if replaced.is_none() {
            self.len = self.len.saturating_add(1);
        }
        replaced
    }

    /// Drops an entry, returning the value it held.
    pub fn remove(&mut self, key: Key) -> Option<Hash32> {
        let root = std::mem::replace(&mut self.root, Node::Empty);
        let (root, removed) = remove_at(root, 0, key);
        self.root = root;
        if removed.is_some() {
            self.len = self.len.saturating_sub(1);
        }
        removed
    }

    pub fn get(&self, key: Key) -> Option<Hash32> {
        let mut node = &self.root;
        let mut depth = 0usize;
        loop {
            match node {
                Node::Empty => return None,
                Node::Leaf { key: found, value } => {
                    return if *found == key { Some(*value) } else { None };
                }
                Node::Internal { left, right, .. } => {
                    node = if key.bit(depth) { right } else { left };
                    depth = depth.saturating_add(1);
                }
            }
        }
    }

    pub fn contains(&self, key: Key) -> bool {
        self.get(key).is_some()
    }

    /// Applies a batch of edits in order and returns the resulting root.
    pub fn apply(&mut self, changes: &[Change]) -> Hash32 {
        for change in changes {
            match *change {
                Change::Insert { key, value } => {
                    self.insert(key, value);
                }
                Change::Remove { key } => {
                    self.remove(key);
                }
            }
        }
        self.root()
    }

    /// Builds the proof for `key`.
    ///
    /// The same walk answers both questions: if the path ends on `key` the
    /// proof shows membership, and otherwise it shows absence.
    pub fn prove(&self, key: Key) -> Proof {
        let mut siblings = Vec::new();
        let mut node = &self.root;
        let mut depth = 0usize;

        loop {
            match node {
                Node::Internal { left, right, .. } => {
                    if key.bit(depth) {
                        siblings.push(left.hash());
                        node = right;
                    } else {
                        siblings.push(right.hash());
                        node = left;
                    }
                    depth = depth.saturating_add(1);
                }
                Node::Leaf { key: found, value } => {
                    let occupant = if *found == key {
                        None
                    } else {
                        Some((*found, *value))
                    };
                    siblings.reverse();
                    return Proof::new(siblings, occupant);
                }
                Node::Empty => {
                    siblings.reverse();
                    return Proof::new(siblings, None);
                }
            }
        }
    }
}
