//! Membership and absence proofs.

use cairn_primitives::codec::{take_at_most, CodecError, Decode, Encode, Reader};
use cairn_primitives::Hash32;

use crate::key::{Key, MAX_DEPTH};
use crate::tree::{empty_hash, leaf_hash, node_hash};

/// Everything needed to check one entry against a root, without the tree.
///
/// Siblings run from the deepest level up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    siblings: Vec<Hash32>,
    /// The entry that occupies the position the key would take, when the path
    /// ends on a different key. Present only in an absence proof.
    occupant: Option<(Key, Hash32)>,
}

impl Proof {
    pub(crate) fn new(siblings: Vec<Hash32>, occupant: Option<(Key, Hash32)>) -> Self {
        Self { siblings, occupant }
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Bytes this proof takes on the wire.
    pub fn size_in_bytes(&self) -> usize {
        let siblings = self.siblings.len().saturating_mul(32);
        let occupant = if self.occupant.is_some() { 64 } else { 0 };
        siblings.saturating_add(occupant).saturating_add(5)
    }

    /// Whether `key` maps to `value` under `root`.
    pub fn verify_membership(&self, root: Hash32, key: Key, value: Hash32) -> bool {
        if self.occupant.is_some() || self.siblings.len() > MAX_DEPTH {
            return false;
        }
        self.fold(leaf_hash(&key, &value), key) == root
    }

    /// Whether `key` maps to nothing under `root`.
    pub fn verify_absence(&self, root: Hash32, key: Key) -> bool {
        if self.siblings.len() > MAX_DEPTH {
            return false;
        }
        let start = match self.occupant {
            None => empty_hash(),
            Some((occupant_key, occupant_value)) => {
                if occupant_key == key {
                    return false;
                }
                // The occupant has to sit where the key's own path leads,
                // otherwise the proof describes an unrelated position.
                if !occupant_key.shares_prefix(&key, self.siblings.len()) {
                    return false;
                }
                leaf_hash(&occupant_key, &occupant_value)
            }
        };
        self.fold(start, key) == root
    }

    fn fold(&self, start: Hash32, key: Key) -> Hash32 {
        let deepest = self.siblings.len().saturating_sub(1);
        let mut current = start;
        for (offset, sibling) in self.siblings.iter().enumerate() {
            let depth = deepest.saturating_sub(offset);
            current = if key.bit(depth) {
                node_hash(*sibling, current)
            } else {
                node_hash(current, *sibling)
            };
        }
        current
    }
}

impl Encode for Proof {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.siblings.encode_to(out);
        match self.occupant {
            None => 0u8.encode_to(out),
            Some((key, value)) => {
                1u8.encode_to(out);
                key.encode_to(out);
                value.encode_to(out);
            }
        }
    }
}

impl Decode for Proof {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let siblings: Vec<Hash32> = take_at_most(reader, MAX_DEPTH, "Proof")?;
        let occupant = match u8::decode_from(reader)? {
            0 => None,
            1 => Some((Key::decode_from(reader)?, Hash32::decode_from(reader)?)),
            _ => return Err(CodecError::InvalidValue { type_name: "Proof" }),
        };
        Ok(Self { siblings, occupant })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use cairn_primitives::codec::MAX_SEQUENCE_LEN;

    /// A proof promising more siblings than a key has bits is refused at the
    /// count.
    ///
    /// Same shape as the forest's, and said plainly: nothing in this workspace
    /// decodes one of these off a wire. The impl is public and the crate is a
    /// library, so it is somebody's decoder even if it is nobody's here, and
    /// the cost of holding it to the same rule as its neighbour is one line.
    /// It is listed as the weakest of the three on purpose.
    #[test]
    fn a_proof_promising_more_siblings_than_a_key_has_bits_is_refused_at_the_count() {
        let promise = u32::try_from(MAX_SEQUENCE_LEN).unwrap().encode();
        assert_eq!(
            Proof::decode(&promise),
            Err(CodecError::InvalidValue { type_name: "Proof" })
        );

        let deepest = Proof::new(vec![Hash32::ZERO; MAX_DEPTH], None);
        assert_eq!(
            Proof::decode(&deepest.encode()).as_ref(),
            Ok(&deepest),
            "the deepest path a key can take has to survive the wire"
        );
    }
}
