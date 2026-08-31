//! The first block of each network.
//!
//! A network is its first block. Two people who each start a node without one
//! agreed upon build two chains and never find out, and a node that asks a
//! stranger where the story begins can be told anything at all. So the block
//! is written here, in the open, and every node checks the chain it is offered
//! descends from it.
//!
//! What is written here is not a promise, it is bytes. Anyone can recompute
//! the identifier from them, check the work behind it, and read what the block
//! says. Putting it in the source is what removes the need to trust a peer;
//! what remains is trusting the program, which unlike a peer can be read,
//! rebuilt, and compared.

use cairn_primitives::codec::Decode;
use cairn_primitives::Hash32;

use crate::block::Block;
use crate::note::NetworkId;

/// The first block of testnet-4, as bytes.
///
/// Mined once, in the open. Its coinbase pays nobody: a network should not
/// start with someone already holding something.
const TESTNET_4: &str = "010057524143000000000000000000000000000000000000000000000000000000000000000000000000000000001c57b5409c87c207a51a7afb6de0a6872e55c4a9505143b310eaa30cac30f792b99665b29f3e16eda0932413c217ec72dcb6ec0c4f5875ec41ed0dc235759b732b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e2088f956a000000000000000800000000000000080000000000000000000000001abf930500000000010000000000000000000000000037000000436169726e20746573746e65742d342e20412070726f6f6620697320776f727468207768617420697420697320776f727468206e6f772e00000000";

/// The first block of the throwaway network.
///
/// Says what it is, and pays nobody, like every first block here.
const DEVNET: &str = "01004452414300000000000000000000000000000000000000000000000000000000000000000000000000000000dfe46a6f2e26f175ffa4d4a6b2522ca93a3fa73c7a1ef971637289623c5d0327b99665b29f3e16eda0932413c217ec72dcb6ec0c4f5875ec41ed0dc235759b732b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e23190956a00000000000080000000000000008000000000000000000000000000dff14e0000000000010000000000000000000000000022000000436169726e206465766e65742e205468726f77617761792062792064657369676e2e00000000";

fn encoded(network: NetworkId) -> Option<&'static str> {
    let text = match network {
        NetworkId::TESTNET_4 => TESTNET_4,
        NetworkId::DEVNET => DEVNET,
        _ => return None,
    };
    if text.is_empty() {
        return None;
    }
    Some(text)
}

/// The first block of `network`, if it has one yet.
pub fn block(network: NetworkId) -> Option<Block> {
    let bytes = cairn_primitives::hex::decode(encoded(network)?)?;
    Block::decode(&bytes).ok()
}

/// The identifier every chain on `network` must start from.
pub fn pinned(network: NetworkId) -> Option<Hash32> {
    block(network).map(|block| block.id())
}

/// The moment `network` opened, before which no block may be dated.
pub fn opens_at(network: NetworkId) -> u64 {
    block(network).map_or(0, |block| block.header.timestamp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::pow::meets_target;

    fn networks() -> [NetworkId; 2] {
        [NetworkId::TESTNET_4, NetworkId::DEVNET]
    }

    #[test]
    fn every_named_network_starts_from_a_real_block() {
        for network in networks() {
            let block = block(network).expect("a network is its first block");
            assert_eq!(block.header.height, 0);
            assert_eq!(block.header.previous, Hash32::ZERO);
            assert_eq!(block.header.network, network);
            assert!(block.transfers.is_empty());
        }
    }

    #[test]
    fn the_work_behind_each_one_is_real() {
        for network in networks() {
            let block = block(network).unwrap();
            assert!(
                meets_target(&block.id(), block.header.difficulty),
                "{network:?} was written down without the work behind it"
            );
            assert!(
                block.header.difficulty > 1,
                "a first block must not be free"
            );
        }
    }

    #[test]
    fn nobody_starts_out_holding_anything() {
        for network in networks() {
            let block = block(network).unwrap();
            assert!(
                block.coinbase.outputs.is_empty(),
                "{network:?} opens with someone already paid"
            );
        }
    }

    #[test]
    fn each_one_says_what_it_is() {
        for network in networks() {
            let block = block(network).unwrap();
            let said = String::from_utf8(block.coinbase.extra.clone()).expect("readable");
            assert!(!said.is_empty(), "{network:?} says nothing about itself");
        }
    }

    #[test]
    fn the_networks_do_not_share_a_beginning() {
        assert_ne!(pinned(NetworkId::TESTNET_4), pinned(NetworkId::DEVNET));
        assert_eq!(
            pinned(NetworkId::MAINNET),
            None,
            "mainnet has not been made"
        );
    }

    #[test]
    fn a_network_opens_when_its_first_block_is_dated() {
        for network in networks() {
            let block = block(network).unwrap();
            assert_eq!(opens_at(network), block.header.timestamp);
        }
        assert_eq!(opens_at(NetworkId::MAINNET), 0);
    }
}
