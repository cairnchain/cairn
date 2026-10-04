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

/// The first block of testnet-8, as bytes.
///
/// Mined once, in the open. Its coinbase pays nobody: a network should not
/// start with someone already holding something. What it says is what the
/// network started over for: the difficulty follows the clock, so a few
/// minutes of hired hash rate no longer stop the chain for a day and a half.
///
/// Provisional. Minted on the code a restart lands with by `cargo run
/// --release -p cairn-ledger --example remint`, which mints this block and
/// the devnet's together and writes both into every place that pins them,
/// on 4 October 2026 at 12:42:21 UTC. Its timestamp is `opens_at`, and the
/// retarget's schedule starts there, so it is minted again the day the
/// network opens: every target time a network opens after its first block is
/// dated is a block asked less than the network's real rate, down to the
/// floor.
const TESTNET_8: &str = "01005b524143000000000000000000000000000000000000000000000000000000000000000000000000000000006f3cc73c214804e789694adf801aa8db60858b3067698961f1d554b05e1c360c0b45c2ae07948141b7940f870815f8cd4831185355bd578d7409ae5d61cdcf732b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e2ad49c26a00000000000000100000000000000010000000000000000000000000b3cadf0000000000010000000000000000000000000032000000436169726e20746573746e65742d382e2054686520646966666963756c747920666f6c6c6f77732074686520636c6f636b2e00000000";

/// How long before it was minted the devnet's first block is dated.
///
/// `cairn-net/tests/pinned_network.rs` mines a thousand and ninety seven
/// devnet blocks forward from that block, each dated when a steady machine at
/// a hundred and twenty eighth of the opening rate would find it, and dates
/// none of them past the wall clock. Under the schedule that chain spans
/// 7 585 seconds whatever day it is mined, two hours and six minutes, so the
/// first block has to stand at least that far behind the moment the test
/// runs. Two and a half hours leaves the test about twenty minutes to grow,
/// and asks a devnet opened the day the block is minted for about eighteen
/// hundred blocks at the floor before it has caught its schedule up, where
/// the twenty nine days this used to be asked half a million. The test holds
/// its chain under this.
pub const DEVNET_DATED_EARLY: u64 = 2 * 3_600 + 30 * 60;

/// The first block of the throwaway network.
///
/// Says what it is, and pays nobody, like every first block here. Minted
/// alongside testnet-8's, by the same command and for the same reason, and
/// because devnet's marker moved too (`NetworkId::DEVNET` is no longer
/// `NetworkId::DEVNET_2`), which changes every byte after it.
///
/// Dated [`DEVNET_DATED_EARLY`] before it was minted, on purpose, so that the
/// test that mines forward from this exact block finds the wall clock ahead
/// of its chain. The schedule starts at this timestamp, so a devnet opened
/// later than that stands behind its schedule by the difference and is asked
/// the floor until it has caught up, about seventeen thousand blocks for every
/// day: `tests/the_difficulty_follows_the_clock.rs` measures a month. So it is
/// minted again with every restart, and a devnet is best opened on the build
/// that carries a fresh one.
const DEVNET: &str = "01004652414300000000000000000000000000000000000000000000000000000000000000000000000000000000dfe46a6f2e26f175ffa4d4a6b2522ca93a3fa73c7a1ef971637289623c5d03270b45c2ae07948141b7940f870815f8cd4831185355bd578d7409ae5d61cdcf732b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e28526c26a00000000000080000000000000008000000000000000000000000000c9c50d0000000000010000000000000000000000000022000000436169726e206465766e65742e205468726f77617761792062792064657369676e2e00000000";

fn encoded(network: NetworkId) -> Option<&'static str> {
    let text = match network {
        NetworkId::TESTNET_8 => TESTNET_8,
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
        [NetworkId::TESTNET_8, NetworkId::DEVNET]
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

    /// The two numbers everything else is pinned to, written out so that a
    /// block replaced without replacing what names it stops the build rather
    /// than the network. The README quotes both for both networks, and
    /// `cargo run --release -p cairn-ledger --example remint` rewrites them
    /// here and there together.
    #[test]
    fn the_pinned_identifier_and_opening_are_what_is_published() {
        for (network, identifier, opened) in [
            (
                NetworkId::TESTNET_8,
                "0000000777f0c8c223e98a202ed43c227cc34ea747f9d4f431d90cd1210b3ff6",
                1_791_117_741,
            ),
            (
                NetworkId::DEVNET,
                "000001a9e0d623a232656b552a3fe801127c0f01dcd9e4b781d2892f4e8efb0b",
                1_791_108_741,
            ),
        ] {
            let first = block(network).unwrap();
            assert_eq!(
                cairn_primitives::hex::encode(first.id().as_bytes()),
                identifier,
                "{network}"
            );
            assert_eq!(opens_at(network), opened, "{network}");
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
        assert_ne!(pinned(NetworkId::TESTNET_8), pinned(NetworkId::DEVNET));
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
