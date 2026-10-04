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
/// minutes of hired hash rate no longer stop the chain for 33 hours.
///
/// Provisional. Minted by `cargo run --release -p cairn-ledger --example
/// remint`, which mints this block and the devnet's together and writes both
/// into every place that pins them, and dated 4 October 2026 at 13:25:06 UTC.
/// Its timestamp is `opens_at`, and the retarget's schedule starts there:
/// every target time a network opens after its first block is dated is a
/// block asked less than the network's real rate, down to the floor. So it is
/// minted again before the release, dated at the opening announced for the
/// network (`-- --opens-at`), and a node started before that moment waits for
/// it. A release is refused until the first word of this paragraph is gone.
const TESTNET_8: &str = "01005b524143000000000000000000000000000000000000000000000000000000000000000000000000000000006f3cc73c214804e789694adf801aa8db60858b3067698961f1d554b05e1c360c0b45c2ae07948141b7940f870815f8cd4831185355bd578d7409ae5d61cdcf732b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e2b253c26a0000000000000010000000000000001000000000000000000000000026d5490900000000010000000000000000000000000032000000436169726e20746573746e65742d382e2054686520646966666963756c747920666f6c6c6f77732074686520636c6f636b2e00000000";

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
///
/// Written as one number rather than as hours and minutes multiplied out: a
/// mutation of that arithmetic is caught only by the test in `cairn-net`,
/// which a mutant of this crate is not run against.
pub const DEVNET_DATED_EARLY: u64 = 9_000;

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
const DEVNET: &str = "01004652414300000000000000000000000000000000000000000000000000000000000000000000000000000000dfe46a6f2e26f175ffa4d4a6b2522ca93a3fa73c7a1ef971637289623c5d03270b45c2ae07948141b7940f870815f8cd4831185355bd578d7409ae5d61cdcf732b8a7f4949a18c612a530d7dc3aa53b75b7fa4163daff6c2742422bdae5a12e28a30c26a000000000000800000000000000080000000000000000000000000007616420000000000010000000000000000000000000022000000436169726e206465766e65742e205468726f77617761792062792064657369676e2e00000000";

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

/// A moment the way this repository writes one for a person:
/// `6 October 2026 at 18:00:00 UTC`.
///
/// Here rather than in each program that says when a network opens, so that
/// the `remint` example, which writes these dates into the comments beside a
/// first block, and the node and the wallet, which tell a person waiting for
/// an opening when it is, say the same moment the same way.
pub fn when(timestamp: u64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let days = timestamp / 86_400;
    let seconds = timestamp % 86_400;
    // Days since 1970 to a civil date, after Howard Hinnant's
    // `civil_from_days`, for dates after the epoch. Nothing here comes near
    // overflowing for any timestamp, and saturating says so without a panic.
    let shifted = days.saturating_add(719_468);
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era = day_of_era
        .saturating_sub(day_of_era / 1_460)
        .saturating_add(day_of_era / 36_524)
        .saturating_sub(day_of_era / 146_096)
        / 365;
    let day_of_year = day_of_era.saturating_sub(
        year_of_era
            .saturating_mul(365)
            .saturating_add(year_of_era / 4)
            .saturating_sub(year_of_era / 100),
    );
    let month_index = day_of_year.saturating_mul(5).saturating_add(2) / 153;
    let day = day_of_year
        .saturating_sub(month_index.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1);
    let month = if month_index < 10 {
        month_index.saturating_add(3)
    } else {
        month_index.saturating_sub(9)
    };
    let year = year_of_era
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(month <= 2));
    let name = usize::try_from(month.saturating_sub(1))
        .ok()
        .and_then(|index| MONTHS.get(index))
        .copied()
        .unwrap_or_default();
    format!(
        "{day} {name} {year} at {:02}:{:02}:{:02} UTC",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
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
                "0000000270eb96cd530f6a3e8c0b3e3a6509b47f4d3393bb6a14d919bf565817",
                1_791_120_306,
            ),
            (
                NetworkId::DEVNET,
                "000000e13c0c16303f63e4bfd5e8e503acfe8102a559679964d7685903b6d8d6",
                1_791_111_306,
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

    /// The dates `remint` writes beside a first block and the node says to a
    /// person waiting for an opening, at the edges of a month, a year, a leap
    /// day and a century.
    #[test]
    fn a_moment_is_written_as_a_date_in_utc() {
        for (timestamp, said) in [
            (0, "1 January 1970 at 00:00:00 UTC"),
            (1_791_309_600, "6 October 2026 at 18:00:00 UTC"),
            (951_782_399, "28 February 2000 at 23:59:59 UTC"),
            (951_782_400, "29 February 2000 at 00:00:00 UTC"),
            (951_868_800, "1 March 2000 at 00:00:00 UTC"),
            (1_709_208_000, "29 February 2024 at 12:00:00 UTC"),
            (4_107_542_399, "28 February 2100 at 23:59:59 UTC"),
            (4_107_542_400, "1 March 2100 at 00:00:00 UTC"),
            (1_767_225_599, "31 December 2025 at 23:59:59 UTC"),
            (1_767_225_600, "1 January 2026 at 00:00:00 UTC"),
            (1_769_904_000, "1 February 2026 at 00:00:00 UTC"),
            (1_785_542_400, "1 August 2026 at 00:00:00 UTC"),
            (1_798_675_200, "31 December 2026 at 00:00:00 UTC"),
            (1_782_864_000, "1 July 2026 at 00:00:00 UTC"),
            (1_780_272_000, "1 June 2026 at 00:00:00 UTC"),
            (1_777_593_600, "1 May 2026 at 00:00:00 UTC"),
            (1_775_001_600, "1 April 2026 at 00:00:00 UTC"),
            (1_772_323_200, "1 March 2026 at 00:00:00 UTC"),
            (1_788_220_800, "1 September 2026 at 00:00:00 UTC"),
            (1_793_491_200, "1 November 2026 at 00:00:00 UTC"),
            (1_796_083_200, "1 December 2026 at 00:00:00 UTC"),
        ] {
            assert_eq!(when(timestamp), said, "{timestamp}");
        }
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
