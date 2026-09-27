//! A failure is replayed from what the campaign printed about it.
//!
//! Its own binary, because it sets `CAIRN_FUZZ_SEED` for the process, and a
//! variable set in one test is read by every other test running beside it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cairn_fuzz::Campaign;

/// A seed typed back exactly as a campaign printed it is the seed that runs.
///
/// Every campaign reports itself as `seed 0x...`, and every failure message
/// in the suite names its case "of seed 0x...". The variable that replays a
/// run was read as a decimal number and anything it could not read was
/// ignored, so the seed as printed was quietly replaced by the default: the
/// replay ran another campaign, passed, and the failure was read as flaky.
/// Nothing asked this, so a seed that could only be replayed by retyping it
/// in decimal passed.
#[test]
fn a_seed_replayed_as_the_campaign_printed_it_is_the_seed_that_ran() {
    for seed in [0x4d2f_3a1b_u64, 1, u64::MAX, 0xCA12_F022_1D05_CA13] {
        let printed = format!("{seed:#x}");
        std::env::set_var("CAIRN_FUZZ_SEED", &printed);
        assert_eq!(
            Campaign::named("replay").seed(),
            seed,
            "a seed typed back exactly as the campaign printed it ran another seed, \
             so a reported failure replayed as reported runs a different campaign"
        );
    }

    // The workflow's own last line gives the seed in decimal, and a log from
    // before this change is read the same way.
    std::env::set_var("CAIRN_FUZZ_SEED", "1045783734");
    assert_eq!(
        Campaign::named("replay").seed(),
        1_045_783_734,
        "a seed given in decimal was not the seed that ran"
    );
}
