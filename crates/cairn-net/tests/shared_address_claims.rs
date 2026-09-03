//! What one peer's broken claim costs the peer beside it.
//!
//! A claim that fails is remembered against the address it came from, because
//! the address is the only thing that survives a reconnection: a peer that
//! failed and dialled back is, from here, indistinguishable from a second peer
//! behind the same gateway. Without that, a broken claim is washed clean by
//! hanging up.
//!
//! What that must not become is a verdict on everyone at the address. It was
//! one: a claim inheriting the mark was thrown out of the choice outright, so
//! a node behind one carrier NAT, one office, or one machine running a devnet
//! had its heavier chain ignored, and the node went on to follow a lighter one
//! it could see was lighter, on the strength of who else shared an address
//! with it.
//!
//! A pause does what the exclusion was for, and stops there.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::net::{IpAddr, Ipv4Addr};

use cairn_net::choosing::{Approach, Chooser, JoinProgress, Step};
use cairn_net::sync::JOIN_RATHER_THAN_READ;

/// Long enough for a claim to be final, which is what makes it a choice.
const LONG: u64 = JOIN_RATHER_THAN_READ + 10;

/// One NAT gateway, shared by a stranger and somebody honest.
fn gateway() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(100, 100, 5, 5))
}

fn elsewhere() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
}

/// A stranger that claims a chain from the gateway and cannot show it, then an
/// honest peer behind the same gateway with a heavier one, and the stranger's
/// second address in front of it with a lighter one.
fn after_a_broken_claim() -> Chooser {
    let mut chooser = Chooser::new();
    chooser.noted(1, Some(gateway()), 100, LONG, true, 1_000);
    assert!(matches!(
        chooser.step(1_003, true, 0, JoinProgress::NothingYet, &[1]),
        Step::Ask(1, _)
    ));
    chooser.failed(1, 1_004);

    chooser.noted(2, Some(gateway()), 1_000, LONG, true, 1_005);
    chooser.noted(3, Some(elsewhere()), 500, LONG, true, 1_005);
    chooser
}

/// **A neighbour's claim waits out the pause, and is then asked.**
///
/// Thirty seconds is what a peer that failed has to wait before it is worth
/// asking again, and a claim that only shares an address with one waits the
/// same. After that it is judged on its work like any other, which is what it
/// always should have been.
#[test]
fn a_claim_from_a_shared_address_waits_the_pause_and_is_then_asked() {
    let mut chooser = after_a_broken_claim();

    // Inside the pause the lighter claim from elsewhere is what there is to
    // ask, and that is right: this could be the same stranger dialling back.
    assert_eq!(
        chooser.step(1_006, true, 0, JoinProgress::NothingYet, &[1, 2, 3]),
        Step::Ask(3, Approach::Join),
        "inside the pause, the claim sharing an address with a broken one waits"
    );

    // Past it, the heavier claim is asked, because sharing an address with a
    // stranger is not evidence about a chain.
    let mut chooser = after_a_broken_claim();
    assert_eq!(
        chooser.step(1_040, true, 0, JoinProgress::NothingYet, &[1, 2, 3]),
        Step::Ask(2, Approach::Join),
        "past the pause, the heavier claim was still shut out"
    );
}

/// **And nothing lighter is committed to while it is still waiting.**
///
/// The other half, and the one that cost a node its chain. A claim thrown out
/// of the choice was also thrown out of the last look before a commitment, so
/// the node adopted a chain it could see was lighter and stopped looking. A
/// claim that is merely waiting still counts against that.
#[test]
fn a_lighter_chain_is_not_committed_to_while_a_heavier_claim_waits() {
    let mut chooser = after_a_broken_claim();
    assert_eq!(
        chooser.step(1_006, true, 0, JoinProgress::NothingYet, &[1, 2, 3]),
        Step::Ask(3, Approach::Join)
    );
    assert!(
        !chooser.shown(3, 500, 1_010),
        "a chain of 500 was adopted while a claim of 1000 stood, unasked"
    );
    assert!(
        !chooser.allows(3, 500, 1_010),
        "and the commitment was allowed on a second look"
    );
}

/// **A broken claim is still not washed clean by reconnecting.**
///
/// The half the memory exists for. The same address, a new connection, and a
/// claim of the earth: inside the pause it is offered a read and never a
/// handover, which is the whole of the difference. A handover is taken on the
/// strength of the claim behind it; a read is checked block by block as it
/// arrives, so it cannot be captured by claiming anything at all.
#[test]
fn a_reconnect_from_the_same_address_is_read_rather_than_taken_at_its_word() {
    let mut chooser = Chooser::new();
    chooser.noted(1, Some(gateway()), 100, LONG, true, 1_000);
    assert!(matches!(
        chooser.step(1_003, true, 0, JoinProgress::NothingYet, &[1]),
        Step::Ask(1, _)
    ));
    chooser.failed(1, 1_004);

    // Dialling back at once, claiming the earth.
    chooser.noted(7, Some(gateway()), u128::MAX, LONG, true, 1_005);
    assert_eq!(
        chooser.step(1_006, true, 0, JoinProgress::NothingYet, &[1, 7]),
        Step::Ask(7, Approach::Read),
        "hanging up and dialling back bought a handover on the strength of a \
         claim that had just failed"
    );

    // And once the pause runs out it is asked like anybody else, because the
    // memory buys a wait rather than a verdict.
    let mut chooser = Chooser::new();
    chooser.noted(1, Some(gateway()), 100, LONG, true, 1_000);
    assert!(matches!(
        chooser.step(1_003, true, 0, JoinProgress::NothingYet, &[1]),
        Step::Ask(1, _)
    ));
    chooser.failed(1, 1_004);
    chooser.noted(7, Some(gateway()), 2_000, LONG, true, 1_005);
    assert_eq!(
        chooser.step(1_040, true, 0, JoinProgress::NothingYet, &[1, 7]),
        Step::Ask(7, Approach::Join)
    );
}
