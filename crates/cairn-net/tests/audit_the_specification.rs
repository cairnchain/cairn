//! The versions the specification says this build speaks, held to the code.
//!
//! The handshake paragraph said the protocol version "is 7 today" through the
//! whole of version eight. A number copied into prose has no reader but a
//! person, so nothing noticed when the constant moved.

use cairn_ledger::block::BLOCK_VERSION;
use cairn_net::PROTOCOL_VERSION;

/// The specification with every run of whitespace made one space, so that a
/// phrase is found whichever line it was wrapped across.
fn specification() -> String {
    include_str!("../../../docs/cairn-specification.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_specification_states_the_protocol_version_this_build_speaks() {
    let stated = format!("handshake, it is {PROTOCOL_VERSION} today,");
    assert!(
        specification().contains(&stated),
        "the specification does not say `{stated}`"
    );
}

#[test]
fn the_specification_states_the_highest_block_version_this_build_knows() {
    let stated = format!("up to a ceiling, which is {BLOCK_VERSION} today.");
    assert!(
        specification().contains(&stated),
        "the specification does not say `{stated}`"
    );
}
