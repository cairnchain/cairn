//! What the wallet makes of a command line argument that is not text.

#![allow(clippy::unwrap_used, clippy::expect_used)]

/// An argument that is not text is a command line the wallet cannot read,
/// and is answered with a message and 2, the code for one.
///
/// Nothing asked this, so the arguments were read with `std::env::args`,
/// which panics on one that is not Unicode, and a key file named with a stray
/// byte was answered with a Rust panic and 101.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_text_is_answered_with_a_message_and_two() {
    use std::os::unix::ffi::OsStrExt as _;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .arg("address")
        .arg("--key")
        .arg(std::ffi::OsStr::from_bytes(b"wallet-\xff.key"))
        .output()
        .expect("the wallet runs");
    let complained = String::from_utf8_lossy(&output.stderr);
    assert!(
        !complained.contains("panicked"),
        "an argument that is not text was answered with a panic: {complained}"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an argument that is not text was not answered as a command line the wallet cannot \
         read: {complained}"
    );
    assert!(
        complained.contains("is not text"),
        "and the message does not say what was wrong with it: {complained}"
    );
}
