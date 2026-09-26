//! Reading to the tip has one name in this crate, and it is bounded.
//!
//! `Wallet::follow_to_the_tip` was written because reading to the tip was
//! written out at eighteen places as a loop on `follow` with nothing in its
//! body and nothing to stop it, and a loop like that is a run which hangs
//! instead of failing when the reading breaks. Its doc says the eighteen were
//! replaced. One was not, and nothing looked.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

/// The loop's condition, in pieces so this file does not find itself.
const FOLLOWED: &str = concat!(".follow", "() > 0");

/// Every Rust file under `directory`, however deep.
fn sources(directory: &Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// No loop in this crate reads to the tip by calling `follow` until it
/// answers nought.
///
/// Nothing asked this, so a copy of the unbounded loop that survived the
/// sweep in `tests/recovery.rs` passed, and a wallet test that could not move
/// forward would have spun there for ever rather than failed.
#[test]
fn no_loop_reads_to_the_tip_without_a_bound() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&crate_root.join("src"), &mut files);
    sources(&crate_root.join("tests"), &mut files);
    assert!(files.len() > 10, "the walk found {} files", files.len());

    let mut unbounded = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        for (number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if code.contains("while ") && code.contains(FOLLOWED) {
                unbounded.push(format!(
                    "{}:{}",
                    file.strip_prefix(crate_root).unwrap_or(file).display(),
                    number + 1
                ));
            }
        }
    }
    assert!(
        unbounded.is_empty(),
        "reading to the tip written out as an unbounded loop on `follow` rather than \
         as `follow_to_the_tip`, at {unbounded:?}"
    );
}
