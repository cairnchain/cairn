//! Keeping two nodes out of one directory, and letting a restart back in.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::PathBuf;

use cairn_store::{DirectoryLock, StoreError};

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-lock-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory
}

#[test]
fn a_fresh_directory_can_be_locked() {
    let directory = scratch("fresh");
    let lock = DirectoryLock::acquire(&directory).unwrap();
    assert!(lock.path().exists());
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_second_holder_is_refused_while_the_first_lives() {
    let directory = scratch("contended");
    let first = DirectoryLock::acquire(&directory).unwrap();

    match DirectoryLock::acquire(&directory) {
        Err(StoreError::Locked { holder, .. }) => {
            // Who holds it is a courtesy, and one the platform decides. Unix
            // locks are advisory and leave the file readable, so the process
            // id written inside comes back. Windows locks cover the bytes, so
            // a file this node cannot lock is one it cannot read either, and
            // the message says that rather than inventing a holder.
            let named = format!("process {}", std::process::id());
            assert!(
                holder == named || holder == "another process",
                "unexpected holder: {holder}"
            );
        }
        Err(other) => panic!("expected a refusal, got {other}"),
        Ok(_) => panic!("two holders got the same directory"),
    }

    drop(first);
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn the_directory_is_free_again_once_the_holder_is_gone() {
    let directory = scratch("released");
    let first = DirectoryLock::acquire(&directory).unwrap();
    drop(first);

    DirectoryLock::acquire(&directory).expect("a released directory takes a new holder");
    let _ = std::fs::remove_dir_all(&directory);
}

/// The case a node hits after a machine loses power.
///
/// A lock file left behind by a process that never got to clean up must not
/// stop the next start. Anything else means an unattended restart needs a
/// person, which a node cannot afford.
#[test]
fn a_lock_file_left_by_a_dead_process_does_not_block_a_restart() {
    let directory = scratch("stale");
    let held = DirectoryLock::acquire(&directory).unwrap();
    let path = held.path().to_path_buf();
    // What a killed process leaves: the file, its contents, and no lock.
    drop(held);
    std::fs::write(&path, "999999").unwrap();
    assert!(path.exists());

    DirectoryLock::acquire(&directory).expect("a stale lock file must not block a restart");
    let _ = std::fs::remove_dir_all(&directory);
}
