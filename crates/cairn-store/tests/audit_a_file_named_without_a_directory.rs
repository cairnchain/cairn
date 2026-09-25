//! A file named with no directory in front of it, which is what a node given
//! an empty data directory writes.
//!
//! Replacing a file waits for the directory it sits in, and for a bare name
//! the directory `Path::parent` gives is the empty string, which no platform
//! opens. `sync_the_directory_of` has a guard for exactly that, and `lib.rs`
//! recorded it as out of reach: reaching it means writing into the directory
//! the test process runs in, which is the repository.
//!
//! A test can choose that directory. This one moves its process into a
//! scratch directory before it writes, and is alone in its file, because the
//! directory a process runs in is shared by every test in the same binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use cairn_store::{write_beside_and_move, HANDED_LEDGER};

/// A file replaced under a bare name is replaced, and says so.
///
/// Read as always true, or with its `!` taken away, the guard sent the empty
/// string to be opened and synced. The file was already in place by then, and
/// the replacement reported a failure on a disk that was fine, which a node
/// takes as a write that did not happen.
#[test]
fn a_file_named_without_a_directory_is_replaced_without_asking_the_empty_path_for_anything() {
    let directory = std::env::temp_dir().join(format!("cairn-bare-name-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    std::env::set_current_dir(&directory).unwrap();

    let written = write_beside_and_move(Path::new(HANDED_LEDGER), b"a ledger");
    assert!(
        written.is_ok(),
        "replacing a file in the current directory failed on a disk that is \
         fine: {written:?}"
    );
    assert_eq!(
        std::fs::read(directory.join(HANDED_LEDGER)).unwrap(),
        b"a ledger",
        "the file does not hold what was written"
    );
    assert!(
        !directory.join(format!("{HANDED_LEDGER}.part")).exists(),
        "the staged copy was left beside it"
    );

    std::env::set_current_dir(std::env::temp_dir()).unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}
