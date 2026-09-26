//! What the daily release looks at, against what the programs are built from.
//!
//! `release.yml` publishes a release on a scheduled run only when something a
//! program is built from has changed since the last one, and it decides that
//! from a list of paths. A file compiled into a program and missing from that
//! list is a change people download that is never released until something
//! else happens to move.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Component, Path, PathBuf};

const RELEASE: &str = include_str!("../../../.github/workflows/release.yml");

/// Crates in the workspace that are in none of the three programs, as the
/// workflow says beside the list.
const IN_NO_PROGRAM: [&str; 2] = ["cairn-docs", "cairn-fuzz"];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `path` with `..` and `.` taken out, without asking the disk.
fn tidy(path: &Path) -> PathBuf {
    let mut tidied = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                tidied.pop();
            }
            Component::CurDir => {}
            other => tidied.push(other),
        }
    }
    tidied
}

/// The source of a file with every item marked `#[cfg(test)]` left out, since
/// nothing in one is in a program.
///
/// Read by indentation, which rustfmt settles: an item closes on a line
/// holding its own indentation and a brace.
fn outside_tests(source: &str) -> String {
    let mut kept = String::new();
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "#[cfg(test)]" {
            kept.push_str(line);
            kept.push('\n');
            continue;
        }
        let Some(item) = lines
            .by_ref()
            .find(|line| !line.trim_start().starts_with("#["))
        else {
            break;
        };
        if item.trim_end().ends_with(';') {
            continue;
        }
        let indent = &item[..item.len() - item.trim_start().len()];
        let closing = format!("{indent}}}");
        for line in lines.by_ref() {
            if line.trim_end() == closing {
                break;
            }
        }
    }
    kept
}

/// Every file a crate's program code names by a relative path that leaves the
/// crate's own sources, as a path from the top of the repository.
fn named_from_outside(crate_directory: &Path, repository: &Path) -> Vec<String> {
    let sources = tidy(&crate_directory.join("src"));
    let mut found = Vec::new();
    let mut waiting = vec![sources.clone()];
    while let Some(directory) = waiting.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                waiting.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let code = outside_tests(&std::fs::read_to_string(&path).unwrap());
            for piece in code.split("\"../").skip(1) {
                let Some(rest) = piece.split('"').next() else {
                    continue;
                };
                let named = tidy(&path.parent().unwrap().join(format!("../{rest}")));
                if named.starts_with(&sources) || !named.is_file() {
                    continue;
                }
                let from_top = named
                    .strip_prefix(tidy(repository))
                    .unwrap()
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                found.push(from_top);
            }
        }
    }
    found
}

/// The paths the release decision compares, apart from the ones it works out
/// for each crate.
fn compared() -> Vec<&'static str> {
    let line = RELEASE
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("paths=\"$paths ") && !line.contains("$crate"))
        .expect("release.yml lists the paths it compares");
    line.trim_start_matches("paths=\"$paths ")
        .trim_end_matches('"')
        .split_whitespace()
        .collect()
}

/// Whether a path the workflow lists covers `path`, as git reads a pathspec.
fn covers(listed: &str, path: &str) -> bool {
    match listed.split_once('*') {
        Some((before, after)) => {
            path.starts_with(before) && path.ends_with(after) && path.len() >= listed.len() - 1
        }
        None => path == listed || path.starts_with(&format!("{listed}/")),
    }
}

/// Every file compiled into a program from outside its crate's sources is one
/// the daily release decision looks at.
///
/// The explorer compiles in its whole site and five papers: its own header
/// says the binary is the site. The decision compared each crate's sources
/// and manifest, the lock and the toolchain, and none of the site. A fix to
/// the script every explorer serves to the public changed what people
/// download while the log said that nothing a release is built from had
/// changed, and so did a change to the root manifest, which holds the release
/// profile and every dependency's features. Nothing read the list against
/// what the sources include.
#[test]
fn release_decision_sees_every_file_a_program_is_built_from() {
    let repository = repository();
    let listed = compared();
    let mut seen = 0usize;
    for entry in std::fs::read_dir(repository.join("crates")).unwrap() {
        let crate_directory = entry.unwrap().path();
        let name = crate_directory.file_name().unwrap().to_string_lossy();
        if IN_NO_PROGRAM.contains(&name.as_ref()) {
            continue;
        }
        for path in named_from_outside(&crate_directory, &repository) {
            seen += 1;
            // Another crate's sources, which the list works out crate by crate.
            if path.starts_with("crates/") && path.split('/').nth(2) == Some("src") {
                continue;
            }
            assert!(
                listed.iter().any(|listed| covers(listed, &path)),
                "{name} compiles in {path}, and the release decision does not look at it, so a \
                 change to it is downloaded by nobody until something else changes"
            );
        }
    }
    assert!(
        seen > 0,
        "nothing was found compiled in from outside a crate, which the explorer's site is"
    );
    assert!(
        listed.iter().any(|listed| covers(listed, "Cargo.toml")),
        "the root manifest holds the release profile and every dependency's features, and \
         the release decision does not look at it"
    );
}
