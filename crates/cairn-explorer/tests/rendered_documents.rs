//! The HTML this program serves is what the Markdown beside it renders to.
//!
//! A document is now a pair of files: the Markdown somebody writes and the
//! HTML `cairn-docs` makes from it, which is the one compiled into this binary
//! and handed to a reader. Nothing at run time reads the Markdown, so a change
//! made in one and not the other would ship silently: the page would keep
//! saying the old thing while the repository showed the new one, and the
//! person who edited it would have no way to notice.
//!
//! So the pair is held here. Edit either file without running
//! `cargo run -p cairn-docs` and this fails, with the first line that differs.
//!
//! This is the same discipline as the figure guards next door, one level up: a
//! published number is held to the code that produces it, and a published page
//! is held to the source it is produced from.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::Path;

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|why| panic!("{} could not be read: {why}", path.display()))
}

/// The first line the two disagree on, said the way a diff would say it.
///
/// Comparing two files of a thousand lines with `assert_eq!` prints both of
/// them and tells nobody anything.
fn first_difference(rendered: &str, committed: &str) -> Option<String> {
    let mut wanted = rendered.lines();
    let mut found = committed.lines();
    let mut at = 1usize;
    loop {
        match (wanted.next(), found.next()) {
            (None, None) => return None,
            (left, right) if left == right => at += 1,
            (left, right) => {
                return Some(format!(
                    "line {at}\n  the Markdown renders: {}\n  the file holds:       {}",
                    left.map_or("<end of file>", str::trim_end),
                    right.map_or("<end of file>", str::trim_end),
                ))
            }
        }
    }
}

#[test]
fn the_committed_html_is_what_the_markdown_renders_to() {
    for document in cairn_docs::DOCUMENTS {
        let markdown = read(&cairn_docs::markdown_path(document));
        let rendered = cairn_docs::render(&markdown)
            .unwrap_or_else(|said| panic!("{document}.md does not render: {said}"));
        let committed = read(&cairn_docs::html_path(document));
        println!(
            "{document}: {} lines of Markdown, {} of HTML",
            markdown.lines().count(),
            rendered.lines().count()
        );
        // The whole string, not a walk over the lines: `lines()` cannot see a
        // trailing newline that one of them has and the other has not, and a
        // guard that passes on a file it did not fully read is not a guard.
        if rendered != committed {
            let apart = first_difference(&rendered, &committed).unwrap_or_else(|| {
                "the very end: one of them ends in a newline and the other does not".to_owned()
            });
            panic!(
                "{document}.html is not what {document}.md renders to, at {apart}\n\
                 Run `cargo run -p cairn-docs` and commit both files."
            );
        }
    }
}

/// Every Markdown document in the folder is one the generator knows about.
///
/// A document left out of the list is one nobody regenerates: it would render
/// once, by hand, and then drift for good while the test above went on passing
/// because it never looked at it.
#[test]
fn no_markdown_document_is_left_out_of_the_list() {
    let folder = cairn_docs::folder();
    let mut found = Vec::new();
    for entry in std::fs::read_dir(&folder)
        .expect("the documents folder")
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_some_and(|kind| kind == "md") {
            let name = path
                .file_stem()
                .expect("a file with an extension has a stem")
                .to_string_lossy()
                .into_owned();
            if name != "README" {
                found.push(name);
            }
        }
    }
    found.sort();
    let mut listed: Vec<String> = cairn_docs::DOCUMENTS
        .iter()
        .map(|d| (*d).to_owned())
        .collect();
    listed.sort();
    assert_eq!(
        found,
        listed,
        "the Markdown in {} is not the list in cairn-docs. Add it to DOCUMENTS, or \
         it is a file nobody regenerates",
        folder.display()
    );
}
