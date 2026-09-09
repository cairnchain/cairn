//! The documents, written in Markdown and rendered to the HTML a node serves.
//!
//! Every paper used to be written as HTML by hand. That meant a change could
//! not be read in a diff, a section number was a figure nobody checked, and a
//! test looking for a phrase was looking through markup. So the source is
//! Markdown now, the HTML is generated beside it, and
//! `crates/cairn-explorer/tests/rendered_documents.rs` fails when the two part
//! company.
//!
//! What comes out is the same shape the explorer already serves: a fragment
//! with no `<html>` and no `<head>`, because `cairn-explorer/src/assets.rs`
//! glues the declaration a browser needs onto the front of it. Nothing that
//! ships depends on this crate. It is a tool that writes files into `docs/`,
//! run by hand with `cargo run -p cairn-docs`.
//!
//! `docs/README.md` is the contributor's side of this: what the front matter
//! carries and what to run after editing.

mod front;
mod render;

use std::fmt;
use std::path::PathBuf;

pub use render::render;

/// Every document this crate renders, named without its extension.
///
/// A document that is not here is not generated, which is the whole of the
/// difference between a Markdown source and a file somebody left in the
/// folder. The four papers still written as HTML by hand are absent on
/// purpose; they are migrated one at a time.
pub const DOCUMENTS: [&str; 1] = ["cairn-whitepaper"];

/// Where the documents live, found from this crate rather than from wherever
/// the command was run, so `cargo run -p cairn-docs` writes the same files
/// from any directory.
#[must_use]
pub fn folder() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
}

/// The Markdown a document is written in.
#[must_use]
pub fn markdown_path(document: &str) -> PathBuf {
    folder().join(format!("{document}.md"))
}

/// The HTML that Markdown renders to, which is the file a node serves.
#[must_use]
pub fn html_path(document: &str) -> PathBuf {
    folder().join(format!("{document}.html"))
}

/// What a document got wrong, said in the words a writer can act on.
///
/// One kind rather than a family of them: everything here is "this document
/// says something this renderer cannot turn into the house shape", and the
/// sentence is the whole of the information.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub(crate) fn new(said: impl Into<String>) -> Self {
        Self(said.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// What every step here answers with.
pub type Result<T> = std::result::Result<T, Error>;
