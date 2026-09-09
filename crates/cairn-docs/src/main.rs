//! Renders every document in `docs/` from its Markdown.
//!
//! `cargo run -p cairn-docs`, and that is the whole of it. It takes no
//! arguments, because the list of documents lives in the library where the
//! test that checks them can read it too, and a command that took a file name
//! would be a command somebody could run on one document and forget the rest.
//!
//! It says which files it wrote and which were already what their Markdown
//! renders to, so a run that changed nothing is visibly a run that changed
//! nothing.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(written) => {
            println!(
                "{} of {} documents rewritten",
                written,
                cairn_docs::DOCUMENTS.len()
            );
            ExitCode::SUCCESS
        }
        Err(said) => {
            eprintln!("cairn-docs: {said}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<usize, String> {
    let mut written = 0usize;
    for document in cairn_docs::DOCUMENTS {
        let source = cairn_docs::markdown_path(document);
        let target = cairn_docs::html_path(document);
        let markdown = read(&source)?;
        let html =
            cairn_docs::render(&markdown).map_err(|said| format!("{}: {said}", shown(&source)))?;
        if read(&target).ok().as_deref() == Some(html.as_str()) {
            println!("{document}.html is already what {document}.md renders to");
            continue;
        }
        fs::write(&target, &html)
            .map_err(|why| format!("{} could not be written: {why}", shown(&target)))?;
        println!("wrote {}, {} lines", shown(&target), html.lines().count());
        written = written.saturating_add(1);
    }
    Ok(written)
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|why| format!("{} could not be read: {why}", shown(path)))
}

/// The path as a person would type it, which is all a message needs.
fn shown(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}
