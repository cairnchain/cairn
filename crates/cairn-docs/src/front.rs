//! The front matter: what a document says about itself.
//!
//! Everything here is something the page shows outside the prose, and there is
//! nowhere else for it to live: a Markdown body has one heading and no notion
//! of a strap line, a byline or a stylesheet. It sits between two rows of three
//! dashes at the top of the file, which is where a writer expects it.
//!
//! Keys, and nothing but these:
//!
//! ```text
//! ---
//! title:      what a browser tab says
//! language:   the tag a browser hyphenates and a screen reader speaks by
//! stylesheet: the file beside this one that styles it
//! strap:      the sentence under the heading, may run over several lines
//! byline:     one line of the byline; write it again for the next one
//! abstract:   the word over the summary, if the document opens with one
//! footer:     one item in the footer; write it again for the next one
//! ---
//! ```
//!
//! A value may run over several lines by indenting the ones that follow, and
//! the line breaks are kept, because the generated HTML keeps the source's
//! wrapping and several tests read phrases out of it.
//!
//! A key nobody knows is an error rather than a line quietly ignored. Front
//! matter is exactly where a typo would otherwise cost a byline and say
//! nothing.

use crate::{Error, Result};

/// What a document says about itself, in the order it is written down.
#[derive(Debug)]
pub(crate) struct Front {
    pub(crate) title: String,
    pub(crate) language: String,
    pub(crate) stylesheet: String,
    pub(crate) strap: Option<String>,
    pub(crate) byline: Vec<String>,
    pub(crate) summary_heading: Option<String>,
    pub(crate) footer: Vec<String>,
}

/// The front matter and the Markdown body that follows it.
pub(crate) fn split(source: &str) -> Result<(Front, &str)> {
    let opened = source.strip_prefix("---\n").ok_or_else(|| {
        Error::new("a document opens with a line of three dashes, then its front matter")
    })?;
    let (matter, body) = opened.split_once("\n---\n").ok_or_else(|| {
        Error::new("the front matter is not closed by a line of three dashes of its own")
    })?;

    let mut entries: Vec<(String, String)> = Vec::new();
    for (number, line) in matter.lines().enumerate() {
        let at = number.saturating_add(2);
        if line.trim().is_empty() {
            return Err(Error::new(format!(
                "line {at} of the front matter is blank, and a blank line there is \
                 almost always a `---` that was meant to close it"
            )));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let Some(last) = entries.last_mut() else {
                return Err(Error::new(format!(
                    "line {at} is indented, so it continues the entry above, and there is none"
                )));
            };
            if !last.1.is_empty() {
                last.1.push('\n');
            }
            last.1.push_str(line.trim());
            continue;
        }
        let (key, value) = line.split_once(':').ok_or_else(|| {
            Error::new(format!("line {at} of the front matter is not `key: value`"))
        })?;
        entries.push((key.trim().to_owned(), value.trim().to_owned()));
    }

    let mut front = Front {
        title: String::new(),
        language: String::new(),
        stylesheet: String::new(),
        strap: None,
        byline: Vec::new(),
        summary_heading: None,
        footer: Vec::new(),
    };
    for (key, value) in entries {
        match key.as_str() {
            "title" => once(&mut front.title, &key, value)?,
            "language" => once(&mut front.language, &key, value)?,
            "stylesheet" => once(&mut front.stylesheet, &key, value)?,
            "strap" => set(&mut front.strap, &key, value)?,
            "abstract" => set(&mut front.summary_heading, &key, value)?,
            "byline" => front.byline.push(value),
            "footer" => front.footer.push(value),
            other => {
                return Err(Error::new(format!(
                    "`{other}` is not a front matter key. The ones there are: title, \
                     language, stylesheet, strap, byline, abstract, footer"
                )))
            }
        }
    }
    for (what, value) in [
        ("title", &front.title),
        ("language", &front.language),
        ("stylesheet", &front.stylesheet),
    ] {
        if value.is_empty() {
            return Err(Error::new(format!(
                "the front matter does not say `{what}`, and every document needs one"
            )));
        }
    }
    Ok((front, body))
}

/// A key that may be written once, whose value is a plain string.
fn once(field: &mut String, key: &str, value: String) -> Result<()> {
    if !field.is_empty() {
        return Err(Error::new(format!("`{key}` is written twice")));
    }
    if value.is_empty() {
        return Err(Error::new(format!(
            "`{key}` is written with nothing after it"
        )));
    }
    *field = value;
    Ok(())
}

/// A key that may be written once and may be left out.
fn set(field: &mut Option<String>, key: &str, value: String) -> Result<()> {
    if field.is_some() {
        return Err(Error::new(format!("`{key}` is written twice")));
    }
    if value.is_empty() {
        return Err(Error::new(format!(
            "`{key}` is written with nothing after it"
        )));
    }
    *field = Some(value);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::split;

    const MATTER: &str = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\n---\nbody\n";

    #[test]
    fn the_body_is_what_follows_the_closing_dashes() {
        let (front, body) = split(MATTER).unwrap();
        assert_eq!(front.title, "A");
        assert_eq!(front.language, "en");
        assert_eq!(front.stylesheet, "a.css");
        assert_eq!(body, "body\n");
    }

    #[test]
    fn an_indented_line_continues_the_entry_above_it_and_keeps_the_break() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\nstrap:\n  one\n  two\n---\n";
        let (front, _) = split(source).unwrap();
        assert_eq!(front.strap.as_deref(), Some("one\ntwo"));
    }

    #[test]
    fn a_key_written_again_adds_an_entry() {
        let source =
            "---\ntitle: A\nlanguage: en\nstylesheet: a.css\nbyline: one\nbyline: two\n---\n";
        let (front, _) = split(source).unwrap();
        assert_eq!(front.byline, vec!["one".to_owned(), "two".to_owned()]);
    }

    #[test]
    fn a_key_nobody_knows_is_an_error_and_not_a_line_dropped() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\nauthor: nobody\n---\n";
        let said = split(source).unwrap_err().to_string();
        assert!(
            said.contains("`author` is not a front matter key"),
            "{said}"
        );
    }

    #[test]
    fn a_document_with_no_front_matter_is_told_so() {
        let said = split("# A title\n").unwrap_err().to_string();
        assert!(said.contains("three dashes"), "{said}");
    }

    #[test]
    fn a_missing_stylesheet_is_named() {
        let source = "---\ntitle: A\nlanguage: en\n---\n";
        let said = split(source).unwrap_err().to_string();
        assert!(said.contains("does not say `stylesheet`"), "{said}");
    }
}
