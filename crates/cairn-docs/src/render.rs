//! Markdown in, the HTML a node serves out.
//!
//! The shape is fixed, because the site's stylesheets and half a dozen tests
//! already know it: a title and a stylesheet link, then `div.paper` holding a
//! `header.title`, an optional `div.abstract`, one `section` per `## ` heading
//! and a `footer`. A section carries its own number in a `div.num` beside the
//! body, and a `### ` heading carries `section.subsection` in a `span.sub`.
//!
//! Those numbers are counted here rather than typed. Every one of them used to
//! be written by hand in the heading, which made a section number a published
//! figure with no instrument behind it, and inserting a section meant editing
//! every number below it or publishing two sections called 7.
//!
//! What a document may vary is what it says, never the shape it says it in.
//! One paper numbers its parts I to VIII and names each of them beside the
//! numeral; another opens on a panel with no word over it; a third puts a line
//! above its heading. So a section may carry a label, written before a `|` in
//! its heading and set down beside the numeral; the numeral has a style; a
//! subsection may go unnumbered; and the opening block's heading word is the
//! `abstract:` the front matter names, or nothing when it names none. Five
//! papers, one shell.
//!
//! Line breaks inside a paragraph are the ones the Markdown has. That is not
//! cosmetic: guards in `cairn-explorer` and `cairn-ledger` look for phrases in
//! the served text, several of them span a line break, and reflowing a
//! paragraph here would move a phrase without anybody editing a word of it.
//! Rewrapping a paragraph is therefore a change to the document, and the
//! round-trip test will say so.
//!
//! What Markdown cannot say, a document says in HTML, which passes through
//! re-indented to where it sits. That is the figures, the parameter list, the
//! table, the reference list and a paragraph that carries a class. Everything
//! else, which is the great majority of every document, is prose.

use std::collections::BTreeSet;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

use crate::front::{self, Front, Subsections};
use crate::{Error, Result};

/// Renders one document.
///
/// # Errors
///
/// When the front matter is malformed, or the body uses something this
/// renderer has no shape for. Nothing is dropped quietly: a construct with no
/// home here is named and refused.
pub fn render(markdown: &str) -> Result<String> {
    let (front, body) = front::split(markdown)?;
    let events: Vec<Event<'_>> = Parser::new_ext(body, options()).collect();
    let mut page = Page::new(events);
    page.run(&front)?;
    Ok(page.out)
}

/// Tables are switched on so that one can be refused by name rather than
/// rendered as a paragraph of pipes. Everything else is `CommonMark` as it is
/// written:
/// no smart punctuation in particular, because a straight apostrophe turned
/// into a curly one is a phrase every guard searching for it stops finding.
fn options() -> Options {
    Options::ENABLE_TABLES
}

/// What is open at the point the walk has reached.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Nothing,
    Summary,
    Section,
}

impl Open {
    /// How deep the blocks inside it sit.
    fn indent(self) -> usize {
        match self {
            Self::Nothing => 0,
            Self::Summary => 2,
            Self::Section => 4,
        }
    }
}

struct Page<'a> {
    events: std::vec::IntoIter<Event<'a>>,
    out: String,
    section: usize,
    sub: usize,
    /// Whether the next block opens a container, and so wants no blank line in
    /// front of it.
    fresh: bool,
    /// The anchors handed out so far, so that no two headings share one.
    anchors: BTreeSet<String>,
}

impl<'a> Page<'a> {
    fn new(events: Vec<Event<'a>>) -> Self {
        Self {
            events: events.into_iter(),
            out: String::new(),
            section: 0,
            sub: 0,
            fresh: true,
            anchors: BTreeSet::new(),
        }
    }

    fn run(&mut self, front: &Front) -> Result<()> {
        // The whole shell, and not a fragment for somebody else to finish.
        // The explorer used to glue the declaration, the character set and
        // the viewport on in front of each file at compile time, with the
        // language typed a second time beside it; opened from a checkout, as
        // the README says a paper can be, a page had no character set at all,
        // and a browser that does not guess read every accent in the French
        // papers as two characters. Written here, the language is the front
        // matter's and nobody else's, and a file is the page it is served as.
        self.line(0, "<!doctype html>");
        self.line(
            0,
            &format!("<html lang=\"{}\">", attribute(&front.language)),
        );
        self.line(0, "<meta charset=\"utf-8\">");
        self.line(
            0,
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        );
        self.line(0, "<meta name=\"color-scheme\" content=\"dark light\">");
        self.line(0, &format!("<title>{}</title>", escape(&front.title)));
        self.line(
            0,
            &format!(
                "<link rel=\"stylesheet\" href=\"{}\">",
                attribute(&front.stylesheet)
            ),
        );
        self.line(
            0,
            &format!(
                "<div class=\"paper\" lang=\"{}\">",
                attribute(&front.language)
            ),
        );

        self.title_block(front)?;

        let mut open = Open::Nothing;
        while let Some(event) = self.events.next() {
            match event {
                Event::Start(Tag::Heading { level, .. }) => {
                    open = self.heading(level, open, front)?;
                }
                other => {
                    if open == Open::Nothing {
                        open = self.open_summary(front);
                    }
                    self.space();
                    let indent = open.indent();
                    self.block(other, indent)?;
                }
            }
        }
        self.close(open);
        self.footer_block(front)?;
        self.blank();
        self.line(0, "</div>");
        Ok(())
    }

    /// The block at the top of the page: the kicker, the heading, the strap
    /// and the byline.
    fn title_block(&mut self, front: &Front) -> Result<()> {
        let opened = self.events.next();
        if !matches!(
            opened,
            Some(Event::Start(Tag::Heading {
                level: HeadingLevel::H1,
                ..
            }))
        ) {
            return Err(Error::new(
                "a document opens with `# ` and the heading the page shows, and this \
                 one opens with something else",
            ));
        }
        let heading = self.inline(Some(TagEnd::Heading(HeadingLevel::H1)), 2)?;

        self.blank();
        self.line(0, "<header class=\"title\">");
        if let Some(kicker) = front.kicker.as_deref() {
            let text = inline_of(kicker, 2)?;
            self.line(2, &format!("<p class=\"kicker\">{text}</p>"));
        }
        self.line(2, &format!("<h1>{heading}</h1>"));
        if let Some(strap) = front.strap.as_deref() {
            self.line(2, "<p class=\"strap\">");
            let text = inline_of(strap, 4)?;
            self.line(4, &text);
            self.line(2, "</p>");
        }
        if !front.byline.is_empty() {
            self.line(2, "<div class=\"byline\">");
            for entry in &front.byline {
                let text = inline_of(entry, 6)?;
                self.line(4, &format!("<span>{text}</span>"));
            }
            self.line(2, "</div>");
        }
        self.line(0, "</header>");
        Ok(())
    }

    fn footer_block(&mut self, front: &Front) -> Result<()> {
        if front.footer.is_empty() {
            return Ok(());
        }
        self.blank();
        self.line(0, "<footer>");
        for entry in &front.footer {
            let text = inline_of(entry, 4)?;
            self.line(2, &format!("<span>{text}</span>"));
        }
        self.line(0, "</footer>");
        Ok(())
    }

    /// A heading, which is also what opens and closes the containers.
    fn heading(&mut self, level: HeadingLevel, open: Open, front: &Front) -> Result<Open> {
        match level {
            HeadingLevel::H1 => Err(Error::new(
                "a document has one `# ` heading, at the top. A section is `## `",
            )),
            HeadingLevel::H2 => {
                let events = self.gather(TagEnd::Heading(HeadingLevel::H2))?;
                let (label, heading) = labelled(events);
                let label = match label {
                    Some(label) => Some(inline_of_events(label, 4)?),
                    None => None,
                };
                let anchor = self.anchor(&heading);
                let text = inline_of_events(heading, 4)?;
                self.close(open);
                self.blank();
                self.section = self.section.saturating_add(1);
                self.sub = 0;
                let number = front.numerals.of(self.section);
                self.line(0, "<section>");
                // The numeral is wrapped so that a stylesheet can address it
                // on its own; the label is not, because a label that is
                // already an element would then sit inside one it never asked
                // for. The design paper's status chips are spans, and a chip
                // in a wrapper is a chip in a box.
                match label {
                    None => self.line(2, &format!("<div class=\"num\">{number}</div>")),
                    Some(label) => self.line(
                        2,
                        &format!("<div class=\"num\"><span>{number}</span>{label}</div>"),
                    ),
                }
                self.line(2, "<div class=\"body\">");
                self.line(4, &format!("<h2 id=\"{anchor}\">{text}</h2>"));
                self.fresh = true;
                Ok(Open::Section)
            }
            HeadingLevel::H3 => {
                if open != Open::Section {
                    return Err(Error::new(
                        "a `### ` heading sits inside a section, and this one comes \
                         before the first `## `",
                    ));
                }
                let events = self.gather(TagEnd::Heading(HeadingLevel::H3))?;
                let anchor = self.anchor(&events);
                let text = inline_of_events(events, 4)?;
                self.sub = self.sub.saturating_add(1);
                self.space();
                let written = match front.subsections {
                    Subsections::Numbered => format!(
                        "<h3 id=\"{anchor}\"><span class=\"sub\">{}.{}</span>{text}</h3>",
                        front.numerals.of(self.section),
                        self.sub
                    ),
                    Subsections::Unnumbered => format!("<h3 id=\"{anchor}\">{text}</h3>"),
                };
                self.line(4, &written);
                Ok(Open::Section)
            }
            deeper => Err(Error::new(format!(
                "this renderer numbers `## ` and `### ` headings, and the document \
                 uses {deeper:?}. Deciding what a fourth level is called is a change \
                 to the stylesheets as well as to this file"
            ))),
        }
    }

    /// Opens the block some documents carry between the header and their first
    /// section.
    ///
    /// The word over it is the one the front matter names, and a document that
    /// names none opens on the block itself. That is not an omission to be
    /// caught: the prior-art paper's opening is a three-part verdict panel that
    /// heads itself, and a word invented to sit above it would be a word a
    /// reader reads that nobody wrote.
    fn open_summary(&mut self, front: &Front) -> Open {
        self.blank();
        self.line(0, "<div class=\"abstract\">");
        if let Some(word) = front.summary_heading.as_deref() {
            self.line(2, &format!("<h2>{}</h2>", escape(word)));
        }
        self.fresh = true;
        Open::Summary
    }

    fn close(&mut self, open: Open) {
        match open {
            Open::Nothing => {}
            Open::Summary => self.line(0, "</div>"),
            Open::Section => {
                self.line(2, "</div>");
                self.line(0, "</section>");
            }
        }
    }

    /// One block of the body, at the depth its container puts it.
    fn block(&mut self, event: Event<'a>, indent: usize) -> Result<()> {
        match event {
            Event::Start(Tag::Paragraph) => {
                self.line(indent, "<p>");
                let text = self.inline(Some(TagEnd::Paragraph), indent.saturating_add(2))?;
                self.line(indent.saturating_add(2), &text);
                self.line(indent, "</p>");
                Ok(())
            }
            Event::Start(Tag::HtmlBlock) => {
                let mut raw = String::new();
                loop {
                    match self.events.next() {
                        Some(Event::Html(text)) => raw.push_str(&text),
                        Some(Event::End(TagEnd::HtmlBlock)) => break,
                        other => {
                            return Err(Error::new(format!(
                                "a block of HTML holds {other:?}, which this renderer \
                                 does not expect inside one"
                            )))
                        }
                    }
                }
                self.out.push_str(&reindent(&raw, indent));
                Ok(())
            }
            Event::Start(Tag::List(first)) => self.list(first, indent),
            Event::Start(Tag::CodeBlock(CodeBlockKind::Indented)) => Err(Error::new(
                "a block indented four spaces is a code block in Markdown, and these \
                 documents write code fenced. The usual way to get one without meaning \
                 to is a blank line inside a block of HTML, which ends the block there \
                 and turns the indented lines after it into code, its own closing tag \
                 included",
            )),
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_))) => {
                let mut text = String::new();
                loop {
                    match self.events.next() {
                        Some(Event::Text(part)) => text.push_str(&part),
                        Some(Event::End(TagEnd::CodeBlock)) => break,
                        other => {
                            return Err(Error::new(format!(
                                "a code block holds {other:?}, which is not text"
                            )))
                        }
                    }
                }
                self.line(
                    indent,
                    &format!("<pre><code>{}</code></pre>", escape(text.trim_end())),
                );
                Ok(())
            }
            Event::Start(Tag::Table(_)) => Err(Error::new(
                "a Markdown table has no shape here yet. The one table these documents \
                 carry is written as HTML, because it has a caption, a scrolling \
                 wrapper and a class on the rows the design is about, and none of the \
                 three has a spelling in Markdown",
            )),
            other => Err(Error::new(format!(
                "{other:?} is not a block this renderer knows. Write it as HTML, or \
                 give it a shape here"
            ))),
        }
    }

    fn list(&mut self, first: Option<u64>, indent: usize) -> Result<()> {
        let (opened, closed) = match first {
            None => ("<ul>".to_owned(), "</ul>"),
            Some(1) => ("<ol>".to_owned(), "</ol>"),
            Some(other) => (format!("<ol start=\"{other}\">"), "</ol>"),
        };
        self.line(indent, &opened);
        let inside = indent.saturating_add(2);
        loop {
            match self.events.next() {
                Some(Event::Start(Tag::Item)) => {
                    let events = self.gather(TagEnd::Item)?;
                    let paragraphs = events
                        .iter()
                        .filter(|event| matches!(event, Event::Start(Tag::Paragraph)))
                        .count();
                    if paragraphs > 1 {
                        return Err(Error::new(
                            "a list item holds more than one paragraph, and this \
                             renderer takes plain items: the paragraphs would be \
                             joined into one run with nothing between them. Write \
                             the item as one paragraph, or the list as HTML",
                        ));
                    }
                    let text = inline_of_events(events, inside)?;
                    self.line(inside, &format!("<li>{text}</li>"));
                }
                Some(Event::End(TagEnd::List(_))) => break,
                other => {
                    return Err(Error::new(format!(
                        "a list holds {other:?}, and this renderer takes plain items"
                    )))
                }
            }
        }
        self.line(indent, closed);
        Ok(())
    }

    /// The text of one run of inline events.
    ///
    /// `until` is the end tag that stops it, or nothing to run to the end of a
    /// fragment. A soft break becomes a line break and the indent that goes
    /// with it, which is how the source's own wrapping survives into the page.
    fn inline(&mut self, until: Option<TagEnd>, indent: usize) -> Result<String> {
        let mut out = String::new();
        for event in self.events.by_ref() {
            match event {
                Event::End(end) if until == Some(end) => return Ok(out),
                Event::Start(Tag::Paragraph) | Event::End(TagEnd::Paragraph) => {}
                Event::Text(text) => out.push_str(&escape(&text)),
                Event::Code(text) => {
                    out.push_str("<code>");
                    out.push_str(&escape(&text));
                    out.push_str("</code>");
                }
                Event::InlineHtml(raw) => {
                    if closes_a_block(&raw) {
                        return Err(Error::new(format!(
                            "`{raw}` closes a block inside a line of prose. That is \
                             what a blank line inside a block of HTML leaves behind: \
                             the block ends at the blank line, and what follows is a \
                             paragraph carrying the closing tag"
                        )));
                    }
                    out.push_str(&raw);
                }
                Event::SoftBreak => {
                    out.push('\n');
                    out.push_str(&" ".repeat(indent));
                }
                Event::Start(Tag::Emphasis) => out.push_str("<em>"),
                Event::End(TagEnd::Emphasis) => out.push_str("</em>"),
                Event::Start(Tag::Strong) => out.push_str("<strong>"),
                Event::End(TagEnd::Strong) => out.push_str("</strong>"),
                Event::Start(Tag::Link {
                    dest_url, title, ..
                }) => {
                    out.push_str("<a href=\"");
                    out.push_str(&attribute(&dest_url));
                    if !title.is_empty() {
                        out.push_str("\" title=\"");
                        out.push_str(&attribute(&title));
                    }
                    out.push_str("\">");
                }
                Event::End(TagEnd::Link) => out.push_str("</a>"),
                other => {
                    return Err(Error::new(format!(
                        "{other:?} is not something this renderer writes inside a line"
                    )))
                }
            }
        }
        if until.is_none() {
            return Ok(out);
        }
        Err(Error::new(format!("{until:?} was never reached")))
    }

    /// The events up to `until`, taken off the walk without being written.
    fn gather(&mut self, until: TagEnd) -> Result<Vec<Event<'a>>> {
        let mut gathered = Vec::new();
        for event in self.events.by_ref() {
            match event {
                Event::End(end) if end == until => return Ok(gathered),
                other => gathered.push(other),
            }
        }
        Err(Error::new(format!("{until:?} was never reached")))
    }

    /// The anchor a heading is linked to by, from the words it says.
    ///
    /// No heading carried one, so no section of any paper could be linked to,
    /// and a paper that sends a reader to "its section 8" could only give a
    /// number. Taken from the text rather than the number, because the text
    /// stays put when a section is inserted above it and the number does not.
    fn anchor(&mut self, heading: &[Event<'_>]) -> String {
        let mut words = String::new();
        for event in heading {
            if let Event::Text(text) | Event::Code(text) = event {
                words.push_str(text);
            }
        }
        let mut slug = String::new();
        for character in words.chars().flat_map(char::to_lowercase) {
            if character.is_alphanumeric() {
                slug.push(character);
            } else if !slug.ends_with('-') && !slug.is_empty() {
                slug.push('-');
            }
        }
        let slug = slug.trim_end_matches('-').to_owned();
        let base = if slug.is_empty() {
            "section".to_owned()
        } else {
            slug
        };
        let mut candidate = base.clone();
        let mut count = 1usize;
        while !self.anchors.insert(candidate.clone()) {
            count = count.saturating_add(1);
            candidate = format!("{base}-{count}");
        }
        candidate
    }

    /// A blank line between two blocks, unless a container has just opened.
    fn space(&mut self) {
        if self.fresh {
            self.fresh = false;
        } else {
            self.blank();
        }
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    fn line(&mut self, indent: usize, text: &str) {
        self.out.push_str(&" ".repeat(indent));
        self.out.push_str(text);
        self.out.push('\n');
    }
}

/// One fragment of Markdown, rendered as the inside of a line.
fn inline_of(source: &str, indent: usize) -> Result<String> {
    let events: Vec<Event<'_>> = Parser::new_ext(source, options()).collect();
    inline_of_events(events, indent)
}

/// Inline events already taken off a walk, rendered as the inside of a line.
fn inline_of_events(events: Vec<Event<'_>>, indent: usize) -> Result<String> {
    Page::new(events).inline(None, indent)
}

/// A heading's label and its heading, split at the first ` | ` that stands in
/// the heading's own words.
///
/// This split the rendered HTML, so a bar inside a code span, a link or an
/// emphasis cut the element in two: a heading whose code span held a bar put
/// an open `<code>` in the margin and its closing tag in the heading. It is decided on the events
/// now, and only a bar in plain text at the top level is a label's.
fn labelled(mut events: Vec<Event<'_>>) -> (Option<Vec<Event<'_>>>, Vec<Event<'_>>) {
    let mut depth = 0usize;
    let mut found = None;
    for (index, event) in events.iter().enumerate() {
        match event {
            Event::Start(_) => depth = depth.saturating_add(1),
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Text(text) if depth == 0 => {
                if let Some((before, after)) = text.split_once(" | ") {
                    found = Some((index, before.to_owned(), after.to_owned()));
                    break;
                }
            }
            _ => {}
        }
    }
    let Some((index, before, after)) = found else {
        return (None, events);
    };
    let rest: Vec<Event<'_>> = events.split_off(index).into_iter().skip(1).collect();
    if !before.is_empty() {
        events.push(Event::Text(before.into()));
    }
    let mut heading = Vec::with_capacity(rest.len().saturating_add(1));
    if !after.is_empty() {
        heading.push(Event::Text(after.into()));
    }
    heading.extend(rest);
    (Some(events), heading)
}

/// Whether a piece of inline HTML closes an element that is a block.
fn closes_a_block(raw: &str) -> bool {
    const BLOCKS: [&str; 16] = [
        "div", "p", "section", "table", "thead", "tbody", "tr", "td", "th", "ul", "ol", "li",
        "figure", "footer", "header", "pre",
    ];
    let Some(name) = raw.trim().strip_prefix("</") else {
        return false;
    };
    let name = name.trim_end_matches('>').trim().to_ascii_lowercase();
    BLOCKS.contains(&name.as_str())
}

/// Moves a block of HTML to where it sits on the page, keeping the shape it
/// was written in.
///
/// A block of HTML in Markdown starts hard against the left margin, because
/// four spaces of indent would make it a code block. So the least-indented
/// line decides what counts as the left margin, and everything keeps its
/// distance from it.
fn reindent(raw: &str, indent: usize) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let margin = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len().saturating_sub(line.trim_start().len()))
        .min()
        .unwrap_or(0);
    let pad = " ".repeat(indent);
    let mut out = String::new();
    for line in lines {
        if line.trim().is_empty() {
            out.push('\n');
            continue;
        }
        out.push_str(&pad);
        out.push_str(line.get(margin..).unwrap_or(line));
        out.push('\n');
    }
    out
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

fn attribute(text: &str) -> String {
    escape(text).replace('"', "&quot;")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::render;

    const HEAD: &str = "---\ntitle: A paper\nlanguage: en\nstylesheet: a.css\n---\n# A heading\n";

    fn page(body: &str) -> String {
        render(&format!("{HEAD}{body}")).unwrap()
    }

    /// A rendered file is a whole page: the declaration, the language from
    /// the front matter, the character set and the viewport, then the title,
    /// the stylesheet and the paper.
    ///
    /// It was a fragment the explorer finished at compile time, typing the
    /// language a second time beside it. Opened from a checkout, as the README
    /// says a paper can be, a page had no character set, and a browser that
    /// does not guess showed the French papers' accents as two characters each.
    #[test]
    fn the_page_opens_with_a_title_a_stylesheet_and_the_paper() {
        let out = page("\n## One\n\nText.\n");
        assert!(
            out.starts_with(
                "<!doctype html>\n<html lang=\"en\">\n<meta charset=\"utf-8\">\n\
                 <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
                 <meta name=\"color-scheme\" content=\"dark light\">\n\
                 <title>A paper</title>\n<link rel=\"stylesheet\" href=\"a.css\">\n\
                 <div class=\"paper\" lang=\"en\">\n"
            ),
            "{out}"
        );
        assert!(out.ends_with("</section>\n\n</div>\n"), "{out}");
        assert!(out.contains("  <h1>A heading</h1>\n"), "{out}");
    }

    /// The whole reason the numbers are not typed: inserting a section moves
    /// every number below it, and a hand-written one would not move.
    #[test]
    fn sections_and_subsections_are_numbered_by_counting_them() {
        let out = page("\n## One\n\n### First\n\n### Second\n\n## Two\n\n### Only\n");
        assert!(out.contains("<div class=\"num\">1</div>"), "{out}");
        assert!(out.contains("<span class=\"sub\">1.1</span>First"), "{out}");
        assert!(
            out.contains("<span class=\"sub\">1.2</span>Second"),
            "{out}"
        );
        assert!(out.contains("<div class=\"num\">2</div>"), "{out}");
        assert!(out.contains("<span class=\"sub\">2.1</span>Only"), "{out}");
    }

    /// Guards in two other crates search the served text for phrases that span
    /// a line break, so where a paragraph wraps is part of the document.
    #[test]
    fn a_paragraph_keeps_the_line_breaks_the_markdown_has() {
        let out = page("\n## One\n\nthe first line\nthe second line\n");
        assert!(
            out.contains("      the first line\n      the second line\n"),
            "{out}"
        );
    }

    #[test]
    fn html_is_carried_through_to_where_it_sits() {
        let out = page("\n## One\n\n<figure>\n  <figcaption>A</figcaption>\n</figure>\n");
        assert!(
            out.contains("    <figure>\n      <figcaption>A</figcaption>\n    </figure>\n"),
            "{out}"
        );
    }

    #[test]
    fn the_abstract_is_the_prose_above_the_first_section() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\nabstract: Abstract\n---\n\
                      # A heading\n\nA summary.\n\n## One\n\nText.\n";
        let out = render(source).unwrap();
        assert!(
            out.contains("<div class=\"abstract\">\n  <h2>Abstract</h2>\n  <p>\n    A summary.\n  </p>\n</div>"),
            "{out}"
        );
    }

    /// The prior-art paper opens on a panel that heads itself, and a word
    /// invented to sit over it would be a word a reader reads that nobody
    /// wrote.
    #[test]
    fn an_opening_block_with_no_word_named_over_it_carries_none() {
        let out = page("\nA summary.\n\n## One\n\nText.\n");
        assert!(
            out.contains("<div class=\"abstract\">\n  <p>\n    A summary.\n  </p>\n</div>"),
            "{out}"
        );
    }

    /// A section's label is a word a reader reads, so it is written where the
    /// section is rather than in a list somebody keeps in step by hand.
    #[test]
    fn a_section_may_carry_a_label_beside_its_number() {
        let out = page("\n## Le problème | Toutes se recentralisent\n\nText.\n");
        assert!(
            out.contains("<div class=\"num\"><span>1</span>Le problème</div>"),
            "{out}"
        );
        assert!(
            out.contains("<h2 id=\"toutes-se-recentralisent\">Toutes se recentralisent</h2>"),
            "{out}"
        );
    }

    /// The label is inline like any other run of a document, so a paper whose
    /// label is a status chip writes the chip and gets no wrapper it did not
    /// ask for.
    #[test]
    fn a_label_written_as_html_is_set_down_as_it_was_written() {
        let out = page("\n## <span class=\"chip locked\">Verrouillé</span> | Les décisions\n");
        assert!(
            out.contains(
                "<div class=\"num\"><span>1</span><span class=\"chip locked\">Verrouillé</span></div>"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_document_that_counts_in_roman_gets_roman_numbers() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\nnumerals: roman\n---\n\
                      # A heading\n\n## One\n\n## Two\n\n## Three\n\n## Four\n";
        let out = render(source).unwrap();
        for number in ["I", "II", "III", "IV"] {
            assert!(
                out.contains(&format!("<div class=\"num\">{number}</div>")),
                "{out}"
            );
        }
    }

    #[test]
    fn a_style_of_numbering_nobody_knows_is_refused() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\nnumerals: greek\n---\n\
                      # A heading\n\n## One\n";
        let said = render(source).unwrap_err().to_string();
        assert!(said.contains("`numerals: greek`"), "{said}");
    }

    /// Four subsections named the same four things in every section is a paper
    /// that would only be repeating "2.3" at its reader.
    #[test]
    fn a_paper_whose_subsections_are_unnumbered_gets_the_heading_alone() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\n\
                      subsections: unnumbered\n---\n\
                      # A heading\n\n## One\n\n### La position\n";
        let out = render(source).unwrap();
        assert!(
            out.contains("    <h3 id=\"la-position\">La position</h3>\n"),
            "{out}"
        );
        assert!(!out.contains("class=\"sub\""), "{out}");
    }

    #[test]
    fn a_kicker_sits_above_the_heading() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\n\
                      kicker: Cairn · étude de l'existant\n---\n\
                      # A heading\n\n## One\n";
        let out = render(source).unwrap();
        assert!(
            out.contains(
                "<header class=\"title\">\n  <p class=\"kicker\">Cairn · étude de \
                 l'existant</p>\n  <h1>A heading</h1>"
            ),
            "{out}"
        );
    }

    #[test]
    fn the_strap_the_byline_and_the_footer_carry_markdown() {
        let source = "---\ntitle: A\nlanguage: en\nstylesheet: a.css\n\
                      strap:\n  one\n  two\nbyline: [a](https://b/)\nfooter: last\n---\n\
                      # A heading\n\n## One\n\nText.\n";
        let out = render(source).unwrap();
        assert!(
            out.contains("  <p class=\"strap\">\n    one\n    two\n  </p>"),
            "{out}"
        );
        assert!(
            out.contains("    <span><a href=\"https://b/\">a</a></span>"),
            "{out}"
        );
        assert!(
            out.contains("<footer>\n  <span>last</span>\n</footer>"),
            "{out}"
        );
    }

    #[test]
    fn a_markdown_table_is_refused_by_name_rather_than_rendered_as_pipes() {
        let said = render(&format!(
            "{HEAD}\n## One\n\n| a | b |\n| - | - |\n| 1 | 2 |\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(said.contains("no shape here yet"), "{said}");
    }

    #[test]
    fn a_fourth_level_of_heading_is_refused_rather_than_numbered_by_guess() {
        let said = render(&format!("{HEAD}\n## One\n\n### Two\n\n#### Three\n"))
            .unwrap_err()
            .to_string();
        assert!(said.contains("numbers `## ` and `### ` headings"), "{said}");
    }

    #[test]
    fn a_list_becomes_a_list() {
        let out = page("\n## One\n\n- first\n- second\n");
        assert!(
            out.contains("    <ul>\n      <li>first</li>\n      <li>second</li>\n    </ul>"),
            "{out}"
        );
    }

    #[test]
    fn emphasis_code_and_links_come_out_as_the_stylesheets_expect() {
        let out = page("\n## One\n\n*a* **b** `c` [d](https://e/) <sup>[[1]](#r1)</sup>\n");
        assert!(
            out.contains("<em>a</em> <strong>b</strong> <code>c</code>"),
            "{out}"
        );
        assert!(out.contains("<a href=\"https://e/\">d</a>"), "{out}");
        assert!(out.contains("<sup><a href=\"#r1\">[1]</a></sup>"), "{out}");
    }

    /// A blank line inside a block of HTML is refused, whichever way the lines
    /// after it are indented.
    ///
    /// Markdown ends an HTML block at a blank line. Indented four spaces, what
    /// followed became a code block, its entities escaped a second time and
    /// the block's own closing tag shown as text; indented less, it became a
    /// paragraph carrying the closing tag. The round trip passed either way,
    /// because the committed page was whatever this produced.
    #[test]
    fn a_blank_line_inside_a_block_of_html_is_refused_in_both_shapes() {
        for body in [
            "\n## One\n\n<div class=\"tiers\">\n  <div>\n\n    Notes, A &amp; B.</div>\n</div>\n",
            "\n## One\n\n<div class=\"tiers\">\n  <div>\n\n  Notes, A &amp; B.</div>\n</div>\n",
        ] {
            let said = render(&format!("{HEAD}{body}")).unwrap_err().to_string();
            assert!(
                said.contains("blank line inside a block of HTML"),
                "a broken block of HTML was not refused by name: {said}"
            );
        }
    }

    /// A bar inside a code span, a link or an emphasis in a heading is part of
    /// the heading, not the line between a label and it.
    #[test]
    fn a_bar_inside_a_code_span_in_a_heading_stays_in_the_heading() {
        let out = page("\n## `a | b`\n\nText.\n");
        assert!(out.contains("<div class=\"num\">1</div>"), "{out}");
        assert!(out.contains("><code>a | b</code></h2>"), "{out}");
        let out = page("\n## Label | *a | b*\n\nText.\n");
        assert!(
            out.contains("<div class=\"num\"><span>1</span>Label</div>"),
            "{out}"
        );
        assert!(out.contains("><em>a | b</em></h2>"), "{out}");
    }

    /// Two paragraphs in one list item are refused rather than glued into one
    /// word.
    #[test]
    fn two_paragraphs_in_one_list_item_are_refused() {
        let said = render(&format!(
            "{HEAD}\n## One\n\n- first paragraph.\n\n  Second paragraph.\n- other\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(said.contains("more than one paragraph"), "{said}");
    }

    /// A link's title is written, not dropped.
    #[test]
    fn a_link_title_is_kept() {
        let out = page("\n## One\n\n[the paper](https://b/ \"Draft \\\"one\\\"\")\n");
        assert!(
            out.contains("<a href=\"https://b/\" title=\"Draft &quot;one&quot;\">the paper</a>"),
            "{out}"
        );
    }

    /// Every heading can be linked to, by the words it says, and no two share
    /// an anchor.
    #[test]
    fn every_heading_carries_an_anchor_of_its_own() {
        let out =
            page("\n## The state\n\n### The hot set\n\n## The state\n\n### Élan, `two` words\n");
        assert!(out.contains("<h2 id=\"the-state\">The state</h2>"), "{out}");
        assert!(out.contains("<h3 id=\"the-hot-set\">"), "{out}");
        assert!(
            out.contains("<h2 id=\"the-state-2\">The state</h2>"),
            "{out}"
        );
        assert!(out.contains("<h3 id=\"élan-two-words\">"), "{out}");
    }

    /// The error arms, each asked for by name.
    #[test]
    fn what_has_no_shape_here_is_refused_by_name() {
        let before = render(&format!("{HEAD}\n### Early\n"))
            .unwrap_err()
            .to_string();
        assert!(before.contains("before the first `## `"), "{before}");
        let twice = render(&format!("{HEAD}\n## One\n\n# Again\n"))
            .unwrap_err()
            .to_string();
        assert!(twice.contains("one `# ` heading"), "{twice}");
        let opening = render("---\ntitle: A\nlanguage: en\nstylesheet: a.css\n---\nText first.\n")
            .unwrap_err()
            .to_string();
        assert!(opening.contains("opens with `# `"), "{opening}");
        let nested = render(&format!("{HEAD}\n## One\n\n- first\n  - inner\n"))
            .unwrap_err()
            .to_string();
        assert!(
            nested.contains("not something this renderer writes inside a line"),
            "{nested}"
        );
    }

    /// An ordered list keeps where it starts, and a fenced block keeps its
    /// text escaped once.
    #[test]
    fn an_ordered_list_keeps_its_start_and_a_fence_its_text() {
        let out = page("\n## One\n\n3. third\n4. fourth\n\n```text\na < b & c\n```\n");
        assert!(out.contains("<ol start=\"3\">"), "{out}");
        assert!(out.contains("<li>third</li>"), "{out}");
        assert!(
            out.contains("<pre><code>a &lt; b &amp; c</code></pre>"),
            "{out}"
        );
        let first = page("\n## One\n\n1. one\n");
        assert!(first.contains("<ol>\n"), "{first}");
    }

    /// A block of HTML keeps its own shape at whatever margin it was written.
    #[test]
    fn html_written_at_a_small_margin_keeps_its_shape() {
        assert_eq!(
            super::reindent(" <a>\n   <b/>\n\n </a>", 2),
            "  <a>\n    <b/>\n\n  </a>\n"
        );
    }

    #[test]
    fn text_and_attributes_are_escaped() {
        assert_eq!(super::escape("a < b & c > d"), "a &lt; b &amp; c &gt; d");
        assert_eq!(
            super::attribute("say \"x\" & y"),
            "say &quot;x&quot; &amp; y"
        );
    }
}
