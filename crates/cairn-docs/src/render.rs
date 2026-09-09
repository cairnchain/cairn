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

use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};

use crate::front::{self, Front};
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
}

impl<'a> Page<'a> {
    fn new(events: Vec<Event<'a>>) -> Self {
        Self {
            events: events.into_iter(),
            out: String::new(),
            section: 0,
            sub: 0,
            fresh: true,
        }
    }

    fn run(&mut self, front: &Front) -> Result<()> {
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
                    open = self.heading(level, open)?;
                }
                other => {
                    if open == Open::Nothing {
                        open = self.open_summary(front)?;
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

    /// The block at the top of the page: the heading, the strap and the byline.
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
    fn heading(&mut self, level: HeadingLevel, open: Open) -> Result<Open> {
        match level {
            HeadingLevel::H1 => Err(Error::new(
                "a document has one `# ` heading, at the top. A section is `## `",
            )),
            HeadingLevel::H2 => {
                let text = self.inline(Some(TagEnd::Heading(HeadingLevel::H2)), 4)?;
                self.close(open);
                self.blank();
                self.section = self.section.saturating_add(1);
                self.sub = 0;
                self.line(0, "<section>");
                self.line(2, &format!("<div class=\"num\">{}</div>", self.section));
                self.line(2, "<div class=\"body\">");
                self.line(4, &format!("<h2>{text}</h2>"));
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
                let text = self.inline(Some(TagEnd::Heading(HeadingLevel::H3)), 4)?;
                self.sub = self.sub.saturating_add(1);
                self.space();
                self.line(
                    4,
                    &format!(
                        "<h3><span class=\"sub\">{}.{}</span>{text}</h3>",
                        self.section, self.sub
                    ),
                );
                Ok(Open::Section)
            }
            deeper => Err(Error::new(format!(
                "this renderer numbers `## ` and `### ` headings, and the document \
                 uses {deeper:?}. Deciding what a fourth level is called is a change \
                 to the stylesheets as well as to this file"
            ))),
        }
    }

    /// Opens the summary that some documents carry above their first section.
    fn open_summary(&mut self, front: &Front) -> Result<Open> {
        let Some(word) = front.summary_heading.as_deref() else {
            return Err(Error::new(
                "there is prose before the first `## ` heading, which is a document's \
                 abstract, and the front matter does not say `abstract:` with the word \
                 to head it",
            ));
        };
        self.blank();
        self.line(0, "<div class=\"abstract\">");
        self.line(2, &format!("<h2>{}</h2>", escape(word)));
        self.fresh = true;
        Ok(Open::Summary)
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
            Event::Start(Tag::CodeBlock(_)) => {
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
                    let text = self.inline(Some(TagEnd::Item), inside)?;
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
                Event::InlineHtml(raw) => out.push_str(&raw),
                Event::SoftBreak => {
                    out.push('\n');
                    out.push_str(&" ".repeat(indent));
                }
                Event::Start(Tag::Emphasis) => out.push_str("<em>"),
                Event::End(TagEnd::Emphasis) => out.push_str("</em>"),
                Event::Start(Tag::Strong) => out.push_str("<strong>"),
                Event::End(TagEnd::Strong) => out.push_str("</strong>"),
                Event::Start(Tag::Link { dest_url, .. }) => {
                    out.push_str("<a href=\"");
                    out.push_str(&attribute(&dest_url));
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
    Page::new(events).inline(None, indent)
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

    #[test]
    fn the_page_opens_with_a_title_a_stylesheet_and_the_paper() {
        let out = page("\n## One\n\nText.\n");
        assert!(out.starts_with(
            "<title>A paper</title>\n<link rel=\"stylesheet\" href=\"a.css\">\n\
             <div class=\"paper\" lang=\"en\">\n"
        ));
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

    #[test]
    fn prose_above_the_first_section_without_a_word_to_head_it_is_refused() {
        let said = render(&format!("{HEAD}\nA summary.\n\n## One\n\nText.\n"))
            .unwrap_err()
            .to_string();
        assert!(said.contains("does not say `abstract:`"), "{said}");
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
}
