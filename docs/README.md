# Writing documentation for Cairn

Every document in this folder is written in Markdown and rendered to HTML by
`cairn-docs`. The HTML is committed beside the Markdown, and a test fails if the
two disagree, because the node serves the HTML and nobody would notice it going
stale otherwise.

Do not edit the HTML. It is generated.

## The one rule that matters

**A document is a claim, held to the same standard as an assertion.**

This project has published sixteen figures the code contradicted. Every single
time, the defect was in the instrument rather than in the thing being measured:
a comment describing a relation backwards while the code beneath it was right, a
paragraph whose own two numbers refuted its conclusion, a test that measured the
wrong half of what it named.

So: **every number in a document is held to the code by a test.** Not most of
them. If you write that something costs 68 MB, that a window is 90 blocks, or
that a correction lands in two hours, there is a test that computes it from the
code and fails when the two part company. `crates/cairn-explorer/tests/published_figures.rs`
is where most of them live and is the model to copy.

A figure without a guard does not go in. It is not a matter of diligence; it is
that nobody, including the person who wrote it, will notice when it becomes
wrong.

## What goes where

**`cairn-whitepaper.md`** is the argument: what the design is, why it is that
shape, what it costs, and what it does not solve. Prose. It may say "roughly"
and "about". It is allowed to persuade.

**`cairn-specification.md`** is normative: what a node MUST do to reach the same
conclusions as every other node. No persuasion, no history, no rationale except
where a reader would otherwise get the rule wrong. It is written so that a
second implementation could be built from it without reading the first, which is
the test of whether it is finished.

The two do not share sentences. A rule that appears in both is a rule that will
be changed in one of them.

**`cairn-design.md`**, **`cairn-open-questions.md`**, **`cairn-prior-art.md`**
are the project's own reasoning, in French, for readers who want the thinking
rather than the protocol.

## House style

Plain English, or plain French where the document is French. Short sentences.
Say what happened and what to do about it.

**No em dashes.** Use a comma, a colon, or a full stop. This is not a
preference about typography; it is that an em dash is almost always two
sentences pretending to be one.

**No emoji, anywhere**, including in commit messages.

**Numbers with a thin space in prose**: 131 072, not 131,072 or 131072. In code
spans and tables, whatever the code writes.

**Name the thing, then say what it does.** Not "there is a mechanism which
handles the case where". The reference implementation's own names read as plain
English on purpose, and documents should borrow them rather than invent
synonyms: a reader who searches the code for a word from the paper should find
it.

**Write the reason, not just the rule.** "The window is 90 blocks" is a fact a
reader cannot check. "The window is 90 blocks, so half a doubling correction
lands after 22 of them" is a fact that fails loudly when it stops being true.

## What a document looks like

Front matter between two rows of three dashes, then the prose. Nothing else.

```markdown
---
title: The Cairn Protocol
language: en
stylesheet: cairn-whitepaper.css
strap:
  A proof-of-work currency in which the state every node must hold is capped
  by consensus rule at a fixed size.
byline: Draft, 31 August 2026
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
abstract: Abstract
footer: Cairn · draft whitepaper · 29 August 2026
footer: No mainnet exists
---

# Cairn: a chain whose validation state does not grow

The paragraphs above the first `## ` are the abstract.

## The problem is the cost of verifying

### The hot set
```

The keys, and there are no others:

| Key | What it is |
| --- | --- |
| `title` | what a browser tab says, which is not always the heading |
| `language` | the tag a browser hyphenates by and a screen reader speaks in |
| `stylesheet` | the file beside this one that styles it |
| `strap` | the sentence under the heading |
| `byline` | one line of the byline; write the key again for the next one |
| `abstract` | the word over the summary, for a document that opens with one |
| `footer` | one item in the footer; write the key again for the next one |

`title`, `language` and `stylesheet` are required. A value runs over several
lines by indenting the ones that follow. A key nobody knows is an error rather
than a line quietly dropped, because front matter is exactly where a typo
would otherwise cost a byline and say nothing.

**The section numbers are counted, not typed.** `## ` is a section and gets
the next number; `### ` under it gets `section.subsection`. Do not write a
number in a heading. Inserting a section used to mean editing every number
below it, which is how a paper came to have two sections called 7.

**Where a paragraph wraps is part of the document.** The generated HTML keeps
the line breaks the Markdown has, because several guards search the served
text for phrases and some of those phrases span a line break. Rewrapping a
paragraph is a change, and the round-trip test will say so.

**What Markdown cannot say, write as HTML.** A block of HTML passes through to
where it sits on the page, indented to fit. That is the figures, the parameter
list, the table, the reference list, and a paragraph carrying a class such as
`claim` or `fig-note`: about a fifth of the whitepaper, and the rest of it is
prose. Leave no blank line inside such a block or Markdown ends it early.

A Markdown table is refused by name rather than rendered as a row of pipes, so
you find out at once rather than in a diff. Anything else the renderer has no
shape for is refused the same way: nothing is dropped quietly.

## Adding a document

1. Write `docs/your-document.md`.
2. Add it to `DOCUMENTS` in `crates/cairn-docs/src/lib.rs` so it is rendered.
3. Add it to `PAPERS` in `crates/cairn-explorer/src/assets.rs` with the path it
   is served at, so a node hands it out.
4. Run `cargo run -p cairn-docs` to generate the HTML, and commit both files.
5. If it names a number that comes from the code, write the guard first and the
   sentence second. It is much easier in that order.

## Changing a document

Edit the Markdown, run `cargo run -p cairn-docs`, commit both. The test
`the_committed_html_is_what_the_markdown_renders_to` fails if you forget the
second step, which is the point of it.

If you change a figure, the guard that holds it will fail. That is not an
obstacle to route around: it is the guard telling you that either the code
changed and the document is catching up, or the document is now wrong. Find out
which before making the test pass.
