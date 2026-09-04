//! The site says the same thing in every language it claims to speak.
//!
//! Everything a reader sees is a key resolved against a translation file at
//! render time, and a key that resolves to nothing renders as the key itself.
//! Nothing fails, nothing is logged, and the page simply says `run.get.title`
//! to whoever chose that language. So the check has to happen here.
//!
//! Two things are held in place. Every key the page asks for exists in
//! English, which catches a typo and a section that was written but never
//! translated. And French carries exactly the keys English does, which catches
//! the half-finished translation: adding a paragraph in one file and not the
//! other is the ordinary way this breaks.
//!
//! The reader below is written rather than pulled in, like the writer the
//! explorer answers with. It reads keys and skips values, which is all that is
//! needed to compare two files by their shape.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

const EN: &str = include_str!("../../../web/i18n/en.json");
const FR: &str = include_str!("../../../web/i18n/fr.json");
const SCRIPT: &str = include_str!("../../../web/cairn.js");
const PAGE: &str = include_str!("../../../web/index.html");

/// A scanner over one translation file.
struct Scan<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Scan<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            at: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    /// One string, returned as bytes so a French value cannot be mangled on
    /// the way past. Keys are ASCII; values are only skipped.
    fn string(&mut self) -> String {
        assert_eq!(self.peek(), Some(b'"'), "a string starts with a quote");
        self.at += 1;
        let mut out: Vec<u8> = Vec::new();
        while let Some(byte) = self.peek() {
            self.at += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    out.push(byte);
                    if self.peek().is_some() {
                        out.push(self.bytes[self.at]);
                        self.at += 1;
                    }
                }
                _ => out.push(byte),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Consumes one whole value, whatever it is.
    fn skip(&mut self) {
        self.skip_space();
        match self.peek() {
            Some(b'"') => {
                let _ = self.string();
            }
            Some(b'{' | b'[') => {
                let mut depth = 0usize;
                while let Some(byte) = self.peek() {
                    match byte {
                        b'"' => {
                            let _ = self.string();
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                self.at += 1;
                                return;
                            }
                        }
                        _ => {}
                    }
                    self.at += 1;
                }
            }
            _ => {
                while matches!(self.peek(), Some(byte) if !b",}]".contains(&byte)) {
                    self.at += 1;
                }
            }
        }
    }

    /// Records every leaf under `prefix`.
    ///
    /// An array is one leaf rather than one per entry: a language may say in
    /// two paragraphs what another says in three and still be complete.
    fn leaves(&mut self, prefix: &str, out: &mut BTreeSet<String>) {
        self.skip_space();
        if self.peek() != Some(b'{') {
            self.skip();
            if !prefix.is_empty() {
                out.insert(prefix.to_owned());
            }
            return;
        }
        self.at += 1;
        loop {
            self.skip_space();
            match self.peek() {
                Some(b'}') => {
                    self.at += 1;
                    return;
                }
                Some(b',') => {
                    self.at += 1;
                    continue;
                }
                Some(b'"') => {}
                _ => return,
            }
            let key = self.string();
            self.skip_space();
            if self.peek() == Some(b':') {
                self.at += 1;
            }
            let path = if prefix.is_empty() {
                key
            } else {
                format!("{prefix}.{key}")
            };
            self.leaves(&path, out);
        }
    }
}

fn leaves_of(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    Scan::new(text).leaves("", &mut found);
    found
}

/// Whether the site would find something for `key`.
///
/// A key may name a leaf, or an object holding one string per reading level,
/// which is what the page resolves at render time. Both count as present.
fn resolves(leaves: &BTreeSet<String>, key: &str) -> bool {
    leaves.contains(key)
        || leaves
            .iter()
            .any(|leaf| leaf.starts_with(&format!("{key}.")))
}

/// Every key the script asks for by name, and every prefix it builds one from.
///
/// A call like `t('learn.' + name + '.title')` cannot be read statically. Its
/// literal part is kept apart as a prefix, and all that is asked of a prefix
/// is that the file has something under it: enough to catch a section renamed
/// on one side only.
fn keys_used() -> (BTreeSet<String>, BTreeSet<String>) {
    let mut whole = BTreeSet::new();
    let mut prefixes = BTreeSet::new();

    for name in ["t", "prose", "paragraphs", "explainer"] {
        let opening = format!("{name}('");
        let mut from = 0usize;
        while let Some(found) = SCRIPT[from..].find(&opening) {
            let at = from + found;
            from = at + opening.len();
            // `t(` has to be a call and not the tail of another name.
            let before = SCRIPT[..at].chars().next_back().unwrap_or(' ');
            if before.is_alphanumeric() || before == '_' || before == '.' {
                continue;
            }
            let Some(end) = SCRIPT[from..].find('\'') else {
                continue;
            };
            let key = &SCRIPT[from..from + end];
            let rest = SCRIPT[from + end + 1..].trim_start();
            if rest.starts_with('+') {
                prefixes.insert(key.to_owned());
            } else {
                whole.insert(key.to_owned());
            }
        }
    }

    for attribute in ["data-t=\"", "data-t-placeholder=\""] {
        let mut from = 0usize;
        while let Some(found) = PAGE[from..].find(attribute) {
            let at = from + found + attribute.len();
            from = at;
            let Some(end) = PAGE[at..].find('"') else {
                continue;
            };
            whole.insert(PAGE[at..at + end].to_owned());
        }
    }

    (whole, prefixes)
}

#[test]
fn every_key_the_site_asks_for_is_written_in_english() {
    let english = leaves_of(EN);
    assert!(english.len() > 200, "the file was read: {}", english.len());

    let (whole, prefixes) = keys_used();
    assert!(whole.len() > 100, "keys were found: {}", whole.len());

    let missing: Vec<&String> = whole
        .iter()
        .filter(|key| !resolves(&english, key))
        .collect();
    assert!(missing.is_empty(), "nothing answers for {missing:?}");

    let empty: Vec<&String> = prefixes
        .iter()
        .filter(|prefix| !english.iter().any(|leaf| leaf.starts_with(*prefix)))
        .collect();
    assert!(empty.is_empty(), "nothing at all under {empty:?}");
}

#[test]
fn french_carries_exactly_what_english_does() {
    let english = leaves_of(EN);
    let french = leaves_of(FR);

    let untranslated: Vec<&String> = english.difference(&french).collect();
    assert!(untranslated.is_empty(), "not in French: {untranslated:?}");

    let orphaned: Vec<&String> = french.difference(&english).collect();
    assert!(orphaned.is_empty(), "in French only: {orphaned:?}");
}

/// The list of downloads is data inside the script, so the keys that name each
/// one cannot be read by the scan above. They are checked here against the
/// same list the page renders from.
#[test]
fn every_download_has_a_name_in_both_languages() {
    let english = leaves_of(EN);
    let french = leaves_of(FR);

    let mut count = 0usize;
    let mut from = 0usize;
    while let Some(found) = SCRIPT[from..].find("{ key: '") {
        let at = from + found + "{ key: '".len();
        from = at;
        let Some(end) = SCRIPT[at..].find('\'') else {
            continue;
        };
        let build = &SCRIPT[at..at + end];
        for field in ["name", "note"] {
            let key = format!("run.platform.{build}.{field}");
            assert!(resolves(&english, &key), "{key} is missing in English");
            assert!(resolves(&french, &key), "{key} is missing in French");
        }
        count += 1;
    }
    assert!(count >= 5, "every build was read: {count}");
}

/// The site does not tell a visitor that the sampled start is unwritten.
///
/// The lesson that exists to state the limits honestly said, in both
/// languages, that joining still meant downloading the whole history, that
/// what was missing was the protocol serving the sample, and that a node holds
/// every block of the branch it follows in memory. All three had stopped being
/// true: the wire carries the messages below, the node reports `Joined` and
/// `Probation` while it uses them, and the same two files carry the sentences
/// the site shows a visitor while that is happening. A page whose subject is
/// candour was describing a Cairn from three test networks ago.
///
/// The messages are named rather than described, so this fails on the day one
/// of them is removed rather than going quietly out of date the way the prose
/// did.
#[test]
fn the_site_does_not_call_the_sampled_start_unwritten() {
    let weigh = cairn_net::Message::GetJoin {
        what: cairn_net::message::Joining::Weight,
        part: 0,
    };
    let hand_over = cairn_net::Message::GetJoin {
        what: cairn_net::message::Joining::Ledger,
        part: 0,
    };
    assert_eq!(weigh.kind(), "get join");
    assert_eq!(hand_over.kind(), "get join");

    for (language, text) in [("English", EN), ("French", FR)] {
        for stale in [
            "the part that uses it is not written yet",
            "What is missing is the protocol that serves that sample",
            "a node holds every block of the branch it follows in memory",
            "la partie qui s'en sert n'est pas écrite",
            "Ce qui manque est le protocole qui sert cet échantillon",
            "un nœud garde en mémoire tous les blocs de la branche qu'il suit",
        ] {
            assert!(
                !text.contains(stale),
                "the {language} site still says `{stale}`, which this build does"
            );
        }
    }
}
