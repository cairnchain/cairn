//! Writing JSON, without a serialisation framework.
//!
//! The explorer answers with a handful of shapes and reads none back, so a
//! writer that tracks nesting and escapes strings is the whole requirement. It
//! is written here rather than pulled in because everything a person is asked
//! to run against this chain should stay readable end to end.

use std::fmt::Write as _;

/// Where a document stood, for [`Writer::rewind`].
#[derive(Clone, Copy, Debug)]
pub struct Mark {
    at: usize,
    /// Whether the container this mark sits in was still empty, so that
    /// rewinding the first row of an array does not leave a comma behind.
    empty: Option<bool>,
}

/// A JSON document under construction.
///
/// Commas and nesting are tracked here rather than left to the caller, so a
/// missing separator cannot produce a document that parses as something else.
#[derive(Debug, Default)]
pub struct Writer {
    out: String,
    /// One entry per open container, true while it is still empty.
    empty: Vec<bool>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes written so far.
    ///
    /// What a caller building a list holds itself to. A page capped in rows is
    /// not capped in bytes, and bytes are what the connection's deadline is
    /// counted in.
    #[must_use]
    pub fn written(&self) -> usize {
        self.out.len()
    }

    /// Where the document stands, so a row that turns out not to fit can be
    /// taken back off it.
    #[must_use]
    pub fn mark(&self) -> Mark {
        Mark {
            at: self.out.len(),
            empty: self.empty.last().copied(),
        }
    }

    /// Undoes everything written since `mark`.
    ///
    /// A page has to decide whether a row fits after writing it, because what
    /// a row weighs is not knowable before. Stopping after the row that went
    /// over means going over by a row, and a ceiling exceeded by a row is not
    /// a ceiling; so the row comes back off and the page names it as the next
    /// one.
    ///
    /// Only meaningful at the same nesting depth the mark was taken at, which
    /// is what a caller writing one whole row at a time has. Anything deeper
    /// is still open and rewinding to here would leave the document unclosed.
    pub fn rewind(&mut self, mark: Mark) {
        if mark.at > self.out.len() {
            return;
        }
        self.out.truncate(mark.at);
        if let (Some(empty), Some(was)) = (self.empty.last_mut(), mark.empty) {
            *empty = was;
        }
    }

    /// Emits the separator this position needs, if any.
    fn separate(&mut self) {
        if let Some(empty) = self.empty.last_mut() {
            if *empty {
                *empty = false;
            } else {
                self.out.push(',');
            }
        }
    }

    pub fn begin_object(&mut self) {
        self.separate();
        self.out.push('{');
        self.empty.push(true);
    }

    pub fn end_object(&mut self) {
        self.empty.pop();
        self.out.push('}');
    }

    pub fn begin_array(&mut self) {
        self.separate();
        self.out.push('[');
        self.empty.push(true);
    }

    pub fn end_array(&mut self) {
        self.empty.pop();
        self.out.push(']');
    }

    /// Names the next value. Only meaningful inside an object.
    ///
    /// The value that follows belongs to this member rather than being a
    /// sibling of it, so the enclosing container is marked empty again for
    /// exactly one value and no comma is emitted before it.
    pub fn key(&mut self, name: &str) {
        self.separate();
        escape_into(name, &mut self.out);
        self.out.push(':');
        if let Some(empty) = self.empty.last_mut() {
            *empty = true;
        }
    }

    pub fn string(&mut self, value: &str) {
        self.separate();
        escape_into(value, &mut self.out);
    }

    pub fn u64(&mut self, value: u64) {
        self.separate();
        let _ = write!(self.out, "{value}");
    }

    pub fn usize(&mut self, value: usize) {
        self.separate();
        let _ = write!(self.out, "{value}");
    }

    pub fn bool(&mut self, value: bool) {
        self.separate();
        self.out.push_str(if value { "true" } else { "false" });
    }

    pub fn null(&mut self) {
        self.separate();
        self.out.push_str("null");
    }

    pub fn field_str(&mut self, name: &str, value: &str) {
        self.key(name);
        self.string(value);
    }

    pub fn field_u64(&mut self, name: &str, value: u64) {
        self.key(name);
        self.u64(value);
    }

    pub fn field_usize(&mut self, name: &str, value: usize) {
        self.key(name);
        self.usize(value);
    }

    pub fn field_bool(&mut self, name: &str, value: bool) {
        self.key(name);
        self.bool(value);
    }

    pub fn field_null(&mut self, name: &str) {
        self.key(name);
        self.null();
    }

    pub fn finish(self) -> String {
        self.out
    }
}

/// Writes `text` as a quoted JSON string.
///
/// Escapes the two characters JSON forbids raw, the shorthands, and every
/// control character. The forward slash is escaped as well, so a string can
/// never close a script element if an answer is ever inlined into a page.
fn escape_into(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            control if control < ' ' => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::Writer;

    /// A row taken back off leaves a document that still parses.
    ///
    /// The comma is the whole of the difficulty. A row written into an array
    /// that already held one puts a comma in front of itself, and truncating
    /// the bytes without putting the container's emptiness back leaves either
    /// a trailing comma or a missing one, both of which parse as something
    /// other than what was meant.
    #[test]
    fn a_row_that_did_not_fit_comes_back_off_cleanly() {
        for kept in 0..3usize {
            let mut json = Writer::new();
            json.begin_object();
            json.key("rows");
            json.begin_array();
            for row in 0..kept {
                json.begin_object();
                json.field_u64("n", row as u64);
                json.end_object();
            }
            let mark = json.mark();
            json.begin_object();
            json.field_u64("n", 99);
            json.end_object();
            json.rewind(mark);
            json.end_array();
            json.field_u64("next", 99);
            json.end_object();

            let rows: String = (0..kept)
                .map(|row| format!("{{\"n\":{row}}}"))
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(
                json.finish(),
                format!("{{\"rows\":[{rows}],\"next\":99}}"),
                "rewinding the row after {kept} of them"
            );
        }
    }

    /// And a mark from before anything was written is honoured.
    #[test]
    fn rewinding_past_what_was_written_does_nothing() {
        let mut json = Writer::new();
        json.begin_object();
        let mark = json.mark();
        json.field_u64("a", 1);
        let later = json.mark();
        json.rewind(mark);
        // A mark taken after the point rewound to is stale, and applying it
        // must not grow the document back.
        json.rewind(later);
        json.field_u64("b", 2);
        json.end_object();
        assert_eq!(json.finish(), "{\"b\":2}");
    }

    #[test]
    fn an_empty_object_is_written() {
        let mut json = Writer::new();
        json.begin_object();
        json.end_object();
        assert_eq!(json.finish(), "{}");
    }

    #[test]
    fn members_are_separated_but_their_values_are_not() {
        let mut json = Writer::new();
        json.begin_object();
        json.field_u64("height", 41_208);
        json.field_str("id", "0000000f");
        json.key("nested");
        json.begin_object();
        json.field_bool("active", true);
        json.end_object();
        json.end_object();
        assert_eq!(
            json.finish(),
            r#"{"height":41208,"id":"0000000f","nested":{"active":true}}"#
        );
    }

    #[test]
    fn arrays_separate_their_items() {
        let mut json = Writer::new();
        json.begin_array();
        json.u64(1);
        json.u64(2);
        json.begin_object();
        json.field_u64("three", 3);
        json.end_object();
        json.end_array();
        assert_eq!(json.finish(), r#"[1,2,{"three":3}]"#);
    }

    #[test]
    fn an_array_inside_a_member_does_not_lead_with_a_comma() {
        let mut json = Writer::new();
        json.begin_object();
        json.field_u64("first", 1);
        json.key("items");
        json.begin_array();
        json.u64(7);
        json.end_array();
        json.field_u64("last", 2);
        json.end_object();
        assert_eq!(json.finish(), r#"{"first":1,"items":[7],"last":2}"#);
    }

    #[test]
    fn strings_that_could_break_out_are_escaped() {
        let mut json = Writer::new();
        json.string("a\"b\\c\nd\u{1}e</script>");
        assert_eq!(json.finish(), r#""a\"b\\c\nd\u0001e<\/script>""#);
    }
}
