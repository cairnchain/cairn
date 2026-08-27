//! Writing JSON, without a serialisation framework.
//!
//! The explorer answers with a handful of shapes and reads none back, so a
//! writer that tracks nesting and escapes strings is the whole requirement. It
//! is written here rather than pulled in because everything a person is asked
//! to run against this chain should stay readable end to end.

use std::fmt::Write as _;

/// A JSON document under construction.
///
/// Commas and nesting are tracked here rather than left to the caller, so a
/// missing separator cannot produce a document that parses as something else.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    out: String,
    /// One entry per open container, true while it is still empty.
    empty: Vec<bool>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
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

    pub(crate) fn begin_object(&mut self) {
        self.separate();
        self.out.push('{');
        self.empty.push(true);
    }

    pub(crate) fn end_object(&mut self) {
        self.empty.pop();
        self.out.push('}');
    }

    pub(crate) fn begin_array(&mut self) {
        self.separate();
        self.out.push('[');
        self.empty.push(true);
    }

    pub(crate) fn end_array(&mut self) {
        self.empty.pop();
        self.out.push(']');
    }

    /// Names the next value. Only meaningful inside an object.
    ///
    /// The value that follows belongs to this member rather than being a
    /// sibling of it, so the enclosing container is marked empty again for
    /// exactly one value and no comma is emitted before it.
    pub(crate) fn key(&mut self, name: &str) {
        self.separate();
        escape_into(name, &mut self.out);
        self.out.push(':');
        if let Some(empty) = self.empty.last_mut() {
            *empty = true;
        }
    }

    pub(crate) fn string(&mut self, value: &str) {
        self.separate();
        escape_into(value, &mut self.out);
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.separate();
        let _ = write!(self.out, "{value}");
    }

    pub(crate) fn usize(&mut self, value: usize) {
        self.separate();
        let _ = write!(self.out, "{value}");
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.separate();
        self.out.push_str(if value { "true" } else { "false" });
    }

    pub(crate) fn null(&mut self) {
        self.separate();
        self.out.push_str("null");
    }

    pub(crate) fn field_str(&mut self, name: &str, value: &str) {
        self.key(name);
        self.string(value);
    }

    pub(crate) fn field_u64(&mut self, name: &str, value: u64) {
        self.key(name);
        self.u64(value);
    }

    pub(crate) fn field_usize(&mut self, name: &str, value: usize) {
        self.key(name);
        self.usize(value);
    }

    pub(crate) fn field_bool(&mut self, name: &str, value: bool) {
        self.key(name);
        self.bool(value);
    }

    pub(crate) fn field_null(&mut self, name: &str) {
        self.key(name);
        self.null();
    }

    pub(crate) fn finish(self) -> String {
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
