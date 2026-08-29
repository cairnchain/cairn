//! A small HTTP server and a JSON writer, shared by the programs that put a
//! page in front of a person.
//!
//! Two of them do: the explorer, which anyone may read, and the wallet, which
//! only its owner does. Written here rather than pulled in, and written once
//! rather than twice, because everything a person is asked to run against this
//! chain should stay readable end to end, and a second copy of a server is a
//! second place for a hole to open.
//!
//! It does what those two need and nothing else: GET and HEAD, one request per
//! connection, no compression, no ranges, no keep-alive. Anything else is
//! answered with a status and dropped.

pub mod http;
pub mod json;

pub use http::{bind, serve, Request, Response};
pub use json::Writer;
