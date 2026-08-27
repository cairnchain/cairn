//! A small HTTP server.
//!
//! It answers GET and HEAD, reads no request body, and serves nothing from the
//! filesystem, so there is no upload path and no way to name a file outside
//! what was compiled in. One thread per connection, the same choice the node
//! makes for its peers and for the same reason: a reader can hold the whole
//! thing in their head.

use std::io::{self, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Longest request line and header block accepted.
const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Longest single line accepted while reading the head.
const MAX_LINE_BYTES: usize = 2 * 1024;
/// Connections served at once. Beyond this a caller is turned away rather than
/// queued, so a flood costs threads that are already bounded.
const MAX_CONNECTIONS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a caller asked for, once the head has been read.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    /// Percent-decoded path, always starting with a slash.
    pub(crate) path: String,
    /// Everything after the first question mark, undecoded.
    pub(crate) query: String,
    /// True for HEAD, where the body is computed but not sent.
    pub(crate) head_only: bool,
}

impl Request {
    /// The value of `name` in the query string, percent-decoded.
    pub(crate) fn parameter(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| percent_decode(value))
        })
    }

    /// The path with `prefix` removed, if it starts with it.
    pub(crate) fn after(&self, prefix: &str) -> Option<&str> {
        self.path.strip_prefix(prefix)
    }
}

/// What to send back.
#[derive(Clone, Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    /// Value of the Cache-Control header.
    pub(crate) cache: &'static str,
    pub(crate) body: Vec<u8>,
}

impl Response {
    pub(crate) fn json(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json; charset=utf-8",
            cache: "no-store",
            body: body.into_bytes(),
        }
    }

    pub(crate) fn asset(content_type: &'static str, body: &'static str) -> Self {
        Self {
            status: 200,
            content_type,
            // Short rather than long: the explorer is served by whoever runs
            // it, and an operator who redeploys should not have to explain to
            // visitors why they are still looking at yesterday.
            cache: "public, max-age=60",
            body: body.as_bytes().to_vec(),
        }
    }

    pub(crate) fn error(status: u16, message: &str) -> Self {
        let mut json = crate::json::Writer::new();
        json.begin_object();
        json.field_str("error", message);
        json.end_object();
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            cache: "no-store",
            body: json.finish().into_bytes(),
        }
    }
}

/// Serves `listener` until `running` is cleared, handing every request to
/// `answer`.
pub(crate) fn serve<F>(listener: &TcpListener, running: &Arc<AtomicBool>, answer: F)
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let answer = Arc::new(answer);
    let live = Arc::new(AtomicUsize::new(0));
    // So the accept loop wakes up often enough to notice a shutdown.
    let _ = listener.set_nonblocking(false);

    for incoming in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = incoming else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

        if live.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            let mut stream = stream;
            let _ = write_response(
                &mut stream,
                &Response::error(503, "too many connections"),
                true,
            );
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }

        let answer = Arc::clone(&answer);
        let counted = Arc::clone(&live);
        live.fetch_add(1, Ordering::SeqCst);
        let spawned = thread::Builder::new()
            .name("explorer-http".to_owned())
            .spawn(move || {
                handle(stream, answer.as_ref());
                counted.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn handle<F>(mut stream: TcpStream, answer: &F)
where
    F: Fn(&Request) -> Response,
{
    let response = match read_request(&stream) {
        Ok(Some(request)) => {
            let head_only = request.head_only;
            (answer(&request), head_only)
        }
        Ok(None) => (Response::error(405, "only GET and HEAD are served"), false),
        Err(status) => (Response::error(status, "malformed request"), false),
    };
    let _ = write_response(&mut stream, &response.0, response.1);
    let _ = stream.shutdown(Shutdown::Both);
}

/// Reads one request head.
///
/// `Ok(None)` means a well-formed request this server does not answer.
fn read_request(stream: &TcpStream) -> Result<Option<Request>, u16> {
    let mut reader = BufReader::new(stream);
    let mut consumed = 0usize;
    let start = read_line(&mut reader, &mut consumed)?;

    // Drain the header block so the caller sees a complete exchange rather
    // than a reset, and so a request that never ends is cut off by the cap.
    loop {
        let line = read_line(&mut reader, &mut consumed)?;
        if line.is_empty() {
            break;
        }
    }

    let mut parts = start.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(400);
    };
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return Err(400);
    }
    let head_only = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return Ok(None),
    };

    // An absolute target is legal in HTTP but has no use here, and accepting
    // one would mean deciding what host it named.
    if !target.starts_with('/') {
        return Err(400);
    }
    let (raw_path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = percent_decode(raw_path);
    if path.contains('\0') {
        return Err(400);
    }

    Ok(Some(Request {
        path,
        query: query.to_owned(),
        head_only,
    }))
}

fn read_line(reader: &mut BufReader<&TcpStream>, consumed: &mut usize) -> Result<String, u16> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= MAX_LINE_BYTES || *consumed >= MAX_HEAD_BYTES {
            return Err(431);
        }
        match io::Read::read(reader, &mut byte) {
            Ok(0) => return Err(400),
            Ok(_) => {}
            Err(_) => return Err(408),
        }
        *consumed = consumed.saturating_add(1);
        let Some(read) = byte.first().copied() else {
            return Err(400);
        };
        if read == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return String::from_utf8(line).map_err(|_| 400);
        }
        line.push(read);
    }
}

fn write_response(stream: &mut TcpStream, response: &Response, head_only: bool) -> io::Result<()> {
    let mut head = String::new();
    head.push_str("HTTP/1.1 ");
    head.push_str(&response.status.to_string());
    head.push(' ');
    head.push_str(reason(response.status));
    head.push_str("\r\n");
    head.push_str("content-type: ");
    head.push_str(response.content_type);
    head.push_str("\r\n");
    head.push_str("content-length: ");
    head.push_str(&response.body.len().to_string());
    head.push_str("\r\n");
    head.push_str("cache-control: ");
    head.push_str(response.cache);
    head.push_str("\r\n");
    head.push_str(SECURITY_HEADERS);
    head.push_str("connection: close\r\n\r\n");

    stream.write_all(head.as_bytes())?;
    if !head_only {
        stream.write_all(&response.body)?;
    }
    stream.flush()
}

/// Sent with every answer.
///
/// The policy allows nothing from anywhere else: no third-party script, no
/// remote font, no analytics. A page about a chain that asks you to trust
/// nobody should not itself call out to four companies to render a heading.
const SECURITY_HEADERS: &str = concat!(
    "content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; ",
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'\r\n",
    "x-content-type-options: nosniff\r\n",
    "referrer-policy: no-referrer\r\n",
    "cross-origin-opener-policy: same-origin\r\n",
    "permissions-policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()\r\n",
);

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Decodes percent escapes, leaving anything malformed as written.
///
/// A stray percent sign is far more likely to be a person pasting an address
/// than an attack, and turning it into an error would only hide the paste.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'%' {
            let high = bytes.get(index.saturating_add(1)).copied().and_then(nibble);
            let low = bytes.get(index.saturating_add(2)).copied().and_then(nibble);
            if let (Some(high), Some(low)) = (high, low) {
                out.push(high.saturating_mul(16).saturating_add(low));
                index = index.saturating_add(3);
                continue;
            }
        }
        out.push(byte);
        index = index.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => byte
            .checked_sub(b'a')
            .and_then(|value| value.checked_add(10)),
        b'A'..=b'F' => byte
            .checked_sub(b'A')
            .and_then(|value| value.checked_add(10)),
        _ => None,
    }
}

/// Where the listener ended up, so a caller can print it.
pub(crate) fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{percent_decode, Request};

    fn request(path: &str, query: &str) -> Request {
        Request {
            path: path.to_owned(),
            query: query.to_owned(),
            head_only: false,
        }
    }

    #[test]
    fn percent_escapes_are_decoded() {
        assert_eq!(percent_decode("/a%20b"), "/a b");
        assert_eq!(percent_decode("%41%42"), "AB");
    }

    #[test]
    fn a_malformed_escape_is_left_alone() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn a_parameter_is_read_from_the_query() {
        let request = request("/api/search", "q=41%20208&other=1");
        assert_eq!(request.parameter("q").as_deref(), Some("41 208"));
        assert_eq!(request.parameter("missing"), None);
    }

    #[test]
    fn a_path_prefix_can_be_stripped() {
        let request = request("/api/block/17", "");
        assert_eq!(request.after("/api/block/"), Some("17"));
        assert_eq!(request.after("/api/tx/"), None);
    }
}
