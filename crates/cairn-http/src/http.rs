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
/// Bytes a form body may reach. A spend names an address, an amount and a
/// fee; anything past this is not one.
const MAX_BODY_BYTES: usize = 4096;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a caller asked for, once the head has been read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Percent-decoded path, always starting with a slash.
    pub path: String,
    /// Everything after the first question mark, undecoded.
    pub query: String,
    /// True for HEAD, where the body is computed but not sent.
    pub head_only: bool,
    /// True for POST, which is how anything that changes something arrives.
    ///
    /// A GET that spends money would be a link: something a page could be
    /// made to follow, and something a browser would keep in its history and
    /// offer to repeat.
    pub post: bool,
    /// The form body of a POST, undecoded. Empty for anything else.
    pub body: String,
    /// The Host header as given, so a server can refuse a name it does not
    /// answer to.
    pub host: String,
    /// The Origin header as given, empty when there was none.
    ///
    /// A browser sends one when a page makes the request and none when the
    /// person navigated there. A server that only ever wants to be reached by
    /// the second can refuse everything with an origin, which is what stops a
    /// page open in another tab from speaking to a wallet.
    pub origin: String,
}

impl Request {
    /// The value of `name` in the query string, percent-decoded.
    pub fn parameter(&self, name: &str) -> Option<String> {
        field(&self.query, name)
    }

    /// The value of `name` in a form body, percent-decoded.
    pub fn field(&self, name: &str) -> Option<String> {
        field(&self.body, name)
    }

    /// The path with `prefix` removed, if it starts with it.
    pub fn after(&self, prefix: &str) -> Option<&str> {
        self.path.strip_prefix(prefix)
    }
}

/// Reads one `name=value` out of a query string or a form body.
///
/// Plus signs are spaces in a form, which is the one place this differs from
/// a path: a caller writing `a+b` in a field means `a b`, and a wallet that
/// read it as `a+b` would refuse an address it was given correctly.
fn field(text: &str, name: &str) -> Option<String> {
    text.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| percent_decode(&value.replace('+', " ")))
    })
}

/// What to send back.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    /// Value of the Cache-Control header.
    pub cache: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json; charset=utf-8",
            cache: "no-store",
            body: body.into_bytes(),
        }
    }

    pub fn asset(content_type: &'static str, body: &'static str) -> Self {
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

    pub fn error(status: u16, message: &str) -> Self {
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
///
/// `running` is read between connections rather than waited on: this blocks
/// on accept, so clearing it stops the server at the next visitor and not
/// before. That is enough for what runs here. A node has to stop on command,
/// because an operator restarting one should not wait on a stranger; a website
/// is stopped by stopping the process, and the explorer keeps nothing in
/// memory that is not already on disk.
pub fn serve<F>(listener: &TcpListener, running: &Arc<AtomicBool>, answer: F)
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let answer = Arc::new(answer);
    let live = Arc::new(AtomicUsize::new(0));
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
    let response = match read_request(&mut BufReader::new(&stream)) {
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
fn read_request<R: io::Read>(reader: &mut R) -> Result<Option<Request>, u16> {
    let mut consumed = 0usize;
    let start = read_line(reader, &mut consumed)?;

    // Drain the header block so the caller sees a complete exchange rather
    // than a reset, and so a request that never ends is cut off by the cap.
    // Two of them are kept: what host the caller thinks it is talking to, and
    // how long a body to expect.
    let mut host = String::new();
    let mut origin = String::new();
    let mut length = 0usize;
    loop {
        let line = read_line(reader, &mut consumed)?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("host") {
                value.clone_into(&mut host);
            } else if name.eq_ignore_ascii_case("origin") {
                value.clone_into(&mut origin);
            } else if name.eq_ignore_ascii_case("content-length") {
                length = value.parse().map_err(|_| 400u16)?;
            }
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
    let (head_only, post) = match method {
        "GET" => (false, false),
        "HEAD" => (true, false),
        "POST" => (false, true),
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

    // Read only for a POST, and only up to what the cap allows, so a caller
    // announcing a body it never sends costs a timeout rather than memory.
    let mut body = String::new();
    if post {
        if length > MAX_BODY_BYTES {
            return Err(413);
        }
        let mut bytes = vec![0u8; length];
        reader.read_exact(&mut bytes).map_err(|_| 400u16)?;
        body = String::from_utf8(bytes).map_err(|_| 400u16)?;
    }

    Ok(Some(Request {
        path,
        query: query.to_owned(),
        head_only,
        post,
        body,
        host,
        origin,
    }))
}

fn read_line<R: io::Read>(reader: &mut R, consumed: &mut usize) -> Result<String, u16> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= MAX_LINE_BYTES || *consumed >= MAX_HEAD_BYTES {
            return Err(431);
        }
        match reader.read(&mut byte) {
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
pub fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{percent_decode, Request};
    use std::fmt::Write as _;

    fn request(path: &str, query: &str) -> Request {
        Request {
            path: path.to_owned(),
            query: query.to_owned(),
            head_only: false,
            post: false,
            body: String::new(),
            host: String::new(),
            origin: String::new(),
        }
    }

    /// A form sends a space as a plus, and a path does not. Reading a field
    /// the way a path is read would hand back an address with a plus where a
    /// space belongs, and refuse something the person typed correctly.
    #[test]
    fn a_form_field_reads_a_plus_as_a_space() {
        let mut request = request("/api/send", "");
        request.post = true;
        request.body = "to=ab+cd&amount=1.5&note=a%20b".to_owned();
        assert_eq!(request.field("to").as_deref(), Some("ab cd"));
        assert_eq!(request.field("amount").as_deref(), Some("1.5"));
        assert_eq!(request.field("note").as_deref(), Some("a b"));
        assert_eq!(request.field("missing"), None);
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

    fn head(text: &str) -> Result<Option<Request>, u16> {
        super::read_request(&mut text.as_bytes())
    }

    #[test]
    fn an_ordinary_request_is_read() {
        let request = head("GET /api/status HTTP/1.1\r\nhost: x\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(request.path, "/api/status");
        assert!(!request.head_only);
    }

    #[test]
    fn a_query_string_is_kept_apart_from_the_path() {
        let request = head("GET /api/blocks?from=12&limit=5 HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(request.path, "/api/blocks");
        assert_eq!(request.parameter("from").as_deref(), Some("12"));
    }

    /// This server reads no bodies, so anything that would carry one is
    /// refused rather than half understood.
    #[test]
    fn a_method_this_server_does_not_answer_is_turned_away() {
        // POST is answered now, so the method that is not is one of the rest.
        assert!(head("PATCH /api/status HTTP/1.1\r\n\r\n")
            .unwrap()
            .is_none());
        assert!(head("PUT / HTTP/1.1\r\n\r\n").unwrap().is_none());
        assert!(head("DELETE / HTTP/1.1\r\n\r\n").unwrap().is_none());
    }

    #[test]
    fn a_head_request_is_answered_without_a_body() {
        let request = head("HEAD / HTTP/1.1\r\n\r\n").unwrap().unwrap();
        assert!(request.head_only);
    }

    /// An absolute target is legal HTTP and has no meaning here, so accepting
    /// one would mean deciding what host it named.
    #[test]
    fn a_target_that_is_not_a_path_is_refused() {
        assert_eq!(head("GET http://elsewhere/ HTTP/1.1\r\n\r\n"), Err(400));
        assert_eq!(head("GET api/status HTTP/1.1\r\n\r\n"), Err(400));
    }

    #[test]
    fn a_malformed_request_line_is_refused() {
        assert_eq!(head("GET\r\n\r\n"), Err(400));
        assert_eq!(head("GET / HTTP/1.1 extra\r\n\r\n"), Err(400));
        assert_eq!(head("GET / SPDY/3\r\n\r\n"), Err(400));
    }

    /// The head is the one thing a caller controls the size of before
    /// anything is decided about them.
    #[test]
    fn an_endless_header_block_is_cut_off() {
        let mut request = String::from("GET / HTTP/1.1\r\n");
        for index in 0..2_000 {
            let _ = write!(request, "x-pad-{index}: filler\r\n");
        }
        request.push_str("\r\n");
        assert_eq!(head(&request), Err(431));
    }

    #[test]
    fn a_single_endless_line_is_cut_off() {
        let mut request = String::from("GET /");
        request.push_str(&"a".repeat(4_000));
        request.push_str(" HTTP/1.1\r\n\r\n");
        assert_eq!(head(&request), Err(431));
    }

    #[test]
    fn a_request_that_stops_partway_is_refused() {
        assert_eq!(head("GET / HTTP/1.1\r\nhost: x"), Err(400));
        assert_eq!(head(""), Err(400));
    }

    /// Nothing is read from disk, so a traversal has nothing to reach. The
    /// path still arrives decoded and intact, which is what the router sees.
    #[test]
    fn a_traversal_attempt_is_just_a_path() {
        let request = head("GET /..%2f..%2fetc%2fpasswd HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(request.path, "/../../etc/passwd");
    }

    #[test]
    fn an_embedded_null_is_refused() {
        assert_eq!(head("GET /a%00b HTTP/1.1\r\n\r\n"), Err(400));
    }

    #[test]
    fn a_path_prefix_can_be_stripped() {
        let request = request("/api/block/17", "");
        assert_eq!(request.after("/api/block/"), Some("17"));
        assert_eq!(request.after("/api/tx/"), None);
    }
}
