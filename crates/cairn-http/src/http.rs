//! A small HTTP server.
//!
//! It answers GET, HEAD and POST, and serves nothing from the filesystem, so
//! there is no upload path and no way to name a file outside what was
//! compiled in. A body is read only for a POST and only up to
//! [`MAX_BODY_BYTES`]; anything larger is refused with a 413 before a byte of
//! it is taken. One thread per connection, the same choice the node makes for
//! its peers and for the same reason: a reader can hold the whole thing in
//! their head.
//!
//! This said "answers GET and HEAD, reads no request body" for as long as it
//! has answered POST and read bodies, which is since three minutes after the
//! sentence was written. An attack surface is the one thing a header like
//! this is read for, and the method it left out is the one that spends money:
//! the wallet's send form is a POST. `the_header_names_every_method_this_
//! answers` holds the sentence against the code now, so the next method is a
//! decision somebody writes down rather than one the header quietly stops
//! describing.
//!
//! A thread each is only affordable because a connection is bounded three
//! ways: how many are served at once, how many come from one address, and how
//! long any one of them may take to ask its question and take its answer.

use std::collections::{HashMap, VecDeque};
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// Longest request line and header block accepted.
///
/// Published for the same reason [`read_request`] is: a test that restated
/// the number would pass on the day somebody changed it here.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Longest single line accepted while reading the head.
pub const MAX_LINE_BYTES: usize = 2 * 1024;
/// Connections served at once. Beyond this a caller is turned away rather than
/// queued, so a flood costs threads that are already bounded.
pub const MAX_CONNECTIONS: usize = 64;
/// Connections held at once from any one address.
///
/// The ceiling above says what a flood costs; this says that one machine
/// cannot be the whole flood. Without it a single host takes all
/// [`MAX_CONNECTIONS`] slots, holds them, and every other reader is met with a
/// 503 for as long as it cares to keep them.
///
/// A quarter of the ceiling rather than a handful, because one address here is
/// rarely one person. A browser opens several connections to an origin at
/// once, and a household or an office arrives behind a single NAT.
///
/// The loopback does not count against it, and that exemption is the whole
/// reason this number can stay this low. As the explorer is deployed it sits
/// behind a proxy on the same machine, so every reader of the public site
/// arrives as `127.0.0.1`: counting them together would have capped the site
/// at sixteen readers while doing nothing at all about the flood, since a
/// flood arriving through the proxy wears the proxy's address too. There the
/// protection is the deadline above and whatever the proxy imposes in front.
/// This ceiling is for the other deployment, a node answering on a public
/// port with nothing in front of it, which is where one address really is one
/// machine and where holding every slot is an attack somebody can mount from
/// a laptop.
pub const MAX_PER_HOST: usize = 16;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a caller has, from being accepted, to finish asking.
///
/// `READ_TIMEOUT` is measured per read, so every byte that arrives resets it:
/// a caller sending one byte every nine seconds is never late by that measure
/// and can hold its slot forever for a few bytes a minute. This one is fixed
/// when the connection is accepted and nothing the caller sends moves it.
///
/// Ten seconds, the same figure as the read timeout and for the same reason. A
/// request head is a few hundred bytes and every real client writes it in one
/// go the moment it connects, so ten seconds is already thousands of times
/// what an honest one needs on a bad link. Past that the caller is not slow,
/// it is not coming.
///
/// It is the first part of what a connection may cost. The rest is
/// [`ANSWER_DEADLINE`], because a caller that asks properly and then takes the
/// answer back in sips holds a slot exactly as well as one that never finishes
/// asking: `WRITE_TIMEOUT` is per write, and every byte the caller consents to
/// take resets it.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// The slowest link an answer is written for, in bytes a second.
///
/// Four kilobytes a second is thirty two kilobits, under any link somebody is
/// reading a website on: a phone on the oldest data network still in service
/// manages several times it, and anything genuinely slower would not have got
/// its request head in under the deadline that let it this far.
const SLOWEST_LINK: u64 = 4 * 1024;
/// The most time a caller can be given to take its answer, however long the
/// answer is.
///
/// The asking half can be a flat number because a request head is a few
/// hundred bytes whatever it asks for. An answer is not, so what it is worth
/// is worked out from its length at the rate above, and this is the ceiling on
/// that.
///
/// It was thirty seconds, which is a hundred and twenty kilobytes at that
/// rate, and the reason given was that "the biggest document compiled in is
/// some fifty kilobytes, and the API pages are capped at a couple of hundred
/// rows". Both halves had stopped being true. The specification is 167 016
/// bytes and was cut off about three thousand short of its end, which is not a
/// partial paper but an incomplete message: a body under its own
/// `content-length` gives the reader a transport error. And a page capped in
/// rows is not capped in bytes, which is the whole of what this ceiling
/// measures: one page of the pool came to eight megabytes.
///
/// Sixty seconds now, which is [`most_one_answer_carries`] and leaves the
/// largest document this site is for with room above it. The other half of
/// the repair is that the explorer holds its answers under that number rather
/// than under a count of rows.
///
/// A ceiling as well as a rate, because a length is only a bound while
/// somebody keeps the answers short. And the rate is read off the length
/// rather than off the writing, because nothing here can see how much of an
/// answer the caller has really taken: what a write reports is what the kernel
/// accepted, and a loopback socket swallows the best part of a megabyte before
/// it blocks, so paying by bytes written would hand a caller that read nothing
/// at all several minutes for the buffering.
pub const ANSWER_DEADLINE: Duration = Duration::from_secs(60);

/// The largest answer this server undertakes to deliver, in bytes.
///
/// What [`ANSWER_DEADLINE`] is worth at [`SLOWEST_LINK`], and therefore the
/// exact length past which an answer cannot reach a reader on the slowest link
/// this server writes for: it is cut off mid body and the reader gets a
/// transport error rather than a short page.
///
/// Published so that whoever builds an answer can hold it to the same number
/// rather than restate it. A ceiling on rows is not a ceiling on bytes, and
/// this is the one the socket actually enforces.
#[must_use]
pub fn most_one_answer_carries() -> usize {
    let seconds = usize::try_from(ANSWER_DEADLINE.as_secs()).unwrap_or(usize::MAX);
    let rate = usize::try_from(SLOWEST_LINK).unwrap_or(usize::MAX);
    seconds.saturating_mul(rate)
}
/// Bytes a form body may reach. A spend names an address, an amount and a
/// fee; anything past this is not one.
pub const MAX_BODY_BYTES: usize = 4096;

/// What a 405 tells a stranger this server answers.
///
/// Beside the methods rather than beside the refusal, so the two are read
/// together, and held to the `match` that decides them by
/// `the_405_names_every_method_this_answers`.
const ANSWERS: &str = "only GET, HEAD and POST are served";
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Bytes one read of [`drain`] takes off the socket.
const DRAIN_CHUNK: usize = 2 * 1024;
/// Bytes [`drain`] clears before it stops.
///
/// Past the head cap and the body cap together, so an honest caller is cleared
/// whole and a caller still sending past that is one this is right to stop
/// reading.
///
/// It was a count of reads, and the sixteen kilobytes was the arithmetic
/// written beside it: eight chunks of two. A count of reads is not a count of
/// bytes on a socket that answers `WouldBlock`, and the first one ended the
/// loop, so a caller whose body was still in flight was cleared of nothing.
/// The reasoning was always about bytes; the constant is now the thing the
/// reasoning is about.
const DRAIN_BYTES: usize = 16 * 1024;
/// How often [`drain`] looks again while it is waiting for bytes.
const DRAIN_POLL: Duration = Duration::from_millis(5);
/// How long a refusal waits for the request it is answering.
///
/// The refusal is written the moment a connection is accepted, a round trip
/// before the caller's body can arrive, so without this there is nothing on
/// the socket to clear and closing over what turns up afterwards resets the
/// connection, taking the answer with it. It is spent on the thread that
/// writes refusals and never in the accept loop.
const REFUSAL_PATIENCE: Duration = Duration::from_millis(250);
/// Refusals waiting to be written at once.
///
/// A floor under how many sockets that thread holds open. Past it a connection
/// is dropped without a refusal, which is what happened to every one of them
/// before the thread existed.
const REFUSALS_QUEUED: usize = 64;
/// How long to wait after an accept that failed, so a failure that persists is
/// a wait rather than a spin.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);

/// How long to leave a socket alone that has no room for more of the answer.
///
/// Short enough that the deadline is what ends a connection rather than this,
/// long enough that a caller reading at a human pace is not a spin.
const WRITE_POLL: Duration = Duration::from_millis(50);

/// The most that goes to the socket in one call.
///
/// Sets how often a long answer's deadline is looked at: once per chunk. Large
/// enough that it costs nothing on a fast link, small enough that a caller
/// cannot buy a whole answer's worth of writing on one check.
const WRITE_CHUNK: usize = 64 * 1024;

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
    let slots = Arc::new(Slots::default());
    let refusals = refusals();
    let _ = listener.set_nonblocking(false);

    for incoming in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = incoming else {
            // An accept that fails leaves the connection queued, so a loop
            // that goes straight round asks for the same one again at
            // once. The case that matters is running out of descriptors,
            // and it is one this process can reach on its own: a node's
            // peer sockets live here too. A pause turns that spin into a
            // wait, and costs nothing on the path where accepts succeed,
            // which is every other time round.
            //
            // Not tested, and saying so beats implying it is: reaching it
            // means lowering this process's descriptor limit, which a test
            // in this suite cannot do without deciding what every other
            // test in the process may open.
            thread::sleep(ACCEPT_PAUSE);
            continue;
        };
        let accepted = Instant::now();
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

        let host = stream.peer_addr().ok().map(|address| address.ip());
        let Some(slot) = slots.take(host) else {
            // Handed over rather than written here. Writing a refusal means
            // waiting for the request it answers, and this loop is the one
            // place that cannot wait: it is the loop every other caller is
            // queued behind, at the moment every caller is being refused.
            //
            // A full queue drops the connection without a word, which is what
            // happened to every refusal this server gave before the thread
            // existed.
            let _ = refusals.try_send((stream, accepted));
            continue;
        };

        let answer = Arc::clone(&answer);
        let _ = thread::Builder::new()
            .name("explorer-http".to_owned())
            .spawn(move || {
                handle(&stream, answer.as_ref(), accepted);
                // Mentioned so the closure owns the slot, which is what
                // gives it back on the ways out that never reach this line.
                drop(slot);
            });
    }
}

/// The connections in flight, counted for the server and for each address.
///
/// Two counts rather than one because they answer different questions: how
/// much this server has on at once, and whether one machine has all of it.
/// They sit under one lock so they cannot disagree about the same connection,
/// and the table holds only addresses that are connected right now, so it is
/// bounded by the ceiling like everything else here.
#[derive(Debug, Default)]
struct Slots {
    counts: Mutex<Counts>,
}

#[derive(Debug, Default)]
struct Counts {
    live: usize,
    from_host: HashMap<IpAddr, usize>,
}

/// One address for one machine, whichever way it arrived.
///
/// A listener bound to `[::]` reports every IPv4 caller as `::ffff:a.b.c.d`;
/// one bound to `0.0.0.0` reports the same caller as `a.b.c.d`. They are the
/// same machine, and this makes them the same key.
///
/// It is also what makes the loopback exemption work. `IpAddr::is_loopback`
/// answers for `127.0.0.0/8` and for `::1`, and says no to
/// `::ffff:127.0.0.1`. As this server is deployed it sits behind a proxy on
/// the same machine, and that proxy is an IPv4 caller, so on a dual stack
/// listener the exemption applied to nobody: the whole public site arrived
/// under one address that was meant to be uncounted and was counted, and was
/// capped at [`MAX_PER_HOST`] readers at a time. The note above that constant
/// calls the exemption "the whole reason this number can stay this low", and
/// the one deployment it was written for is the one it never reached.
fn one_machine(host: IpAddr) -> IpAddr {
    match host {
        IpAddr::V6(within) => within.to_ipv4_mapped().map_or(host, IpAddr::V4),
        IpAddr::V4(already) => IpAddr::V4(already),
    }
}

impl Slots {
    /// Takes a slot for a connection from `host`, unless there is no room for
    /// it, on the server or for that address.
    ///
    /// A `host` of `None` is a peer the operating system would not name, which
    /// is what a connection that has already gone looks like. It still counts
    /// against the ceiling, because it still costs a thread.
    fn take(self: &Arc<Self>, host: Option<IpAddr>) -> Option<Held> {
        let mut counts = self.counts();
        if counts.live >= MAX_CONNECTIONS {
            return None;
        }
        // Anything reaching this from the machine it runs on is either the
        // proxy in front of it, carrying every reader of the public site under
        // one address, or the operator. Neither is a flood worth counting, and
        // treating the proxy as one visitor was capping the site rather than
        // the attack.
        // Through `one_machine`, because the exemption below did not recognise
        // the shape the proxy actually arrives in.
        let counted = host.map(one_machine).filter(|host| !host.is_loopback());
        if let Some(host) = counted {
            let held = counts.from_host.get(&host).copied().unwrap_or(0);
            if held >= MAX_PER_HOST {
                return None;
            }
            counts.from_host.insert(host, held.saturating_add(1));
        }
        counts.live = counts.live.saturating_add(1);
        Some(Held {
            slots: Arc::clone(self),
            host: counted,
        })
    }

    /// A poisoned lock means a thread panicked while holding it. What is under
    /// it is two counters, and carrying on with them is better than turning
    /// every visitor away for the rest of the run.
    fn counts(&self) -> MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A slot, held for exactly as long as the connection that took it.
///
/// Given back when this is dropped rather than at the end of the code that
/// answers, so that every way out gives it back: an answer written, a caller
/// cut off at the deadline, a thread that panicked partway, and a thread that
/// never started, since the slot travels inside the closure that would have
/// run it.
#[derive(Debug)]
struct Held {
    slots: Arc<Slots>,
    host: Option<IpAddr>,
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut counts = self.slots.counts();
        counts.live = counts.live.saturating_sub(1);
        let Some(host) = self.host else {
            return;
        };
        let gone = match counts.from_host.get_mut(&host) {
            Some(held) => {
                *held = held.saturating_sub(1);
                *held == 0
            }
            None => false,
        };
        if gone {
            counts.from_host.remove(&host);
        }
    }
}

fn handle<F>(stream: &TcpStream, answer: &F, accepted: Instant)
where
    F: Fn(&Request) -> Response,
{
    let asking = deadline(accepted, Duration::ZERO);
    let response = match read_request(&mut BufReader::new(Timed {
        stream,
        until: asking,
    })) {
        Ok(Some(request)) => {
            let head_only = request.head_only;
            (answer(&request), head_only)
        }
        // [`ANSWERS`], not a sentence written here. This said "only GET and
        // HEAD are served" for as long as this server has answered POST, which
        // is the sentence the module header was corrected for: the correction
        // reached the comment a maintainer reads and not the line a stranger
        // is sent.
        Ok(None) => (Response::error(405, ANSWERS), false),
        Err(status) => (Response::error(status, refusal(status)), false),
    };
    let sent = if response.1 { 0 } else { response.0.body.len() };
    let until = deadline(accepted, answering(sent));
    // A blocking write comes back only when the whole slice has gone, and the
    // socket's own timeout is reset by every byte that moves, so one write of
    // a long answer sails past the deadline while the caller sips at it. A
    // socket that refuses to block is what puts the deadline back in charge.
    let _ = stream.set_nonblocking(true);
    let _ = write_response(&mut Timed { stream, until }, &response.0, response.1);
    // No patience: this path read its request, so anything left came with it.
    hang_up(stream, Duration::ZERO);
}

/// The thread that writes refusals, and the way to hand one to it.
///
/// A refusal is written before the caller's request has necessarily arrived,
/// and a connection closed over bytes nobody read is reset, which takes the
/// answer with it. Clearing them takes patience, and the accept loop is the
/// one place in this server that cannot spend any: it is where every other
/// caller is queued, at the moment every caller is being refused. So a refused
/// connection is handed here, and the waiting happens on a thread of its own.
///
/// One thread and a queue with a floor under it. Past [`REFUSALS_QUEUED`] a
/// connection is dropped without a refusal, which is what happened to every
/// one of them before, so a full queue is this server's old behaviour rather
/// than a new failure. If the thread cannot be started at all, the receiving
/// end goes with the closure and every send fails at once, which is the same
/// thing again.
fn refusals() -> std::sync::mpsc::SyncSender<(TcpStream, Instant)> {
    let (into, out) = std::sync::mpsc::sync_channel::<(TcpStream, Instant)>(REFUSALS_QUEUED);
    let _ = thread::Builder::new()
        .name("cairn-http-refuse".to_owned())
        .spawn(move || refuse_them(&out));
    into
}

/// A refused connection whose refusal is written, waiting for what the caller
/// is still sending so that closing over it does not reset the answer.
struct Waiting {
    stream: TcpStream,
    until: Instant,
    cleared: usize,
}

impl Waiting {
    /// Everything the caller has sent by now, taken off the socket without
    /// waiting for more. True once there is nothing left to clear, or no
    /// patience left to clear it with, and the connection can be dropped.
    fn done(&mut self) -> bool {
        let mut sink = [0u8; DRAIN_CHUNK];
        let mut source = &self.stream;
        loop {
            match source.read(&mut sink) {
                Ok(0) => return true,
                Ok(taken) => {
                    self.cleared = self.cleared.saturating_add(taken);
                    if self.cleared >= DRAIN_BYTES {
                        return true;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Instant::now() >= self.until;
                }
                Err(_) => return true,
            }
        }
    }
}

/// Puts a refused connection among those being waited on, giving up the
/// oldest first if that many are already held.
///
/// Its own function so the ceiling can be asked. `cargo mutants` found the
/// comparison could be turned around without a test noticing: the test of
/// refusals sends fewer callers than the ceiling, which asks whether they are
/// answered and not whether the thread holding them stays bounded.
fn wait_on(waiting: &mut VecDeque<Waiting>, stream: TcpStream, now: Instant) {
    if waiting.len() >= REFUSALS_QUEUED {
        waiting.pop_front();
    }
    waiting.push_back(Waiting {
        stream,
        until: now.checked_add(REFUSAL_PATIENCE).unwrap_or(now),
        cleared: 0,
    });
}

/// Drops every connection that has nothing more to clear or no more patience,
/// and keeps the rest. Returns how many it let go, which is what a test can
/// ask.
fn let_go_of_the_done(waiting: &mut VecDeque<Waiting>) -> usize {
    let before = waiting.len();
    waiting.retain_mut(|each| !each.done());
    before.saturating_sub(waiting.len())
}

/// Writes every refusal the moment it arrives, and waits on all of them
/// together.
///
/// It took them one at a time: write the 503, then wait up to
/// [`REFUSAL_PATIENCE`] for the caller to finish, then the next. A caller that
/// holds its socket open, which is what a browser does, costs that whole wait,
/// so refusals went out a quarter of a second apart, and each was judged
/// against its own connection's deadline, which kept running while it queued.
/// [`REQUEST_DEADLINE`] is forty quarters. Of forty eight callers refused
/// together and holding their sockets, forty read a 503 and eight read
/// nothing: the forty first was written after its deadline had passed and got
/// a bare close, which is the failure this thread was written to end, forty
/// places into the queue built to end it.
///
/// The write is what the caller needs and the wait only protects it, so the
/// two are pulled apart. Every refusal is written as soon as it is taken, and
/// the waiting is one look at each open socket per pass, none of them
/// blocking the rest. What the patience costs is the same per caller and no
/// longer adds up across them.
///
/// Holds at most [`REFUSALS_QUEUED`] waiting and that many again queued. Past
/// the first, the oldest waiting connection is let go early: its refusal is
/// already written, and letting it go risks the reset for that one caller,
/// which is the lesser loss beside holding sockets without bound.
fn refuse_them(out: &std::sync::mpsc::Receiver<(TcpStream, Instant)>) {
    let mut waiting: VecDeque<Waiting> = VecDeque::new();
    let mut closed = false;
    loop {
        // Everything that has arrived, each written as it is taken. Blocking
        // only when there is nobody to wait on.
        while !closed {
            let next = if waiting.is_empty() {
                match out.recv() {
                    Ok(next) => next,
                    Err(_) => return,
                }
            } else {
                match out.try_recv() {
                    Ok(next) => next,
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        closed = true;
                        break;
                    }
                }
            };
            let (stream, accepted) = next;
            write_refusal(&stream, accepted);
            wait_on(&mut waiting, stream, Instant::now());
        }
        let _ = let_go_of_the_done(&mut waiting);
        if waiting.is_empty() {
            if closed {
                return;
            }
        } else {
            thread::sleep(DRAIN_POLL);
        }
    }
}

/// The one answer a full server gives.
///
/// Body and all. This is written before a byte of the request has been read,
/// so nothing here knows whether a HEAD was asked for, and it used to pass the
/// flag that means "compute the body and do not send it". The caller then got
/// a head declaring `content-length: 32` and no body: not a short answer but
/// an incomplete message, which reaches a reader as a transport error rather
/// than as a 503. The one answer this server gives under load was the one
/// answer nobody could read.
///
/// Sending it is right for a GET, which is what almost every caller sends, and
/// harmless for a HEAD: `connection: close` ends the exchange, so there is no
/// next message to frame wrongly.
///
/// Written and the write half shut, and nothing more: the waiting that keeps
/// the answer from being reset happens in [`refuse_them`], across every
/// refused caller at once.
fn write_refusal(stream: &TcpStream, accepted: Instant) {
    let _ = stream.set_nonblocking(true);
    let _ = write_response(
        &mut Timed {
            stream,
            until: deadline(accepted, Duration::ZERO),
        },
        &Response::error(503, "too many connections"),
        false,
    );
    let _ = stream.shutdown(Shutdown::Write);
}

/// Bytes taken off the socket and dropped, before it is closed.
///
/// Closing a connection while bytes it received are still unread resets it,
/// and a reset takes with it whatever the caller has not already read of the
/// answer just written. Every answer this server gives is small, so what the
/// caller loses is all of it: the head arrives, the body does not, and the
/// message reaches a reader as a transport error rather than as the status it
/// says.
///
/// Every stack does this. What differs between them is whether the caller has
/// already taken the answer out of its own buffer before the reset lands,
/// which is a race, and `tests/audit_what_a_refusal_says.rs` has been winning
/// it on the machines this was written on and losing it on the Windows
/// runner.
///
/// The refusal a full server sends is the path that always leaves bytes
/// unread, because it answers before reading any. The ordinary path leaves
/// them whenever a caller sent more than its request head, which is any caller
/// that sent a body this server did not want.
///
/// Bounded, and never waiting on anything. The socket is non-blocking by the
/// time this runs, so a read with nothing in the buffer comes back rather than
/// blocking, and the refusal path runs in the accept loop, where waiting would
/// stop every other caller. What it has to clear is a request head and at most
/// a body, both of which are already capped, and a caller that goes on sending
/// past that is one this is right to stop reading.
///
/// `patience` is how long to wait for bytes that have not arrived yet, and it
/// is the whole of what separates the two callers. The ordinary path has read
/// the request already, so whatever is left came with it and is there to be
/// taken now; waiting would add that wait to every connection this server
/// closes, for nothing. The refusal path answers before the request has
/// necessarily arrived at all, so the bytes it has to clear are usually still
/// in flight, and not waiting for them is not clearing anything.
///
/// It used to wait for nobody, and what that cost was measured. Server full,
/// an honest caller posting a head inside the cap and a body of exactly
/// [`MAX_BODY_BYTES`]: sent in one piece with no gap, twelve of twelve read
/// the whole 503; sent thirty milliseconds after the head, seven of twelve;
/// sent in eight pieces twenty milliseconds apart, none of twelve. Every loss
/// the same, a reset after the response head and none of its body, which
/// reaches a reader as a transport error rather than as the refusal this
/// server meant to give. On a real link it was not intermittent: the refusal
/// is written the moment `accept` returns, a round trip before the caller's
/// body can arrive.
///
/// Waiting was impossible while this ran in the accept loop, where every
/// millisecond of patience is a millisecond no other caller is accepted, at
/// the one moment every caller is being refused. It does not run there any
/// more: see [`refusals`].
/// Returns what it cleared, which is what a test can ask it. Whether the
/// answer survives the close after it depends on the host's own timing and
/// cannot be asked here; how many of the caller's bytes were taken off the
/// socket first is the whole of what this decides, and that is a number.
fn drain(stream: &TcpStream, patience: Duration) -> usize {
    let mut sink = [0u8; DRAIN_CHUNK];
    let mut source = stream;
    let until = Instant::now().checked_add(patience);
    let mut cleared = 0usize;
    while cleared < DRAIN_BYTES {
        match source.read(&mut sink) {
            Ok(0) => break,
            Ok(taken) => cleared = cleared.saturating_add(taken),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // Nothing there yet. With no patience this is the end, which
                // is what every caller but one wants.
                let Some(until) = until else {
                    break;
                };
                if Instant::now() >= until {
                    break;
                }
                thread::sleep(DRAIN_POLL);
            }
            Err(_) => break,
        }
    }
    cleared
}

/// Ends a connection so that the answer just written survives it.
///
/// The write half, which sends the end of the message and puts what is still
/// buffered on its way, and then what the caller sent and nobody read, so that
/// closing has nothing to reset over.
///
/// **The read half is left alone.** Shutting it buys nothing on a connection
/// about to be dropped, and it costs something: from that moment every byte
/// the caller is still sending arrives at a half nothing will take, and the
/// answer to that is a reset. The refusal path writes before the request has
/// necessarily arrived at all, so those bytes are often still on their way
/// when this runs, and this used to shut the door in front of them.
///
/// What is left is the close the drop does, which resets if bytes turn up
/// unread after all. That window is what draining narrows, and how far it
/// narrows is `patience`, which is nothing here: this is the path that has
/// already read its request, so whatever is left came with it. The path that
/// answers before reading one no longer comes through here at all. It waited
/// here, one caller after another, and [`refuse_them`] waits on every refused
/// caller at once instead.
fn hang_up(stream: &TcpStream, patience: Duration) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = drain(stream, patience);
}

/// When a connection accepted at `accepted` is over, given `answering` to say
/// what is written back.
///
/// One moment for the whole connection rather than one for each half, so that
/// a caller cannot spend the asking budget slowly and then start again on the
/// answering one.
fn deadline(accepted: Instant, answering: Duration) -> Instant {
    accepted
        .checked_add(REQUEST_DEADLINE)
        .and_then(|at| at.checked_add(answering))
        .unwrap_or_else(Instant::now)
}

/// What an answer of `bytes` is worth in time, which is how long it takes on
/// the slowest link this server writes for, and never more than
/// [`ANSWER_DEADLINE`].
///
/// Worked out from the length rather than from the writing, so that the number
/// is settled before a byte of it moves and nothing the caller does can add to
/// it. An answer of a few hundred bytes is worth almost nothing and is held to
/// the asking deadline alone; the long pages are worth their length; and past
/// the ceiling nothing is worth any more.
fn answering(bytes: usize) -> Duration {
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    Duration::from_secs(bytes.checked_div(SLOWEST_LINK).unwrap_or(0)).min(ANSWER_DEADLINE)
}

/// A reader and a writer that stop at a fixed moment, however slowly the bytes
/// come or go.
///
/// The socket's own timeouts are per read and per write, so a caller that
/// moves a byte whenever it is about to run out resets them forever and keeps
/// its slot for almost nothing. It works in both directions: dribble the
/// request, or ask properly and then take the answer back a byte at a time.
/// This moment is fixed before either half starts and nothing the caller does
/// moves it. It also hands the socket whatever is left of that budget as its
/// own timeout, so a caller that goes quiet at the last moment cannot buy
/// another timeout's worth of silence on top.
///
/// The reading half checks the moment a byte at a time, which is how the head
/// is read anyway. The writing half cannot: one write of a long answer is one
/// call that comes back when the whole slice has gone, and the timeout under
/// it is reset by every byte that moves, so the moment would only be looked at
/// once. So the socket is asked not to block and the waiting is done here,
/// where the moment is.
#[derive(Debug)]
struct Timed<'a> {
    stream: &'a TcpStream,
    until: Instant,
}

impl Timed<'_> {
    /// What is left of the budget, or nothing when it is spent.
    fn left(&self) -> io::Result<Duration> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        Ok(left)
    }
}

impl io::Read for Timed<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let left = self.left()?;
        let _ = self.stream.set_read_timeout(Some(left.min(READ_TIMEOUT)));
        let mut source = self.stream;
        source.read(out)
    }
}

impl Write for Timed<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Never more than a chunk in one call, so the moment below is looked
        // at once per chunk rather than once per answer.
        //
        // `write_all` hands the whole body down in one slice, and a `write`
        // that takes all of it checks the deadline exactly once, at the start.
        // Whether that is enough then rests on the kernel refusing the bytes,
        // which is not a promise any of them make: one that accepts a large
        // send into its own buffers turns the whole answer into a single call
        // that was inside the budget when it began. Writing less than asked
        // for is what `write` is allowed to do and what `write_all` expects,
        // so this costs nothing and makes the budget hold without depending on
        // how a particular kernel behaves.
        let data = data.get(..data.len().min(WRITE_CHUNK)).unwrap_or(data);
        loop {
            let left = self.left()?;
            // Set as well as polled: a socket that could not be put into
            // non-blocking mode has nothing else to stop it.
            let _ = self.stream.set_write_timeout(Some(left.min(WRITE_TIMEOUT)));
            let mut sink = self.stream;
            match sink.write(data) {
                Err(error) if would_wait(&error) => thread::sleep(WRITE_POLL.min(left)),
                outcome => return outcome,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut sink = self.stream;
        sink.flush()
    }
}

/// Reads one request head.
///
/// `Ok(None)` means a well-formed request this server does not answer.
///
/// # Why this is public
///
/// It is the most exposed parser in the workspace: every byte from every
/// stranger arrives here, before routing and before anything else has looked
/// at them. An audit found it had no fuzz target, and the reason it had none
/// is that it was private, which put every test of it behind a real socket
/// and a real connection and so behind the deadlines, the slot accounting and
/// the answer writer. None of those are the parser.
///
/// Public rather than `pub(crate)` with a wrapper, because a wrapper would be
/// a second entry point that a change to this one need not go through, and
/// the point of the target is that it feeds the bytes the socket feeds. It
/// takes an [`io::Read`], so a test hands it an [`io::Cursor`] and gets to
/// watch what it consumed, which is one of the things the target checks and
/// the socket path cannot show.
///
/// `crates/cairn-http/tests/fuzz_request.rs` is the caller this is for.
pub fn read_request<R: io::Read>(reader: &mut R) -> Result<Option<Request>, u16> {
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
    // A NUL was the one byte refused here, and the two beside it are the
    // delimiters of this protocol. The path is percent decoded, so `%0d%0a`
    // put a whole line ending into it, and a campaign against this reader
    // found `GET /a%0D%0AX-Injected:+1` coming back as a `Request` whose path
    // was `/a\r\nX-Injected:+1`.
    //
    // Nothing downstream can be made to write it out today: `write_response`
    // builds its head from a status, a length, a content type and a compiled
    // in constant, with no request byte in it. Refused all the same, because
    // the rule was already here and was refusing the byte that cannot reach a
    // delimiter while admitting the two that are them. A path with a line
    // ending in it matches no route, so the only thing this changes for an
    // honest caller is a 400 where there used to be a 404.
    if path.contains(['\0', '\r', '\n']) {
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

/// Reads one line of the head, counting every byte it took against the head
/// cap.
///
/// Public alongside [`read_request`], and for the same audit: the two caps it
/// keeps are the only thing standing between a stranger and an unbounded
/// read, and a target that could only reach it through a whole request could
/// not say which of the two refused.
pub fn read_line<R: io::Read>(reader: &mut R, consumed: &mut usize) -> Result<String, u16> {
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
            // A carriage return anywhere but immediately before the line feed
            // is not the end of a line, and it is not part of one either.
            // This dropped one only in that position, so an interior one
            // survived into whatever the line turned into: a campaign against
            // this reader found `host: x\ry` coming back as a host of `x\ry`,
            // and the same for an origin. Both are compared for exact
            // equality by the wallet, so the value was refused a moment
            // later, but a header value carrying a delimiter is a value no
            // caller has a use for and the right place to say so is here.
            if line.contains(&b'\r') {
                return Err(400);
            }
            return String::from_utf8(line).map_err(|_| 400);
        }
        line.push(read);
    }
}

/// Whether a socket said "not now" rather than "no".
fn would_wait(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn write_response<W: Write>(out: &mut W, response: &Response, head_only: bool) -> io::Result<()> {
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

    out.write_all(head.as_bytes())?;
    if !head_only {
        out.write_all(&response.body)?;
    }
    out.flush()
}

/// Sent with every answer.
///
/// The policy allows nothing from anywhere else: no third-party script, no
/// remote font, no analytics. A page about a chain that asks you to trust
/// nobody should not itself call out to four companies to render a heading.
///
/// `cross-origin-resource-policy` is the one that is not about this page. The
/// wallet holds everything about itself behind a secret and lets its own look
/// and script through without one, on the grounds that "the look and the
/// script are the same bytes for anyone who asks". True, and it answers a
/// different question from "does answering tell a stranger anything": a
/// subresource load sends no `Origin`, and the `Host` is the loopback the
/// browser itself wrote, so a page on any site could pull `/wallet.js` off a
/// range of loopback ports and learn that this machine runs a Cairn wallet and
/// on which port. This header is what stops a browser handing the bytes to a
/// document from somewhere else. It costs the explorer nothing: its own page
/// loads its own assets from its own origin, and nothing here ever sent an
/// `access-control-allow-origin`, so no cross-origin fetch worked before it
/// either.
const SECURITY_HEADERS: &str = concat!(
    "content-security-policy: default-src 'none'; script-src 'self'; style-src 'self'; ",
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'\r\n",
    "x-content-type-options: nosniff\r\n",
    "referrer-policy: no-referrer\r\n",
    "cross-origin-opener-policy: same-origin\r\n",
    "cross-origin-resource-policy: same-origin\r\n",
    "permissions-policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()\r\n",
);

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        // The wallet's two security refusals, the only two statuses in the
        // workspace this table did not name, so they went out as
        // `HTTP/1.1 403 Error` and `HTTP/1.1 421 Error`. The wallet's
        // `turned_away` says who reads them: "an operator reading a log should
        // be able to tell a mistyped address from a page trying its luck".
        // Eleven statuses produced across three crates, nine named here, and
        // the two missing were those.
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// What a refusal made while reading a request says happened.
///
/// Every one of them said "malformed request", whatever had gone wrong. A
/// caller cut off at the deadline was told its request was malformed; so was
/// one whose header block was larger than this server takes, and one whose
/// form body was. The status line was right in each case and the sentence
/// under it was about a different failure, which is the one thing a person
/// reading an error has to go on.
fn refusal(status: u16) -> &'static str {
    match status {
        408 => "the request did not arrive in time",
        413 => "the form body is larger than this server takes",
        431 => "the request head is larger than this server takes",
        _ => "malformed request",
    }
}

/// Decodes percent escapes, leaving anything malformed as written.
///
/// A stray percent sign is far more likely to be a person pasting an address
/// than an attack, and turning it into an error would only hide the paste.
///
/// Public for the audit that put a fuzz target on [`read_request`]. "Leaving
/// anything malformed as written" is a claim that this is total: it has no
/// failure case at all, so every byte a stranger can write has to come back
/// as something. That is a property worth a campaign of its own, and a
/// campaign that could only arrive here through [`read_request`] would spend
/// almost all of itself on request lines that are refused before a target is
/// ever decoded.
pub fn percent_decode(text: &str) -> String {
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
    use super::{
        answering, drain, let_go_of_the_done, one_machine, percent_decode, reason, wait_on,
        Request, Slots, Waiting, ANSWER_DEADLINE, DRAIN_BYTES, MAX_CONNECTIONS, MAX_PER_HOST,
        REFUSALS_QUEUED,
    };
    use std::collections::VecDeque;
    use std::fmt::Write as _;
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Every status any program in this workspace sends has a reason phrase of
    /// its own.
    ///
    /// Enumerated from the sources that build responses rather than listed
    /// by hand, since a hand list is where the two missing ones hid: the
    /// wallet's 403 and 421, its only two security refusals, went out as
    /// `Error` because this table was kept beside the statuses this crate
    /// produces and not the ones the crates built on it produce.
    #[test]
    fn every_status_the_workspace_sends_has_its_own_reason() {
        const SOURCES: [(&str, &str); 4] = [
            ("cairn-http", include_str!("http.rs")),
            (
                "cairn-explorer api",
                include_str!("../../cairn-explorer/src/api.rs"),
            ),
            (
                "cairn-explorer assets",
                include_str!("../../cairn-explorer/src/assets.rs"),
            ),
            (
                "cairn-wallet serve",
                include_str!("../../cairn-wallet/src/serve.rs"),
            ),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (_, source) in SOURCES {
            for opening in ["Response::error(", "text(", "status: ", "Err("] {
                for (at, _) in source.match_indices(opening) {
                    let digits: String = source[at + opening.len()..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    if digits.len() == 3 {
                        seen.insert(digits.parse::<u16>().unwrap());
                    }
                }
            }
        }
        assert!(
            seen.len() >= 9,
            "the statuses could not be read out of the sources, so this asserts \
             nothing: {seen:?}"
        );
        for status in &seen {
            assert_ne!(
                reason(*status),
                "Error",
                "status {status} is sent by this workspace and has no reason phrase \
                 of its own: {seen:?}"
            );
        }
    }

    /// Both ends of one loopback connection, the server end non-blocking as
    /// the refusal thread holds it.
    fn a_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let caller = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        (caller, server)
    }

    /// Long enough for bytes written on the loopback to be readable at the
    /// other end. A liveness bound, set far past what it needs.
    fn settle() {
        std::thread::sleep(Duration::from_millis(100));
    }

    /// A refused connection is waited on while the caller may still be
    /// sending, and let go the moment there is nothing left to wait for.
    ///
    /// `cargo mutants` found every line of `Waiting::done` could be changed
    /// with nothing noticing: the refusal tests ask whether a 503 arrived, and
    /// on the loopback it arrives whether or not anybody waited. Asked here of
    /// the function, on a real socket, with no race in it.
    #[test]
    fn a_refused_caller_is_waited_on_while_it_may_still_be_sending() {
        let far = Instant::now() + Duration::from_secs(60);

        // Nothing sent and patience left: still waiting.
        let (caller, server) = a_pair();
        let mut waiting = Waiting {
            stream: server,
            until: far,
            cleared: 0,
        };
        assert!(
            !waiting.done(),
            "nothing arrived yet and there is patience left"
        );

        // Bytes arrive: taken off the socket and counted, and still waiting,
        // because more may follow.
        let mut caller = caller;
        caller.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        settle();
        assert!(!waiting.done(), "bytes taken, and the caller may send more");
        assert_eq!(waiting.cleared, 18, "every byte that arrived was taken");

        // The caller closes: nothing more can come.
        drop(caller);
        settle();
        assert!(
            waiting.done(),
            "a caller that has closed has sent everything"
        );

        // Patience spent with nothing arriving: let go.
        let (_held, server) = a_pair();
        let mut spent = Waiting {
            stream: server,
            until: Instant::now(),
            cleared: 0,
        };
        assert!(spent.done(), "no patience left, so no reason to hold on");

        // A caller that keeps sending past what a request can be: let go.
        let (mut flooding, server) = a_pair();
        let mut flooded = Waiting {
            stream: server,
            until: far,
            cleared: 0,
        };
        flooding.write_all(&vec![b'x'; DRAIN_BYTES + 1]).unwrap();
        settle();
        assert!(
            flooded.done(),
            "past what a request can be, reading on is reading for a stranger"
        );
    }

    /// The thread holding refused connections holds at most so many, and the
    /// sweep lets go of exactly the ones that are done.
    #[test]
    fn the_refused_connections_held_are_bounded_and_swept() {
        // Far enough ahead that no patience runs out while the queue is being
        // built. It used to be the clock, and a runner slow enough to spend
        // `REFUSAL_PATIENCE` opening sixty seven socket pairs swept every one
        // of them for being out of patience: the sweep then let go of sixty
        // four where ten had closed, and the test that reads as being about
        // which connections are done was deciding a race.
        let now = Instant::now()
            .checked_add(Duration::from_secs(3_600))
            .expect("an hour from now");
        let mut waiting: VecDeque<Waiting> = VecDeque::new();
        let mut callers = Vec::new();
        for _ in 0..(REFUSALS_QUEUED + 3) {
            let (caller, server) = a_pair();
            callers.push(caller);
            wait_on(&mut waiting, server, now);
        }
        assert_eq!(
            waiting.len(),
            REFUSALS_QUEUED,
            "the oldest are given up past the ceiling, not held without bound"
        );

        // Some of the callers close, and not half of them. With exactly half,
        // a sweep that let go of the open ones and kept the closed ones gave
        // the same count, and this compared counts: `cargo mutants` turned the
        // sweep around and it stayed green.
        let closing = 10;
        callers.drain(..closing + 3);
        settle();
        let gone = let_go_of_the_done(&mut waiting);
        assert_eq!(
            gone, closing,
            "the connections whose callers closed are let go, and only those"
        );
        assert_eq!(waiting.len(), REFUSALS_QUEUED - closing);
        assert!(
            waiting.iter_mut().all(|each| !each.done()),
            "and what is left is what is still worth waiting on"
        );
    }

    /// A caller whose connection was reset is let go at once, rather than
    /// held until patience runs out.
    ///
    /// A reset is the one answer from a read that is neither bytes, an end,
    /// nor "nothing yet", and the waiting treated it as "nothing yet" if the
    /// guard in front of `WouldBlock` was dropped: `cargo mutants` found no
    /// test produced one. A caller closing while bytes it was sent sit unread
    /// in its own buffer resets rather than closes, which is how one is made
    /// here.
    #[test]
    fn a_reset_caller_is_let_go_at_once() {
        let (caller, server) = a_pair();
        let mut sent = &server;
        let _ = sent.write_all(b"never read");
        settle();
        drop(caller);
        settle();
        let mut reset = Waiting {
            stream: server,
            until: Instant::now() + Duration::from_secs(60),
            cleared: 0,
        };
        assert!(
            reset.done(),
            "a reset connection has nothing more to send and is not waited on"
        );
    }

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

    /// What an answer is worth in time is its length at the slowest link, so a
    /// short one is worth almost nothing and cannot be spun out into a held
    /// slot, and the pages this server really sends are worth their length
    /// rather than the ceiling.
    #[test]
    fn an_answer_is_worth_its_length_and_no_more_than_the_ceiling() {
        assert_eq!(answering(0), Duration::ZERO, "an empty body buys no time");
        assert_eq!(
            answering(500),
            Duration::ZERO,
            "and neither does a short one"
        );
        let seconds = |bytes: usize| answering(bytes).as_secs();
        assert_eq!(
            seconds(54 * 1024),
            13,
            "the largest document compiled in, at four kilobytes a second"
        );
        assert_eq!(seconds(4 * 1024 * 4), 4, "four seconds of the slowest link");
        assert_eq!(
            answering(usize::MAX),
            ANSWER_DEADLINE,
            "and nothing is worth more than the ceiling"
        );
    }

    /// One machine on the open network cannot be the whole flood.
    #[test]
    fn an_address_from_outside_stops_at_its_share() {
        let slots = Arc::new(Slots::default());
        let host = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        let held: Vec<_> = (0..MAX_PER_HOST).filter_map(|_| slots.take(host)).collect();
        assert_eq!(held.len(), MAX_PER_HOST);
        assert!(
            slots.take(host).is_none(),
            "the next one from that address is turned away"
        );
        assert!(
            slots
                .take(Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))))
                .is_some(),
            "while everybody else is still served"
        );
    }

    /// The loopback is the proxy carrying the whole public site, so counting
    /// it per address would cap the site rather than any flood. It still
    /// counts against the ceiling, because it still costs a thread.
    #[test]
    fn the_proxy_on_this_machine_is_not_counted_per_address() {
        let slots = Arc::new(Slots::default());
        let host = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let held: Vec<_> = (0..MAX_CONNECTIONS)
            .filter_map(|_| slots.take(host))
            .collect();
        assert_eq!(
            held.len(),
            MAX_CONNECTIONS,
            "the proxy is one address and every reader of the site"
        );
        assert!(slots.take(host).is_none(), "the ceiling still holds");
        drop(held);
        assert!(
            slots.take(host).is_some(),
            "and the slots come back when the connections do"
        );
    }

    /// And the proxy is still the proxy when it arrives mapped.
    ///
    /// A listener bound to `[::]` reports every IPv4 caller as
    /// `::ffff:a.b.c.d`, which is what `peer_addr` hands this code for the
    /// proxy in front of it. `is_loopback` says no to that, so the exemption
    /// above applied to a shape the deployment never produces and the whole
    /// public site was capped at sixteen readers at a time.
    ///
    /// Held here rather than over a socket. A dual stack listener accepts
    /// IPv4 callers on Linux and refuses them on macOS and Windows, where the
    /// default is `IPV6_V6ONLY`, so a test driven through a socket would pass
    /// for want of a caller on two of the three platforms this is built for.
    /// A test that cannot fail on most of the machines that run it is worse
    /// than the one below.
    #[test]
    fn the_proxy_is_the_proxy_when_it_arrives_mapped() {
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert!(
            !mapped.is_loopback(),
            "this test is about the address that is the loopback and does not say so; if \
             it starts saying so, the code under it can go"
        );
        assert!(one_machine(mapped).is_loopback());

        let slots = Arc::new(Slots::default());
        let held: Vec<_> = (0..MAX_CONNECTIONS)
            .filter_map(|_| slots.take(Some(mapped)))
            .collect();
        assert_eq!(
            held.len(),
            MAX_CONNECTIONS,
            "the proxy was counted as one visitor and the site was capped at \
             {MAX_PER_HOST} readers"
        );
    }

    /// A drain with patience clears what was still on its way.
    ///
    /// The whole of what separates a refusal a caller can read from one it
    /// cannot. A refusal is written the moment a connection is accepted, a
    /// round trip before the caller's body can arrive, so the bytes it has to
    /// clear are usually still in flight; a drain that gives up on the first
    /// empty read clears none of them, and closing over what turns up
    /// afterwards resets the connection and takes the answer with it.
    ///
    /// Held here rather than through the server. Whether the reset takes the
    /// answer depends on the host: the loopback on the machine this was
    /// written on delivers a caller's body fast enough that even the old drain
    /// found it there, and the runner where this race was lost is a different
    /// one. What the server does with the result is argued from this and from
    /// the reset semantics written on `hang_up`; what `drain` does is a number
    /// and is measured.
    #[test]
    fn a_drain_with_patience_clears_what_was_still_on_its_way() {
        use std::net::{Ipv4Addr, TcpListener};

        const LATE: usize = 512;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a free port");
        let at = listener.local_addr().expect("the port it took");
        let sending = std::thread::spawn(move || {
            let mut out = std::net::TcpStream::connect(at).expect("the listener is up");
            std::thread::sleep(Duration::from_millis(60));
            let _ = std::io::Write::write_all(&mut out, &[b'x'; LATE]);
            let _ = std::io::Write::flush(&mut out);
            // Held open, so nothing here is a close being read as an end.
            std::thread::sleep(Duration::from_millis(600));
        });
        let (taken, _) = listener.accept().expect("the connection above");
        taken
            .set_nonblocking(true)
            .expect("a socket that will not block");

        assert_eq!(
            drain(&taken, Duration::ZERO),
            0,
            "nothing has arrived yet, and without patience nothing is what is cleared"
        );
        assert_eq!(
            drain(&taken, Duration::from_millis(500)),
            LATE,
            "the caller's bytes arrived after the refusal was written, which is what \
             every caller on a link with a round trip in it does"
        );

        drop(taken);
        let _ = sending.join();
    }

    /// One machine is one share of the ceiling, arriving either way.
    #[test]
    fn a_caller_does_not_get_two_shares_by_arriving_twice_over() {
        let plain = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 5).to_ipv6_mapped());
        assert_ne!(plain, mapped, "they are different addresses to begin with");

        let slots = Arc::new(Slots::default());
        let mut held = Vec::new();
        for turn in 0..MAX_PER_HOST {
            let host = if turn % 2 == 0 { plain } else { mapped };
            held.push(slots.take(Some(host)).expect("inside the share"));
        }
        assert!(
            slots.take(Some(plain)).is_none(),
            "one machine took {} slots by alternating the way it arrived",
            held.len().saturating_add(1)
        );
        assert!(slots.take(Some(mapped)).is_none(), "either way round");
    }
}
