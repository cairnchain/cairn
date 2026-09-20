//! The request reader, under a generator that does not know what HTTP is.
//!
//! This is the first code in the workspace that touches a byte from a
//! stranger. Before routing, before the explorer or the wallet has seen
//! anything, before any check about what is being asked for: a socket is
//! accepted and the bytes come here. An audit found it had no fuzz target at
//! all, which is how [`read_request`], [`read_line`] and [`percent_decode`]
//! came to be public; each says so where it is defined.
//!
//! Four properties, and each one is something the rest of `cairn-http` and
//! both programs above it assume without saying so:
//!
//! 1. **A refusal is a status.** Any bytes at all produce a request, a
//!    well-formed request this server does not answer, or a status code.
//!    Never a panic, never an abort, never a read that does not end.
//! 2. **A request that comes back has a path.** It starts with a slash and
//!    carries no NUL, so a route match is a match against something shaped
//!    like a path rather than against whatever the caller wrote. It used to
//!    be able to carry a line ending, which is this campaign's one finding;
//!    `a_line_ending_reaches_no_path_and_no_header_value` is the rule now.
//! 3. **A caller cannot buy an unbounded read.** Whatever it sends, no more
//!    than the head cap plus a body it declared and was allowed is consumed,
//!    and no more than the body cap is ever reserved.
//! 4. **Percent decoding is total.** It has no failure case, which is a
//!    claim that every byte a person can paste comes back as something.
//!
//! Two arms, counted apart. One assembles a request out of the generator's
//! own vocabulary, which is what it takes to reach past the request line at
//! all: uniformly random bytes are refused at the first space. The other
//! bends a well-formed head. A single counter over both would pass with
//! either arm dead, which is the defect the audit found in the campaigns that
//! existed, so there are two counters and two guards.
//!
//! Deterministic. `CAIRN_FUZZ_SEED`, `CAIRN_FUZZ_CASES` and
//! `CAIRN_FUZZ_SECONDS` steer it; with none of them set it runs the same
//! small campaign on every machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fmt::Write as _;
use std::io::{self, Cursor, Read};

use cairn_fuzz::{mutate, Arms, Built, Campaign, Rng};
use cairn_http::http::{
    percent_decode, read_line, read_request, Request, MAX_BODY_BYTES, MAX_HEAD_BYTES,
    MAX_LINE_BYTES,
};

/// The statuses this server knows how to put a sentence under.
///
/// `reason` and `refusal` in `http.rs` name exactly these; anything else
/// reaches a person as the bare word "Error" with no sentence, which is the
/// complaint `refusal`'s own doc comment records having fixed. A reader that
/// invented a fifth status would put it back.
const REFUSALS: [u16; 4] = [400, 408, 413, 431];

/// Feeds one byte string to the reader and holds everything against it.
///
/// Returns whether a request came back, so a campaign can say how far each of
/// its arms got.
fn holds(bytes: &[u8], case: usize) -> bool {
    let mut cursor = Cursor::new(bytes);
    let answer = read_request(&mut cursor);
    let consumed = usize::try_from(cursor.position()).unwrap_or(usize::MAX);

    // What a caller can make this server read before it has decided anything
    // about them. The head is capped line by line and in total; the body is
    // read only for a POST and only up to the body cap. A reader that had
    // stopped counting would show up here as a case that swallowed the whole
    // input, and the input a long campaign builds is longer than this sum.
    assert!(
        consumed <= MAX_HEAD_BYTES.saturating_add(MAX_BODY_BYTES),
        "the reader consumed {consumed} bytes of a {} byte input, past the head \
         cap of {MAX_HEAD_BYTES} and a body of {MAX_BODY_BYTES} (case {case})",
        bytes.len()
    );

    match answer {
        Err(status) => {
            assert!(
                REFUSALS.contains(&status),
                "the reader refused with {status}, which has no sentence under it \
                 (case {case})"
            );
            false
        }
        // A well-formed request this server does not answer. Nothing was
        // decided about a path, so there is nothing here to hold.
        Ok(None) => false,
        Ok(Some(request)) => {
            holds_about_a_request(&request, consumed, case);
            true
        }
    }
}

/// What a `Request` handed to a router is allowed to be.
fn holds_about_a_request(request: &Request, consumed: usize, case: usize) {
    // Every route in the explorer and the wallet is a prefix match against a
    // path that begins with a slash. A path that did not would be a target
    // the caller chose the shape of: `http://elsewhere/api/send` reaching the
    // wallet's spend route, with the host part read as part of the path.
    assert!(
        request.path.starts_with('/'),
        "a request came back with the path {:?} (case {case})",
        request.path
    );

    // Percent decoding can put any byte into a path, NUL included. Nothing
    // downstream here opens a file by name, but a string that ends early for
    // one reader and not another is the shape of a check passed by one
    // spelling and acted on as another.
    assert!(
        !request.path.contains('\0'),
        "a request came back with a NUL in its path (case {case})"
    );

    // A body is a POST's alone and is capped. A GET carrying one would be a
    // read this server did without being asked, paid for out of the same
    // deadline.
    assert!(
        request.post || request.body.is_empty(),
        "a request that is not a POST came back holding a body of {} bytes \
         (case {case})",
        request.body.len()
    );
    assert!(
        request.body.len() <= MAX_BODY_BYTES,
        "a body of {} bytes came back, past the cap of {MAX_BODY_BYTES} \
         (case {case})",
        request.body.len()
    );

    // A body is read past the head, so the two caps add. Stated as a second
    // assertion rather than folded into the one above because this one can
    // only fail on the POST path, and that is the path with an allocation in
    // it.
    assert!(
        consumed <= MAX_HEAD_BYTES.saturating_add(request.body.len()),
        "the reader consumed {consumed} bytes for a head and a body of {} \
         (case {case})",
        request.body.len()
    );

    // No line ending in anything that was read as a line. `read_line` stops
    // at a line feed, so none of these three can hold one, and that is what
    // makes it worth asserting: it is the property the frame gives for free
    // and the one that would go if somebody made the head reader take a
    // continuation line, which is a thing HTTP once had.
    //
    // The path is not in this list for a different reason. It is
    // percent-decoded, so the escapes could say anything the frame does not,
    // and a line ending is what that used to buy: this campaign's one
    // finding. It is refused now, and
    // `a_line_ending_reaches_no_path_and_no_header_value` is the rule.
    //
    // This named `a_line_ending_reaches_a_path_and_a_header_value`, which is
    // the same name with the verdict reversed and does not exist. Line 20 of
    // this file was corrected when the refusal went in and this was not, so
    // one file said the path both does and does not carry a line ending.
    //
    // The body is not in the list either. It is read as bytes against a
    // declared length rather than line by line, so a form field holding a
    // newline is a form field holding a newline.
    for (what, field) in [
        ("query", &request.query),
        ("host", &request.host),
        ("origin", &request.origin),
    ] {
        assert!(
            !field.contains('\n'),
            "the {what} came back holding a line feed (case {case})"
        );
    }
}

/// A request head assembled out of a vocabulary rather than out of bytes.
///
/// The fresh arm has to be built rather than drawn, and the reason is
/// measurable: a request is refused at `split(' ')` unless it holds two
/// spaces and a version, so uniformly random bytes reach the path decoder
/// essentially never. `the_fresh_arm_is_worth_running` below measures both
/// and is the assertion that keeps this paragraph honest.
fn a_request(rng: &mut Rng) -> Vec<u8> {
    let mut head = Vec::new();

    // Weighted towards what this server answers rather than spread evenly
    // over what a client can write. An even spread is a generator that spends
    // three quarters of its cases on the two comparisons at the top of the
    // function: `the_fresh_arm_is_worth_running` measures what came of that,
    // and the first version of this file, with the methods drawn evenly, read
    // 407 requests in twenty thousand.
    let method = if rng.chance(4) {
        rng.pick(&["PUT", "PATCH", "DELETE", "OPTIONS", "get", "GETX", ""])
            .copied()
            .unwrap_or("GET")
    } else {
        rng.pick(&["GET", "HEAD", "POST"]).copied().unwrap_or("GET")
    };
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(&a_target(rng));
    head.push(b' ');
    let version = if rng.chance(4) {
        rng.pick(&["HTTP/1.0", "HTTP/1.", "HTTP/2", "SPDY/3", "", "HTTP/1.1 "])
            .copied()
            .unwrap_or("HTTP/1.1")
    } else {
        "HTTP/1.1"
    };
    head.extend_from_slice(version.as_bytes());
    end_a_line(rng, &mut head);

    let mut declared: Option<usize> = None;
    for _ in 0..rng.between(0, 6) {
        let name = rng
            .pick(&[
                "host",
                "Host",
                "HOST",
                "origin",
                "Origin",
                "content-length",
                "Content-Length",
                "x-pad",
                "",
            ])
            .copied()
            .unwrap_or("host");
        head.extend_from_slice(name.as_bytes());
        // Not always a colon, because a line without one is dropped rather
        // than refused and that branch is reachable from a real client.
        if rng.chance(8) {
            head.push(b';');
        } else {
            head.push(b':');
        }
        head.push(b' ');
        if name.eq_ignore_ascii_case("content-length") {
            let length = a_declared_length(rng);
            head.extend_from_slice(length.to_string().as_bytes());
            declared = Some(length);
        } else if rng.chance(24) {
            // A value past the line cap, so the cheaper of the two head
            // refusals is reached by the campaign rather than only by the
            // tests written to reach it. Without this the 431 branch was
            // never taken in twenty thousand cases, which was measured and is
            // why the padding is here.
            let over = MAX_LINE_BYTES.saturating_add(rng.between(0, 64));
            head.extend_from_slice(&vec![b'p'; over]);
        } else {
            let filler = rng.between(0, 24);
            head.extend_from_slice(&rng.plausible_bytes(filler));
        }
        end_a_line(rng, &mut head);
    }
    end_a_line(rng, &mut head);

    // A body as long as the header said, most of the time, so that both the
    // branch where the read is satisfied and the branch where it runs out are
    // reached.
    //
    // Clamped before anything is drawn. A header may declare `usize::MAX` and
    // is refused for it at 413 without a byte being read, but the generator
    // has to survive writing the case: the first version of this asked for a
    // vector of that length and aborted the test process, which is the test
    // reproducing the defect it exists to deny rather than finding one.
    let sending = match declared {
        Some(length) => {
            let honest = length.min(2usize.saturating_mul(MAX_BODY_BYTES));
            if rng.chance(8) {
                honest.saturating_sub(rng.between(0, 4))
            } else {
                honest
            }
        }
        None => rng.between(0, 8),
    };
    head.extend_from_slice(&rng.plausible_bytes(sending));
    head
}

/// A target, mostly shaped like one this site actually serves.
fn a_target(rng: &mut Rng) -> Vec<u8> {
    let mut target = Vec::new();
    if !rng.chance(16) {
        target.push(b'/');
    }
    let shape = rng
        .pick(&[
            "api/status",
            "api/tx/",
            "api/note/",
            "api/address/",
            "api/blocks",
            "send",
            "",
            "..",
            "a%2fb",
        ])
        .copied()
        .unwrap_or("");
    target.extend_from_slice(shape.as_bytes());
    for _ in 0..rng.between(0, 3) {
        match rng.below(4) {
            // A percent escape written out, which is the branch a pasted
            // address takes.
            0 => {
                target.push(b'%');
                let digits = rng.between(0, 2);
                target.extend_from_slice(&rng.plausible_bytes(digits));
            }
            1 => target.extend_from_slice(b"%00"),
            2 => target.push(b'?'),
            _ => {
                let filler = rng.between(0, 16);
                target.extend_from_slice(&rng.plausible_bytes(filler));
            }
        }
    }
    target
}

/// A content-length worth writing: around the cap, around zero, and absurd.
fn a_declared_length(rng: &mut Rng) -> usize {
    match rng.below(6) {
        0 => 0,
        1 => rng.between(1, 64),
        2 => MAX_BODY_BYTES,
        3 => MAX_BODY_BYTES.saturating_add(1),
        4 => usize::MAX,
        _ => rng.between(0, 2 * MAX_BODY_BYTES),
    }
}

/// Ends a line the way a client might, including the ways it should not.
fn end_a_line(rng: &mut Rng, into: &mut Vec<u8>) {
    match rng.below(8) {
        0 => into.push(b'\n'),
        1 => into.extend_from_slice(b"\r\r\n"),
        // A line with no ending at all, which is the input that ends mid head.
        2 if rng.chance(4) => {}
        _ => into.extend_from_slice(b"\r\n"),
    }
}

/// Heads the bending arm starts from, one per branch worth arriving inside.
fn corpus() -> Vec<Vec<u8>> {
    [
        "GET /api/status HTTP/1.1\r\nhost: cairn.example\r\n\r\n",
        "HEAD / HTTP/1.0\r\n\r\n",
        "GET /api/tx/0f1e2d3c?limit=5 HTTP/1.1\r\nhost: x\r\norigin: https://x\r\n\r\n",
        "POST /send HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 21\r\n\r\nto=abc&amount=1.5&f=0",
        "POST /send HTTP/1.1\r\ncontent-length: 0\r\n\r\n",
        "PATCH /api/status HTTP/1.1\r\n\r\n",
        "GET /a%20b%2Fc%ZZ%0 HTTP/1.1\r\n\r\n",
        "GET / HTTP/1.1\nhost:x\n\n",
    ]
    .iter()
    .map(|text| text.as_bytes().to_vec())
    .collect()
}

#[test]
fn any_bytes_at_all_give_a_request_or_a_status() {
    let campaign = Campaign::named("http: request heads");
    let corpus = corpus();
    let mut arms = Arms::default();

    let ran = campaign.run(20_000, |case, rng| {
        let (built, bytes) = if rng.bool() {
            (Built::FromNothing, a_request(rng))
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            (Built::ByBending, mutate(rng, &seed, &corpus))
        };
        arms.saw(built, holds(&bytes, case));
    });

    arms.report("http: request heads");
    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    // Two guards and not one. Either arm reaching nothing is a campaign that
    // tests refusal and calls it coverage, and the single guard that used to
    // stand in this position elsewhere in the workspace hid exactly that.
    assert!(
        arms.from_nothing.accepted > 0,
        "not one assembled request was read: {:?}",
        arms.from_nothing
    );
    assert!(
        arms.by_bending.accepted > 0,
        "not one bent head was read: {:?}",
        arms.by_bending
    );
}

/// The same inputs against the reader, checking it reached what it claims to.
///
/// The campaign above asserts things about a `Request`, and every one of
/// those assertions is satisfied by never building one. This counts the
/// branches instead, and fails if a branch stops being reached rather than
/// if it misbehaves. Without it the campaign above could go green for ever
/// on a reader that answered 400 to everything.
#[test]
fn the_campaign_reaches_every_branch_it_makes_a_claim_about() {
    let campaign = Campaign::named("http: branches reached");
    let corpus = corpus();
    let mut got = 0usize;
    let mut refused = [0usize; 4];
    let mut unanswered = 0usize;
    let mut with_a_body = 0usize;
    let mut with_an_escape = 0usize;

    let ran = campaign.run(20_000, |_, rng| {
        let bytes = if rng.bool() {
            a_request(rng)
        } else {
            let seed = rng.pick(&corpus).cloned().unwrap_or_default();
            mutate(rng, &seed, &corpus)
        };
        match read_request(&mut Cursor::new(&bytes)) {
            Ok(Some(request)) => {
                got += 1;
                if !request.body.is_empty() {
                    with_a_body += 1;
                }
                // A path that came back shorter than it went in is one the
                // decoder actually acted on.
                if request.path.len() < bytes.len() && request.path.contains('%') {
                    with_an_escape += 1;
                }
            }
            Ok(None) => unanswered += 1,
            Err(status) => {
                if let Some(at) = REFUSALS.iter().position(|known| *known == status) {
                    refused[at] += 1;
                }
            }
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    eprintln!(
        "http: {got} read, {unanswered} unanswered methods, {with_a_body} with a body, \
         {with_an_escape} with a percent sign left in the path, refusals {refused:?}"
    );
    assert!(got > 0, "no request was ever read");
    assert!(
        unanswered > 0,
        "the unanswered-method branch was never taken"
    );
    assert!(with_a_body > 0, "the body read was never reached");
    // 400, 413 and 431 are the three the campaign produces on its own. 408
    // needs a reader that errors rather than bytes that are wrong, and is
    // reached by `a_source_that_fails_is_a_timeout_and_not_a_malformed_request`
    // instead.
    assert!(refused[0] > 0, "nothing was ever refused as malformed");
    assert!(refused[2] > 0, "the body cap was never reached");
    assert!(refused[3] > 0, "the head cap was never reached");
}

/// **A line ending reaches no path and no header value.**
///
/// The one thing this campaign found, in two halves that turned up a day
/// apart: the header half at case 1477 of the short run, the path half at
/// case 97935 of a ten second one, both on the default seed.
///
/// The header half. `read_line` reads to a line feed and dropped a carriage
/// return only where it sat immediately before one, so a caller writing
/// `origin: http://a\rhttp://b` got both halves back in a single value. RFC
/// 9110 has no reading of that: a field value may not hold a carriage return
/// at all.
///
/// The path half, which is the larger of the two. The path is
/// percent-decoded, so it holds whatever the escapes say, and `%0d%0a` says
/// a line ending. `GET /a%0D%0AX-Injected:+1 HTTP/1.1` came back with the
/// path `/a\r\nX-Injected:+1`. The reader did check for one byte here, and
/// that is what made it worth writing down rather than shrugging at: it
/// refused `%00` and took `%0d%0a`, which is a rule that stops one byte from
/// reaching a string and lets through the two that are the string's own
/// delimiters.
///
/// Neither was a hole, and the reason is worth keeping rather than leaving
/// to be rediscovered. The three fields are compared for equality and
/// nothing else. `cairn-wallet`'s `turned_away` refuses an origin that is not
/// exactly the wallet's own and a host that is not exactly the loopback it
/// printed, so a value with a line ending in it failed both comparisons and
/// the request was turned away. A path with one in it matches no route in
/// either program and was a 404. And nothing anywhere writes any of the three
/// back into a response header, which is the one thing that would have turned
/// this into response splitting: `write_response` builds its head out of a
/// status, a length, a content type and this crate's compiled in security
/// headers, and not one byte of it comes from the request.
///
/// Refused all the same. Not being reachable today is a fact about today, and
/// the rule that admitted it was already refusing the one byte that cannot
/// reach a delimiter. What it costs an honest caller is a 400 where there
/// used to be a 404, which is the same outcome sooner and in better words.
#[test]
fn a_line_ending_reaches_no_path_and_no_header_value() {
    let head = "GET /a\rb HTTP/1.1\r\norigin: http://a\rhttp://b\r\nhost: x\ry\r\n\r\n";
    assert_eq!(
        read_request(&mut Cursor::new(head.as_bytes())),
        Err(400),
        "a carriage return inside a head line is refused"
    );

    // Through an escape, which is the half that reaches a whole line ending
    // and not only one byte of one.
    let escaped = "GET /a%0D%0AX-Injected:+1 HTTP/1.1\r\n\r\n";
    assert_eq!(
        read_request(&mut Cursor::new(escaped.as_bytes())),
        Err(400),
        "a line ending written as an escape is refused in a path"
    );

    // And the byte that was always refused, so the rule is on the record
    // beside the two it now covers.
    assert_eq!(
        read_request(&mut Cursor::new(b"GET /a%00b HTTP/1.1\r\n\r\n".as_slice())),
        Err(400),
        "a NUL written as an escape is refused"
    );

    // The ordinary case, so this cannot pass by refusing everything.
    let plain = read_request(&mut Cursor::new(
        b"GET /api/status HTTP/1.1\r\nhost: cairn\r\n\r\n".as_slice(),
    ))
    .expect("a well formed head")
    .expect("GET is answered");
    assert_eq!(plain.path, "/api/status");
    assert_eq!(plain.host, "cairn");
}

/// A caller that never stops writing is cut off by the cap, not by memory.
///
/// The bound the campaign above asserts is only worth something if something
/// can reach it, and nothing a generator writes is infinite. This is that
/// reader: it answers every read with a byte, for ever.
#[test]
fn a_head_that_never_ends_is_cut_off_at_the_cap() {
    struct Endless;
    impl Read for Endless {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            for slot in out.iter_mut() {
                *slot = b'x';
            }
            Ok(out.len())
        }
    }

    let campaign = Campaign::named("http: an endless head");
    let ran = campaign.run(64, |case, _| {
        let mut counted = Counting {
            inner: Endless,
            read: 0,
        };
        assert_eq!(
            read_request(&mut counted),
            Err(431),
            "an endless head was not cut off (case {case})"
        );
        assert!(
            counted.read <= MAX_HEAD_BYTES,
            "{} bytes were read off a caller that never stops (case {case})",
            counted.read
        );
    });
    assert!(ran.cases >= 1, "the campaign ran {} cases", ran.cases);
}

/// A reader that gives out and one that gives out mid body.
///
/// 408 is the status for a read that failed, and nothing a byte string can
/// say produces one: it needs the source itself to break, which on the real
/// path is the deadline in `Timed`. This is the only thing in the file that
/// reaches that branch.
#[test]
fn a_source_that_fails_is_a_timeout_and_not_a_malformed_request() {
    struct Failing {
        good: usize,
        head: Vec<u8>,
    }
    impl Read for Failing {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.good == 0 {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            let taking = out.len().min(1).min(self.head.len());
            if taking == 0 {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            out[..taking].copy_from_slice(&self.head[..taking]);
            self.head.drain(..taking);
            self.good -= 1;
            Ok(taking)
        }
    }

    let campaign = Campaign::named("http: a source that fails");
    let mut timed_out = 0usize;
    let ran = campaign.run(2_000, |case, rng| {
        let head = b"POST /send HTTP/1.1\r\ncontent-length: 12\r\n\r\nto=abc&amount".to_vec();
        let mut source = Failing {
            good: rng.between(0, head.len().saturating_add(4)),
            head,
        };
        let answer = read_request(&mut source);
        assert!(
            matches!(answer, Err(400 | 408) | Ok(Some(_))),
            "a source that gave out answered {answer:?} (case {case})"
        );
        if answer == Err(408) {
            timed_out += 1;
        }
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);
    // A source that fails while a line is being read is a timeout. One that
    // fails during the body read is a 400, because `read_exact` cannot say
    // which of the two it was. Both are reached; only the first is this
    // test's subject.
    assert!(
        timed_out > 0,
        "the timeout branch was never reached, so the assertion above is about \
         nothing"
    );
}

/// A declared body past the cap costs a status, never the memory.
///
/// The distinction this turns on is the same one `cairn-primitives`'s codec
/// campaign makes about a sequence count: a reader that checked the number
/// before reserving answers 413 at once, and one that found out by reading
/// would have taken the bytes first. Written as a separate campaign because
/// nothing assembled at random declares four gigabytes often enough to say it
/// was tested.
#[test]
fn a_body_larger_than_the_cap_is_refused_where_the_length_is_read() {
    let campaign = Campaign::named("http: a body past the cap");

    let ran = campaign.run(4_000, |case, rng| {
        let declared = match rng.below(4) {
            0 => MAX_BODY_BYTES.saturating_add(1),
            1 => usize::MAX,
            2 => MAX_BODY_BYTES.saturating_add(rng.between(1, 1 << 20)),
            _ => usize::try_from(u64::MAX).unwrap_or(usize::MAX),
        };
        let head = format!("POST /send HTTP/1.1\r\ncontent-length: {declared}\r\n\r\n");
        // No body at all behind the header. A reader that reserved for the
        // declared length before looking at it would ask this process for it.
        assert_eq!(
            read_request(&mut Cursor::new(head.as_bytes())),
            Err(413),
            "a declared body of {declared} was not refused where it was read \
             (case {case})"
        );
    });

    assert!(ran.cases >= 100, "the campaign ran {} cases", ran.cases);

    // And the boundary itself, pinned rather than sampled.
    let at = format!("POST /send HTTP/1.1\r\ncontent-length: {MAX_BODY_BYTES}\r\n\r\n");
    assert_eq!(
        read_request(&mut Cursor::new(at.as_bytes())),
        Err(400),
        "at the cap the length is allowed and the body is simply not there"
    );
}

/// What `read_line` counts, which is what makes the head cap a cap.
#[test]
fn a_line_that_comes_back_was_paid_for_byte_by_byte() {
    let campaign = Campaign::named("http: lines");
    let mut lines = 0usize;
    let mut capped = 0usize;

    let ran = campaign.run(20_000, |case, rng| {
        let bytes = if rng.bool() {
            let len = rng.between(0, 300);
            rng.plausible_bytes(len)
        } else {
            let front = rng.between(0, 60);
            let mut text = rng.plausible_bytes(front);
            text.extend_from_slice(b"\r\n");
            let back = rng.between(0, 60);
            text.extend_from_slice(&rng.plausible_bytes(back));
            text
        };
        let mut cursor = Cursor::new(&bytes);
        let mut consumed = rng.between(0, MAX_HEAD_BYTES);
        let before = consumed;

        match read_line(&mut cursor, &mut consumed) {
            Ok(line) => {
                lines += 1;
                assert!(
                    line.len() < MAX_LINE_BYTES,
                    "a line of {} bytes came back (case {case})",
                    line.len()
                );
                // One for the newline, two when a carriage return was
                // dropped. A reader whose count and whose output drifted
                // apart is a head cap that stops counting part of the head,
                // which is how a cap becomes decoration.
                let paid = consumed.saturating_sub(before);
                assert!(
                    paid == line.len().saturating_add(1) || paid == line.len().saturating_add(2),
                    "a line of {} bytes cost {paid} against the head cap (case {case})",
                    line.len()
                );
            }
            Err(status) => {
                assert!(REFUSALS.contains(&status));
                if status == 431 {
                    capped += 1;
                }
            }
        }
        assert!(
            consumed <= MAX_HEAD_BYTES,
            "the head count reached {consumed} (case {case})"
        );
        assert!(
            consumed >= before,
            "the head count went backwards (case {case})"
        );
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(lines > 0, "no line was ever read");
    assert!(capped > 0, "the head cap was never what refused a line");
}

/// Percent decoding has no failure case, which is a claim worth a campaign.
#[test]
fn percent_decoding_answers_for_every_string_there_is() {
    let campaign = Campaign::named("http: percent decoding");
    let mut shortened = 0usize;
    let mut unchanged = 0usize;

    let ran = campaign.run(20_000, |case, rng| {
        // Built from bytes and then made into a string, so the input covers
        // what a URL can carry rather than what an ASCII generator writes.
        let len = rng.between(0, 96);
        let raw = if rng.bool() {
            rng.plausible_bytes(len)
        } else {
            rng.bytes(len)
        };
        let text = String::from_utf8_lossy(&raw).into_owned();
        let decoded = percent_decode(&text);

        if !text.contains('%') {
            // Nothing to decode, so nothing may change. A decoder that
            // rewrote a string with no escape in it would be changing an
            // address somebody pasted correctly.
            assert_eq!(
                decoded, text,
                "a text with no percent sign in it came back changed (case {case})"
            );
            unchanged += 1;
        } else if decoded.len() < text.len() {
            shortened += 1;
        }
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
    assert!(unchanged > 0, "no input without an escape was ever tried");
    assert!(
        shortened > 0,
        "no escape was ever decoded, so the campaign only tested the copy path"
    );
}

/// Every byte comes back through an escape, which is the property a pasted
/// identifier depends on.
#[test]
fn any_byte_written_as_an_escape_comes_back_as_itself() {
    let campaign = Campaign::named("http: escapes round trip");

    let ran = campaign.run(20_000, |case, rng| {
        let len = rng.between(0, 64);
        let raw = rng.bytes(len);
        let mut escaped = String::new();
        for byte in &raw {
            let _ = write!(escaped, "%{byte:02x}");
        }
        let decoded = percent_decode(&escaped);
        // Lossy, because a path is a `String` and the bytes are arbitrary.
        // What is being held is that the decoder produced exactly those bytes
        // and let the string type decide the rest, rather than losing or
        // inventing one of its own.
        assert_eq!(
            decoded,
            String::from_utf8_lossy(&raw),
            "escaped bytes did not come back (case {case})"
        );
    });

    assert!(ran.cases >= 1_000, "the campaign ran {} cases", ran.cases);
}

/// The measurement behind the fresh arm being assembled rather than drawn.
///
/// Kept because a campaign is only worth what its generator reaches, and
/// because the claim in `a_request`'s doc comment is the kind that stops
/// being true quietly. If somebody replaces the assembler with `rng.bytes`,
/// every other test in this file still passes and this one does not.
#[test]
fn the_fresh_arm_is_worth_running() {
    let mut rng = Rng::new(7);
    let mut assembled = 0usize;
    let mut drawn = 0usize;

    for _ in 0..20_000 {
        if matches!(
            read_request(&mut Cursor::new(a_request(&mut rng))),
            Ok(Some(_))
        ) {
            assembled += 1;
        }
        let len = rng.between(0, 200);
        if matches!(read_request(&mut Cursor::new(rng.bytes(len))), Ok(Some(_))) {
            drawn += 1;
        }
    }

    eprintln!("http: {assembled} assembled requests read, {drawn} drawn ones");
    // About four per cent of what the assembler writes is read, against
    // nothing at all from twenty thousand drawn byte strings. The floor is
    // set well below the measurement rather than at it, because the number
    // moves with the vocabulary and with anything that changes how many draws
    // the assembler takes, and a test that has to be retuned on every change
    // is a test people delete.
    assert!(
        assembled > 400,
        "only {assembled} of 20000 assembled requests were read, which is not a \
         generator that reaches the reader"
    );
    assert!(
        drawn.saturating_mul(100) < assembled,
        "{drawn} drawn byte strings were read against {assembled} assembled ones, \
         so the assembler is no longer buying anything"
    );
}

/// Wraps a reader and counts what came off it.
struct Counting<R> {
    inner: R,
    read: usize,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let took = self.inner.read(out)?;
        self.read = self.read.saturating_add(took);
        Ok(took)
    }
}

/// The header names every method this server answers.
///
/// A module header on an HTTP server is read for one thing: what a stranger
/// can reach. This one said "answers GET and HEAD, reads no request body" from
/// three minutes before POST landed until an enumeration of every checkable
/// sentence in the repository turned it up, and the method it left out is the
/// one that spends money, since the wallet's send form is a POST.
///
/// So the sentence is held against the code rather than against whoever
/// remembers. The methods are read out of the `match` that decides them, and
/// each has to appear in the header. A new one is then a decision somebody
/// writes down, not one the header quietly stops describing.
#[test]
fn the_header_names_every_method_this_answers() {
    const SOURCE: &str = include_str!("../src/http.rs");

    // The sentence that enumerates them, and not the header at large. The
    // first version of this asked whether each method appeared anywhere in
    // the header; the paragraph below the summary mentions POST twice, so
    // deleting POST from the enumerating sentence left it green. That is the
    // same shape as the defect found in the specification table this morning,
    // presence asked as though it were the claim, and mutating in both
    // directions is what showed it.
    let header: String = SOURCE
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .map(|line| line.trim_start_matches("//!").trim())
        .collect::<Vec<_>>()
        .join(" ");
    let (_, rest) = header
        .split_once("It answers")
        .expect("the header opens by saying what this answers");
    let says = rest
        .split_once(", and serves")
        .expect("the enumerating sentence ends where the filesystem claim begins")
        .0;

    // The arms of the match that turns a method into what to do with it. Read
    // out of the source so the list cannot be kept by hand either.
    let answered: Vec<&str> = SOURCE
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix('"')?;
            let (method, tail) = rest.split_once('"')?;
            tail.trim_start().starts_with("=> (").then_some(method)
        })
        .collect();

    assert!(
        answered.len() >= 3,
        "the methods could not be read out of the source, so this test is \
         asserting nothing: {answered:?}"
    );
    for method in &answered {
        assert!(
            says.contains(method),
            "this server answers {method} and its header does not say so. The \
             header is what somebody reads to know what a stranger can reach: \
             {answered:?}"
        );
    }
}
