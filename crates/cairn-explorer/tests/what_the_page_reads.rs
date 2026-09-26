//! What the API says, held against what the page shows.
//!
//! The page is a script the explorer compiles in, and nothing in the suite ran
//! it: `site.rs` holds the translation files against the keys it asks for, and
//! the routes are held by driving them, and the join between the two, which
//! fields an answer carries and which of them the page reads, was held by
//! nothing. An audit of the front end found the page reading six of the twelve
//! states its node reports, a "Show more" link that showed the same page again,
//! and three pages about somebody's money leaving out the sentence that says
//! how much of the chain the figure is about.
//!
//! These read `api.rs`, `cairn.js` and the rest as text, the way `site.rs`
//! does, because there is no browser here. What each one holds is a join: that
//! a field the API writes is one a view reads, or that a view does what a
//! route needs it to.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

const API: &str = include_str!("../src/api.rs");
const SCRIPT: &str = include_str!("../../../web/cairn.js");
const STYLE: &str = include_str!("../../../web/cairn.css");
const PAGE: &str = include_str!("../../../web/index.html");
const EN: &str = include_str!("../../../web/i18n/en.json");
const FR: &str = include_str!("../../../web/i18n/fr.json");

/// The body of a Rust `fn name(` in api.rs, up to the first `\n}\n`.
fn rust_fn(name: &str) -> &'static str {
    let opening = format!("\nfn {name}(");
    let at = API
        .find(&opening)
        .unwrap_or_else(|| panic!("{name} is written in api.rs"));
    API[at..].split_once("\n}\n").unwrap().0
}

/// The body of a JavaScript `function name(` in cairn.js, up to `\n}\n`.
fn js_fn(name: &str) -> &'static str {
    let opening = format!("function {name}(");
    let at = SCRIPT
        .find(&opening)
        .unwrap_or_else(|| panic!("{name} is written in cairn.js"));
    SCRIPT[at..].split_once("\n}\n").unwrap().0
}

/// The line of the route table that sends `pattern` somewhere.
fn route(pattern: &str) -> &'static str {
    let routes = SCRIPT.split_once("const routes = [").unwrap().1;
    let routes = routes.split_once("];").unwrap().0;
    routes
        .lines()
        .find(|line| line.contains(pattern))
        .unwrap_or_else(|| panic!("a route for {pattern}"))
}

/// Every object the API writes under `node` in `/api/status`: the names
/// `node_object` and the helpers it calls open with `json.key("...")`.
fn node_states() -> Vec<String> {
    let mut names = Vec::new();
    for body in [
        rust_fn("node_object"),
        rust_fn("clock_field"),
        rust_fn("unweighable_field"),
        rust_fn("filling_field"),
        rust_fn("unanswered_field"),
    ] {
        let mut from = 0usize;
        while let Some(found) = body[from..].find("json.key(\"") {
            let start = from + found + "json.key(\"".len();
            let end = start + body[start..].find('"').unwrap();
            let name = body[start..end].to_owned();
            if !names.contains(&name) {
                names.push(name);
            }
            from = end;
        }
    }
    names
}

/// States the node reports that are for whoever runs the site and not for
/// whoever reads it.
///
/// Nobody being able to connect to this node in is the one: it still dials
/// out, still follows the chain, and every figure on the page is as right as
/// it was. `/api/status` carries it for the operator, who has nothing else to
/// read it from; a visitor has nothing to do about it.
const FOR_THE_OPERATOR: [&str; 1] = ["unanswered"];

/// **Every state the node reports about itself is one the page can say.**
///
/// `/api/status` carries `node.unwritten`, `node.unread`, `node.unjudged`,
/// `node.unweighable`, `node.filling` and `node.clockBehind`, and `trouble()`
/// is the one function that turns the answer into the sentence above the
/// numbers. It read none of the six, so a node whose disk had filled and which
/// had switched itself off was shown under "not connected to anybody ... it
/// will not learn about a new block until somebody reaches it again", which is
/// false, and the other five looked healthy. The API's own tests held that the
/// fields were served; nothing held that anything read them.
#[test]
fn every_state_the_node_reports_is_one_the_page_can_say() {
    let states = node_states();
    assert!(
        states.len() >= 9,
        "the node reports at least nine states, found {states:?}"
    );
    let trouble = js_fn("trouble");
    let unsaid: Vec<&String> = states
        .iter()
        .filter(|state| !FOR_THE_OPERATOR.contains(&state.as_str()))
        .filter(|state| !trouble.contains(&format!("node.{state}")))
        .collect();
    assert!(
        unsaid.is_empty(),
        "the API reports {unsaid:?} under `node` and trouble() never reads them, so a \
         node in any of those states looks healthy on the site"
    );
}

/// **A node that has stopped is never shown under a sentence that says it will
/// recover.**
///
/// `warn.alone` promises the node will learn about new blocks once somebody
/// reaches it. A node whose disk is past saving has switched itself off and
/// nobody can reach it, and it also has no peers, so a banner that asked
/// about peers before it asked about the disk made the promise to exactly the
/// node it was false about.
#[test]
fn a_node_that_has_stopped_is_said_before_one_that_is_alone() {
    let trouble = js_fn("trouble");
    let disk = trouble.find("node.unwritten").expect("the disk is read");
    let alone = trouble.find("warn.alone").expect("being alone is said");
    assert!(
        disk < alone,
        "trouble() says the node is alone before it asks whether the node stopped"
    );
    assert!(
        trouble.contains("withinReach"),
        "trouble() does not tell a disk that can still catch up from one that has \
         stopped the node"
    );
}

/// **The block page asks for the page its own link names.**
///
/// `/api/block/N` pages a block's transfers on `from`, and the page prints
/// "Show more" linking to `/block/N?from=25`. The route handed `block()` the
/// height and not the query, so the link drew the first page again under the
/// second page's address, and no transfer past the twenty fifth of any block
/// could be seen.
#[test]
fn the_block_page_asks_for_the_page_its_link_names() {
    assert!(
        route("/^\\/block\\/(.+)$/").contains("parameters"),
        "the /block/ route does not hand the query to block()"
    );
    let block = js_fn("block");
    assert!(
        block.contains("parameters.get('from')") && block.contains("from="),
        "block() does not forward the `from` cursor to /api/block"
    );
}

/// **Every answer that carries `coverage` is shown with it.**
///
/// `coverage()` in api.rs is carried by every answer that comes out of the
/// index. The page rendered it on the block page and the holders page and
/// left it out of the address, transaction and note pages, which are the
/// three about somebody's money: an address three blocks behind printed its
/// balance bare, since the banner only speaks past eight.
#[test]
fn every_answer_that_carries_coverage_is_shown_with_it() {
    let mut bare = Vec::new();
    for view in ["block", "transaction", "address", "note", "holders"] {
        assert!(
            rust_fn(view).contains("coverage(&mut json, context)"),
            "/api/{view} carries coverage"
        );
        if !js_fn(view).contains("coverageLine(") {
            bare.push(view);
        }
    }
    assert!(
        bare.is_empty(),
        "these views receive `coverage` and never render it: {bare:?}"
    );
}

/// **What an address was paid and paid out are shown as floors when they are
/// floors.**
///
/// Both only grow, so a figure off part of the chain is at least the real
/// one, and so is one that has passed what a count of pebbles holds, which the
/// API says with `turnoverCounted`. The page printed both bare, while the note
/// count beside them already carried the sign.
#[test]
fn what_an_address_was_paid_is_a_floor_where_the_answer_says_so() {
    let turnover = js_fn("turnover");
    assert!(
        turnover.contains("turnoverCounted") && turnover.contains("whole === false"),
        "the turnover figures do not read either reason they can be floors"
    );
    let address = js_fn("address");
    for field in ["data.received", "data.spent"] {
        assert!(
            address.contains(&format!("turnover(data, {field})")),
            "the address page prints {field} without asking whether it is a floor"
        );
    }
}

/// **The pool page shows how much is waiting and a way to the rest.**
///
/// `/api/pool` answers with `count` and a `next` cursor because the pool has
/// a ceiling in bytes and none in transfers. The page printed the first page
/// with no count and no way on, so a pool of forty read as a pool of twenty
/// five beside a ticker saying forty.
#[test]
fn the_pool_page_shows_the_rest_of_the_pool() {
    assert!(
        rust_fn("pool").contains("json.field_usize(\"count\", total)"),
        "/api/pool says how many are waiting"
    );
    let pool = js_fn("pool");
    assert!(
        pool.contains("data.count"),
        "the pool page does not say how many are waiting"
    );
    assert!(
        pool.contains("data.next") && pool.contains("parameters.get('from')"),
        "the pool page offers no way past its first page"
    );
    assert!(
        route("/^\\/pool$/").contains("parameters"),
        "the /pool route does not hand the query to pool()"
    );
}

/// **Every cursor the address answer carries is one the page can follow.**
///
/// `notesNext` was added to the API because an address holding more than a
/// hundred notes had nowhere to ask for the rest. The page never read it and
/// never forwarded `notes`, so the rest still could not be seen.
#[test]
fn every_cursor_the_address_answer_carries_is_followed() {
    assert!(
        rust_fn("address").contains("\"notesNext\""),
        "/api/address carries notesNext"
    );
    let address = js_fn("address");
    assert!(
        address.contains("data.notesNext") && address.contains("parameters.get('notes')"),
        "the address page neither links to the next page of notes nor asks for it"
    );
}

/// **An error is said in the words its status supports.**
///
/// Everything that was not a 404 was announced as the node not answering, so
/// `/address/notanaddress` told the reader the node was down and put the true
/// reason in the pale line under it. The API answers 400 for a malformed
/// reference and 500 for an answer too long to deliver; neither is the node
/// being away.
#[test]
fn an_error_is_said_in_the_words_its_status_supports() {
    let show = js_fn("showError");
    assert!(
        show.contains("400") && show.contains("error.malformed"),
        "a malformed reference is not told apart from a node that did not answer"
    );
    assert!(
        show.contains("500"),
        "an answer the API refused to deliver is not told apart from a node that \
         did not answer"
    );
}

/// **A "not here" says why it is not here.**
///
/// The API now says, for a transaction or a block it cannot produce, whether
/// the block is one this site no longer keeps, one its disk would not read
/// back, or one above the tip. The page said "There is nothing on this chain
/// with that name" for all of them, which is the one thing that is false in
/// every case.
#[test]
fn a_not_here_says_why_it_is_not_here() {
    let show = js_fn("showError");
    for reason in ["not kept", "unreadable", "above the tip", "not written yet"] {
        assert!(
            show.contains(&format!("'{reason}'")),
            "showError() has no sentence for `{reason}`"
        );
    }
}

/// **A block with nothing after it here says why.**
///
/// "Not mined yet" is only true of the tip. A block whose successor this
/// site no longer keeps printed it too.
#[test]
fn only_the_tip_is_not_mined_yet() {
    let block = js_fn("block");
    let pending = block.find("field.pending").expect("the tip still says so");
    let before = &block[..pending];
    assert!(
        before.contains("data.confirmations === 1") || before.contains("isTip"),
        "the block page says `Not mined yet` without asking whether the block is the \
         tip"
    );
}

/// **A search that found nothing says how much it looked in.**
///
/// The API answers `kind: unknown` with `coverage`, and the page printed
/// "Nothing on this chain matches that." whatever the coverage said, so a
/// transaction the index had not reached was denied during every first pass.
#[test]
fn a_search_that_found_nothing_says_how_much_it_looked_in() {
    let handler = SCRIPT
        .split_once("searchForm.addEventListener('submit'")
        .unwrap()
        .1
        .split_once("\n});\n")
        .unwrap()
        .0;
    let nothing = handler
        .find("search.nothing")
        .expect("the search still says nothing matched");
    // The branch for an answer with no target, and not the one above it that
    // already reads the coverage for an address it guessed.
    let branch = handler[..nothing]
        .rfind("go(answer.target)")
        .expect("the search goes where the answer points");
    assert!(
        handler[branch..nothing].contains("answer.coverage"),
        "the search says nothing on the chain matches without asking how much of the \
         chain it looked in"
    );
}

/// **A page whose API has stopped answering says so.**
///
/// The ticker caught every failure and returned, so the height, the footer
/// and the banner went on showing the last answer for as long as the tab was
/// open, and an explorer that was down looked like a chain that was quiet.
#[test]
fn a_page_whose_api_stopped_answering_says_so() {
    let ticker = js_fn("readStatus");
    let caught = ticker
        .split_once("} catch (error) {")
        .expect("the ticker catches a failed read")
        .1;
    let caught = caught.split_once("\n  }\n").unwrap().0;
    assert!(
        caught.contains("misses") && caught.contains("error.stale"),
        "a failed read of the status leaves the last answer on the page with nothing \
         to say it is old"
    );
}

/// **One poll of the status at a time.**
///
/// The ticker ran on a fixed interval with nothing checking the previous poll
/// had come back, so on a site answering slowly every open tab queued another
/// request every five seconds, into a server with sixty four connections for
/// everybody.
#[test]
fn the_ticker_asks_once_at_a_time() {
    let ticker = js_fn("refreshTicker");
    let first = ticker.lines().nth(1).unwrap_or_default();
    assert!(
        first.contains("if (ticking) return;"),
        "the ticker asks again while its last question is still out"
    );
}

/// **The page shown is the page the address bar names.**
///
/// Two navigations in flight drew whichever answer arrived last: click a
/// block, then Explore while it loads, and the block was drawn under
/// `/blocks` with Explore marked as the current section. Every view waits on
/// the API before it draws, so every view has to ask, once the wait is over,
/// whether it is still the one the reader asked for.
#[test]
fn the_page_shown_is_the_page_the_address_bar_names() {
    let render = js_fn("render");
    let taken = render
        .find("const mine = ++rendering;")
        .expect("render() takes a turn");
    let waited = render.find("await handler").expect("render() waits");
    assert!(taken < waited, "the turn is taken after the wait");
    assert!(
        render.contains("showError(error, mine)") && js_fn("showError").contains("rendering"),
        "a late failure still draws its error over the page that replaced it"
    );
    for view in [
        "home",
        "blocks",
        "block",
        "transaction",
        "address",
        "note",
        "pool",
        "holders",
        "rules",
    ] {
        let body = js_fn(view);
        let turn = body
            .find("const mine = rendering;")
            .unwrap_or_else(|| panic!("{view}() does not take the turn it was drawn for"));
        let first = body.find("await ").unwrap();
        let last = body.rfind("await ").unwrap();
        let guard = body
            .find("if (mine !== rendering) return;")
            .unwrap_or_else(|| {
                panic!("{view}() draws its answer whether or not a newer page was asked for")
            });
        let draws = body.find("clear(view)").unwrap();
        assert!(
            turn < first && last < guard && guard < draws,
            "{view}() asks whether it is still the page asked for somewhere other than \
             between its last wait and its first touch of the page"
        );
    }
}

/// The WCAG contrast ratio between two `#rrggbb` colours.
fn contrast(one: &str, two: &str) -> f64 {
    fn luminance(colour: &str) -> f64 {
        let hex = colour.trim_start_matches('#');
        let channel = |at: usize| {
            let value = f64::from(u8::from_str_radix(&hex[at..at + 2], 16).unwrap()) / 255.0;
            if value <= 0.039_28 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4)
    }
    let (a, b) = (luminance(one), luminance(two));
    let (light, dark) = if a > b { (a, b) } else { (b, a) };
    (light + 0.05) / (dark + 0.05)
}

/// The value a block of `cairn.css` gives a custom property.
fn property(block: &str, name: &str) -> String {
    let at = block
        .find(&format!("{name}:"))
        .unwrap_or_else(|| panic!("{name} is set"));
    block[at + name.len() + 1..]
        .split(';')
        .next()
        .unwrap()
        .trim()
        .to_owned()
}

/// **The palest ink on the page can be read.**
///
/// `--ink-3` sets labels, table headings, the notes under figures and the
/// sentence that says how much of the chain a balance is about, all of them
/// under eighteen pixels, where the bound for readable text is 4.5 to 1. It
/// was 4.13 on the dark ground and 3.50 on the light one, and nothing asked.
#[test]
fn the_palest_ink_on_the_page_can_be_read() {
    let dark = STYLE
        .split_once(":root {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    let light = STYLE
        .split_once("prefers-color-scheme: light")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    for (theme, block) in [("dark", dark), ("light", light)] {
        let ink = property(block, "--ink-3");
        for ground in ["--ground", "--surface", "--surface-2"] {
            let behind = property(block, ground);
            let ratio = contrast(&ink, &behind);
            assert!(
                ratio >= 4.5,
                "in the {theme} theme the palest ink on {ground} reads at {ratio:.2} to \
                 one, under the 4.5 small text needs"
            );
        }
    }
}

/// **The size of a node's drawer is said the way the lessons say it.**
///
/// The home page divided by 1024 and called the result megabytes, so it
/// printed 65 MB three panels above a lesson, and a design paper, that say 68.
/// The papers count in decimal megabytes; the figure is the thesis, and it
/// was two different numbers on one site.
#[test]
fn the_drawer_is_the_same_size_on_every_page() {
    let capacity = cairn_ledger::validation::ConsensusParams::testnet().hot_capacity;
    let per_note: usize = API
        .split_once("const HOT_BYTES_PER_NOTE: u64 = ")
        .unwrap()
        .1
        .split_once(';')
        .unwrap()
        .0
        .parse()
        .unwrap();
    let megabytes = (capacity * per_note + 500_000) / 1_000_000;
    let bytes = js_fn("bytes");
    assert!(
        bytes.contains("1000000") && !bytes.contains("1048576"),
        "the page counts megabytes of 1 048 576 bytes while the lessons count them \
         in millions"
    );
    for (language, text, unit) in [("English", EN, "MB"), ("French", FR, "Mo")] {
        assert!(
            text.contains(&format!("{megabytes} {unit}")),
            "the {language} lessons do not say the drawer is {megabytes} {unit}"
        );
    }
}

/// **A miner's message is set apart from the page around it.**
///
/// A coinbase message is text a stranger chose, and a right to left override
/// inside it reverses whatever follows it on the line. The API now refuses
/// the format characters that do that; the page also isolates the message, so
/// one that slips past is contained to itself.
#[test]
fn a_miners_message_is_isolated_from_the_page_around_it() {
    for view in ["block", "transaction"] {
        let body = js_fn(view);
        let at = body
            .find("field.message")
            .unwrap_or_else(|| panic!("{view} shows the message"));
        let line = body[at..].lines().next().unwrap();
        assert!(
            line.contains("el('bdi'"),
            "the {view} page puts a stranger's text on the line without isolating it"
        );
    }
}

/// **The number of pebbles in a CAIRN is the one the rules serve.**
///
/// It is written into the script for the page to divide by, and the API
/// serves it at `/api/params`. The two agree today; this is what says so.
#[test]
fn a_cairn_is_the_same_number_of_pebbles_on_the_page() {
    let written: u64 = SCRIPT
        .split_once("const PEBBLES_PER_CAIRN = ")
        .unwrap()
        .1
        .split_once("n;")
        .unwrap()
        .0
        .parse()
        .unwrap();
    assert_eq!(
        written,
        cairn_primitives::amount::PEBBLES_PER_CAIRN,
        "the page divides by a different number of pebbles than the rules count"
    );
}

/// **A section is marked current only for its own pages.**
///
/// `markCurrent` compared with `startsWith`, so `/learnx` lit up Learn.
#[test]
fn a_section_is_current_only_for_its_own_pages() {
    let mark = js_fn("markCurrent");
    assert!(
        mark.contains("path === target") && mark.contains("target + '/'"),
        "a path that merely begins with a section's address is marked as that section"
    );
}

/// **A page that moves without reloading moves what a screen reader follows.**
///
/// The title stayed "Cairn" on every view, focus stayed wherever the click
/// was, the search note was not announced, the welcome panel took no focus
/// and no Escape, table headings had no scope, and the navigation's label was
/// the one English string not under a translation key.
#[test]
fn a_page_that_moves_without_reloading_moves_what_a_reader_follows() {
    assert!(
        js_fn("render").contains("view.focus({ preventScroll: true })"),
        "a new view does not take focus"
    );
    assert!(
        SCRIPT.contains("document.title = ") && js_fn("setTitle").contains("site.title"),
        "the title does not follow the view"
    );
    assert!(
        PAGE.contains("id=\"search-note\" aria-live=\"polite\""),
        "what the search found is not announced"
    );
    assert!(
        js_fn("table").contains("scope: 'col'"),
        "table headings do not say what they head"
    );
    assert!(
        PAGE.contains("data-t-label=\"a11y.sections\"")
            && js_fn("translateStatic").contains("data-t-label"),
        "the navigation's label is not translated"
    );
    assert!(
        SCRIPT.contains("'Escape'") && js_fn("showWelcome").contains("focus()"),
        "the welcome panel takes neither focus nor Escape"
    );
}

/// **A tip served without a difficulty does not take the home page down.**
///
/// `BigInt(undefined)` throws, and the home page parsed the tip's difficulty
/// bare, so an answer shaped a little differently from the one the page
/// expected blanked the page rather than one figure on it.
#[test]
fn a_figure_the_answer_left_out_is_one_figure_and_not_the_page() {
    let home = js_fn("home");
    assert!(
        !home.contains("BigInt(status.tip ?") && home.contains("status.tip.difficulty ?"),
        "the home page parses a field of the tip that may not be there"
    );
}
