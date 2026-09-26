//! The wallet, shown as a page on this machine and nowhere else.
//!
//! The key never comes here. This reads what the library says and passes back
//! what a person typed; the signing happens where the key already is. A face
//! that could sign would be a second place to get signing wrong.
//!
//! Four things keep it to this machine, and none of them is a formality:
//!
//! - it listens on the loopback, so nothing off this machine can reach the
//!   socket at all;
//! - the address carries a secret drawn from the operating system, so a page
//!   that guesses the port still cannot ask anything;
//! - a request naming any host but the loopback is refused, which closes the
//!   attack where a site points a name of its own at 127.0.0.1 and knocks;
//! - a request carrying an origin that is not this wallet's own is refused,
//!   which is what a page open somewhere else in the same browser would send.
//!
//! And it runs only while the wallet is open. There is no background service
//! to forget about.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use cairn_crypto::{random_bytes, PublicKey};
use cairn_http::{Request, Response, Writer};
use cairn_primitives::Amount;

use crate::{parse_address, Wallet, WalletError};

/// Bytes of secret in the address of the page.
const SECRET_BYTES: usize = 24;

/// Notes listed on the page. Enough to show where the money sits, and not a
/// list that grows with the wallet.
const NOTES_SHOWN: usize = 200;

/// Movements listed on the page, newest first.
const MOVEMENTS_SHOWN: usize = 100;

/// A running wallet page.
pub struct Opened {
    pub address: SocketAddr,
    pub secret: String,
}

/// Written by hand, as `SecretKey`'s and `Wallet`'s are, and for the same
/// reason: the secret spends the wallet, a token that reached a log or a
/// panic message is one that is gone, and the derive that would have put it
/// there is one line. `hand_over` keeps it out of whatever reads stdout; this
/// keeps it out of whatever reads a `{:?}`.
impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("address", &self.address)
            .field("secret", &"<withheld>")
            .finish()
    }
}

/// Where the link to a running page was handed over.
#[derive(Clone, PartialEq, Eq)]
pub enum Link {
    /// The address itself, for an operator who is looking at a terminal.
    Shown(String),
    /// A file holding it, for a stdout that is not one.
    Written(PathBuf),
}

/// By hand, for the reason `Opened`'s is: the address shown carries the
/// secret. The path it was written to does not, and is said.
impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shown(_) => f.write_str("Shown(<address withheld>)"),
            Self::Written(path) => f.debug_tuple("Written").field(path).finish(),
        }
    }
}

/// What the file is called, in the wallet's own directory.
const LINK_FILE: &str = "open-this-page";

impl Opened {
    /// The address to open in a browser, secret and all.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/?k={}", self.address, self.secret)
    }

    /// Hands the link over, by the route that suits where stdout goes.
    ///
    /// The link carries the secret that guards the page, so printing it puts a
    /// bearer token wherever stdout goes. On a terminal that is the operator's
    /// own screen and is the whole point of the command. Redirected, it is a
    /// file or a service journal that outlives anybody's attention and is often
    /// readable by more people than the wallet's own directory: on a machine
    /// where the wallet runs under a service manager, a token in the journal is
    /// worth spending money with, for as long as the wallet runs, to anyone who
    /// can read the journal and could not read the keys.
    ///
    /// So a stdout that is not a terminal is handed the path to a file instead,
    /// written in the wallet's own directory, readable by its owner and nobody
    /// else. That is the same protection the keys already have, which is the
    /// right comparison: whoever can read it could have spent the money anyway.
    ///
    /// The token dies with the process either way. What this changes is how
    /// long a copy of it lasts and who can reach that copy, not how long it
    /// works.
    ///
    /// A link file already in the data directory is from a run that stopped
    /// without closing, and names a page that is not there. It goes either
    /// way: written over by the route below, taken away by this one.
    pub fn hand_over(&self, data: &Path, to_a_terminal: bool) -> Result<Link, String> {
        if to_a_terminal {
            Self::let_the_link_go(data);
            return Ok(Link::Shown(self.url()));
        }
        let path = data.join(LINK_FILE);
        write_for_the_owner(&path, self.url().as_bytes())
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        Ok(Link::Written(path))
    }

    /// Takes the file back out, for a wallet that is closing or one that is
    /// handing its address to a terminal instead.
    ///
    /// A link that no longer works is worth nothing to anybody, so this is
    /// tidiness rather than safety: what it prevents is an operator opening a
    /// stale file and finding a page that is not there.
    pub fn let_the_link_go(data: &Path) {
        let _ = std::fs::remove_file(data.join(LINK_FILE));
    }
}

/// Writes a file the owner can read and nobody else can.
///
/// The file holds the address the page is served at, and that address carries
/// the token that spends the wallet. It was opened in place, twice wrongly. A
/// mode given to `open` applies to a file being created and not to one that is
/// already there, so a link file left from an earlier run and widened since,
/// by a restore, a copy off a stick, or a `chmod -R` over the data directory,
/// took the token back in at the mode it had been widened to. And opening in
/// place follows a symbolic link at the name, so a link planted in the data
/// directory, or brought back by a restore, chose where the token went, and
/// emptied that file first: pointed at the key file, it put a page address
/// where the key had been.
///
/// So the file is made new each time, with whatever stood at its name taken
/// away first, by the one helper the account's own partial file is made by;
/// `keyfile::create_anew` has the reasoning. Windows has no mode to set and
/// the file takes the directory's own access control, which is where the
/// wallet already keeps its keys.
fn write_for_the_owner(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut file = crate::keyfile::create_anew(path)?;
    file.write_all(bytes)
}

/// Serves the wallet until `running` is cleared.
///
/// Blocks, so a caller that wants to do anything else runs it on a thread.
/// The wallet is shared rather than borrowed because each connection is
/// answered on its own thread, which outlives this call.
pub fn run(
    wallet: &Arc<Wallet>,
    listener: &std::net::TcpListener,
    opened: &Arc<Opened>,
    running: &Arc<AtomicBool>,
) {
    let wallet = Arc::clone(wallet);
    let opened = Arc::clone(opened);
    cairn_http::serve(listener, running, move |request| {
        answer(&wallet, &opened, request)
    });
}

/// Opens a socket on the loopback and draws the secret that guards it.
pub fn open(port: u16) -> Result<(std::net::TcpListener, Opened), String> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let listener =
        cairn_http::bind(address).map_err(|error| format!("could not listen: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read the address: {error}"))?;
    let secret = random_bytes::<SECRET_BYTES>()
        .map_err(|_| "the operating system refused to provide entropy".to_owned())?;
    let secret = secret.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    });
    Ok((listener, Opened { address, secret }))
}

fn answer(wallet: &Wallet, opened: &Opened, request: &Request) -> Response {
    if let Some(refusal) = turned_away(opened, request) {
        return refusal;
    }
    match request.path.as_str() {
        "/" => served(crate::page::HTML.as_bytes(), "text/html; charset=utf-8"),
        // The look and the script carry nothing and know nothing: the secret
        // reaches the script from the address of the page, so these two are
        // the same bytes for anyone who asks. Holding them behind the secret
        // would mean writing it into the page, where a browser would keep it
        // in the file it caches.
        "/style.css" => served(crate::page::CSS.as_bytes(), "text/css; charset=utf-8"),
        "/wallet.js" => served(crate::page::JS.as_bytes(), "text/javascript; charset=utf-8"),
        "/api/state" => state(wallet),
        "/api/send" if request.post => send(wallet, request),
        // Asked before a spend, so the page can show what carrying it costs
        // rather than finding out afterwards. A POST like the spend it is
        // about, because it takes the same three fields and because nothing
        // that reads this wallet should be reachable by following a link.
        "/api/quote" if request.post => quote(wallet, request),
        "/api/send" | "/api/quote" => text(405, "this one is a POST"),
        _ => text(404, "nothing here"),
    }
}

/// Everything that has to be true before a request is looked at.
///
/// Returned as a refusal rather than a boolean so each reason says which it
/// was: an operator reading a log should be able to tell a mistyped address
/// from a page trying its luck.
fn turned_away(opened: &Opened, request: &Request) -> Option<Response> {
    // A browser sends this when a page made the request, and it sends it on a
    // POST even when the page is this wallet's own. So the test is not whether
    // there is an origin but whether it is ours: anything else is a page
    // somewhere else in the same browser, which is the attack this is here for.
    let ours = format!("http://{}", opened.address);
    if !request.origin.is_empty() && request.origin != ours {
        return Some(text(403, "this wallet does not answer other pages"));
    }
    // The name in the request has to be the loopback. Without this, a site can
    // point a name it controls at 127.0.0.1, have a browser load it, and reach
    // this socket from a page the browser considers same-origin.
    let expected = opened.address.to_string();
    if request.host != expected {
        return Some(text(421, "this wallet answers on the loopback only"));
    }
    // The look and the script are the same for everyone, so they are not held
    // behind the secret. Everything that says anything about this wallet is.
    if matches!(request.path.as_str(), "/style.css" | "/wallet.js") {
        return None;
    }
    let given = request
        .parameter("k")
        .or_else(|| request.field("k"))
        .unwrap_or_default();
    if !constant_time_eq(given.as_bytes(), opened.secret.as_bytes()) {
        return Some(text(403, "open the address the wallet printed"));
    }
    None
}

/// Compares without letting the time taken say how much matched.
///
/// Whoever holds this secret holds the page, and the page spends money. A
/// comparison that stops at the first byte that differs tells anybody who can
/// time it how much of their guess was right, which turns finding the secret
/// from one guess in an enormous number into thirty two guesses in two hundred
/// and fifty six.
///
/// What the property rests on is that every byte is looked at whatever the
/// answer turns out to be, which is what the fold below is: no early return,
/// and the difference accumulated rather than tested. It is that shape in the
/// source and it is not that shape by any rule, so this is the one claim in
/// this file resting on a reading of the code.
///
/// `subtle` would carry it instead, with barriers a compiler is not allowed to
/// see through, and it is in this tree already under `ed25519-dalek` so it
/// would cost nothing anybody downloads. It is not taken, because the count of
/// outside dependencies this project publishes counts the ones its manifests
/// name, and that number is small on purpose and checked by a test. A sixth
/// name for a barrier against something no compiler has been seen to do here
/// is not the trade.
///
/// The length is compared separately and in the ordinary way, which leaks it.
/// That is deliberate: the length of this secret is fixed and printed by the
/// wallet, so it is not a thing anybody has to guess.
///
/// **No test in this file measures any of the above**, and the one that used
/// to be named as though it did is the reason this note is here. What a test
/// can hold is that the comparison answers what a comparison should, which is
/// what [`the_comparison_answers_what_a_comparison_should`] holds. Timing it
/// would be reading this machine at two moments and calling the difference a
/// property of the code.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differing, (a, b)| differing | (a ^ b))
        == 0
}

fn state(wallet: &Wallet) -> Response {
    let progress = wallet.progress();
    // Before the money is counted, because it decides part of the answer: a
    // note whose path has been rebuilt is money that can move again. Asked at
    // most once every so often however often this page redraws, and it costs
    // nothing at all when there is nothing stuck.
    let recovery = wallet.recover_stranded();
    let holdings = wallet.holdings();

    let mut json = Writer::new();
    json.begin_object();
    json.field_str("address", &wallet.address().to_string());
    json.field_str("network", wallet.params().network_name());
    match progress.height {
        Some(height) => json.field_u64("height", height),
        None => json.field_null("height"),
    }
    json.field_usize("peers", progress.peers);
    json.field_str("joining", &progress.joining.to_string());
    // Three states of the node the height and the balance say nothing about,
    // and all three look from here like a wallet that is working.
    match progress.warning() {
        Some(warning) => json.field_str("warning", &warning),
        None => json.field_null("warning"),
    }
    json.field_str("spendable", &holdings.spendable.to_string());
    json.field_str("waiting", &holdings.waiting.to_string());
    json.field_str("ripening", &holdings.ripening.to_string());
    match holdings.ripe_at {
        Some(at) => json.field_str("ripeAt", &at.to_string()),
        None => json.field_null("ripeAt"),
    }
    json.field_str("stranded", &holdings.stranded.to_string());
    // What was done about it, in words, rather than a page of its own that
    // would have to be kept saying the same thing.
    match recovery.words() {
        Some(words) => json.field_str("strandedNote", &words),
        None => json.field_null("strandedNote"),
    }
    // Notes the account has stopped answering for, in words rather than as a
    // figure. A figure beside a balance invites adding it back on, and adding
    // it back on is the thing this exists to stop.
    match holdings.unaccounted_note() {
        Some(note) => json.field_str("unaccountedNote", &note),
        None => json.field_null("unaccountedNote"),
    }
    // Whether this key holds anything at all, which is not the same question
    // as whether a spend has anything to reach for. The page used to answer
    // the second and print the first.
    json.field_bool("anything", !holdings.empty_handed());
    json.field_usize("held", holdings.notes.len());
    // Counted here over every note, because the list below stops at
    // `NOTES_SHOWN` and a count the page made over that list was a count of
    // the notes it was shown, said of all of them.
    json.field_usize(
        "fallen",
        holdings.notes.iter().filter(|held| held.is_cold()).count(),
    );

    // Payments handed over that no block carries yet. The one thing a person
    // watching an unmoved balance after pressing Send needs to be told.
    json.key("payments");
    json.begin_array();
    for payment in wallet.waiting() {
        json.begin_object();
        json.field_str("id", &payment.id.to_string());
        json.field_str("amount", &payment.amount.to_string());
        json.field_str("committed", &payment.committed.to_string());
        json.end_object();
    }
    json.end_array();
    json.key("notes");
    json.begin_array();
    // Enough to show where the money sits without handing a page a list that
    // grows with the wallet.
    for held in holdings.notes.iter().take(NOTES_SHOWN) {
        json.begin_object();
        json.field_str("value", &held.note.value.to_string());
        json.field_bool("cold", held.is_cold());
        json.field_str("source", &held.id.source.to_string());
        json.field_u64("index", u64::from(held.id.index));
        json.end_object();
    }
    json.end_array();

    // What happened, newest first. Read from the wallet's own account of it
    // rather than from the chain, which does not keep one.
    let movements = wallet.history();
    json.key("movements");
    json.begin_array();
    for movement in movements.iter().take(MOVEMENTS_SHOWN) {
        json.begin_object();
        json.field_u64("height", movement.height);
        json.field_u64("at", movement.at);
        json.field_str("way", movement.direction.as_str());
        json.field_str("amount", &movement.amount.to_string());
        json.field_str("id", &movement.id.to_string());
        json.end_object();
    }
    json.end_array();
    json.field_usize("movements_held", movements.len());

    // What the chain took back. A payment that was undone leaves the list
    // above, and leaving with it is the only record anybody had of it.
    let undone = wallet.undone();
    json.key("undone");
    json.begin_array();
    for movement in undone.iter().take(MOVEMENTS_SHOWN) {
        json.begin_object();
        json.field_u64("height", movement.height);
        json.field_str("way", movement.direction.as_str());
        json.field_str("amount", &movement.amount.to_string());
        json.field_str("id", &movement.id.to_string());
        json.end_object();
    }
    json.end_array();
    // How many there were, for the same reason `movements_held` is written
    // ten lines above and by the rule written beside the other face: a list
    // that stops short and does not say where it stopped has told somebody
    // something untrue about their own money. This list holds up to
    // `MAX_UNDONE`, which is two hundred and fifty six, and shows a hundred,
    // and the page renders what it shows as a finished sentence ending
    // "Whoever you were paying has not been paid". A payment missing from it
    // reads as a payment that went through.
    json.field_usize("undone_held", undone.len());

    let covered = wallet.history_covers();
    match covered.from {
        Some(from) => json.field_u64("history_from", from),
        None => json.field_null("history_from"),
    }
    // Where the list may be short, which is apart from where it begins: a gap
    // in the middle is a stretch the account read nothing of, and the
    // movements on both sides of it are here.
    match covered.missed_below {
        Some(missed) => json.field_u64("history_missed_below", missed),
        None => json.field_null("history_missed_below"),
    }
    json.field_u64("history_behind", covered.behind());
    json.end_object();
    json_response(200, json)
}

/// What a person typed into the send form, read once.
struct Asked {
    recipient: PublicKey,
    amount: Amount,
    fee: Amount,
}

/// The amount a spend asks for, or the sentence that says what is wrong
/// with it.
///
/// Absent and malformed are two faults and get two sentences, the way the two
/// fields beside it already do: `to` says "who is being paid?" when it is
/// missing and names the shape of a key when it is wrong, and a blank fee means
/// "work it out" rather than a fault. This one collapsed both, so a request
/// that sent no amount at all was told "that is not an amount of CAIRN", which
/// is a sentence about a value nobody typed.
fn amount_of(field: Option<String>) -> Result<Amount, &'static str> {
    let Some(text) = field.filter(|text| !text.trim().is_empty()) else {
        return Err("how much is being sent?");
    };
    parse_amount(&text).ok_or("that is not an amount of CAIRN")
}

fn asked(wallet: &Wallet, request: &Request) -> Result<Asked, Response> {
    let Some(to) = request.field("to") else {
        return Err(refusal("who is being paid?"));
    };
    let Ok(recipient) = parse_address(&to) else {
        return Err(refusal(
            "that is not a public key: it is 64 hexadecimal characters",
        ));
    };
    let amount = amount_of(request.field("amount")).map_err(refusal)?;
    // Left blank means what the network asks, worked out from the transfer
    // this would build. Nothing is no longer a fee anybody carries, and a page
    // that sent one would have the refusal come back from a pool the person
    // typing cannot see.
    let fee = match request.field("fee") {
        None => wallet.floor_for(recipient, amount),
        Some(text) if text.trim().is_empty() => wallet.floor_for(recipient, amount),
        Some(text) => match parse_amount(&text) {
            Some(fee) => fee,
            None => return Err(refusal("that fee is not an amount of CAIRN")),
        },
    };
    Ok(Asked {
        recipient,
        amount,
        fee,
    })
}

/// What a spend would cost, without making it.
///
/// The fee was the one number the page never showed. Somebody meaning
/// `0.00005` and typing `5` paid five CAIRN to a miner and read "Sent
/// 1.00000000 CAIRN", with nothing anywhere saying what carrying it had cost.
fn quote(wallet: &Wallet, request: &Request) -> Response {
    let asked = match asked(wallet, request) {
        Ok(asked) => asked,
        Err(refusal) => return refusal,
    };
    // Refused as sending refuses it, in the same words: a payment with no
    // transfer to price has no price. This used to quote one anyway, with the
    // ceiling standing in for a sum past it and nought for the floor of a
    // payment the wallet could not make.
    if let Some(error) = wallet.could_not_draft(asked.recipient, asked.amount, asked.fee) {
        return refusal(&error.to_string());
    }
    let Some(total) = asked.amount.checked_add(asked.fee) else {
        return refusal(&WalletError::TooLarge.to_string());
    };
    let floor = wallet.floor_for(asked.recipient, asked.amount);

    let mut json = Writer::new();
    json.begin_object();
    json.field_bool("quoted", true);
    json.field_str("amount", &asked.amount.to_string());
    json.field_str("fee", &asked.fee.to_string());
    json.field_str("floor", &floor.to_string());
    json.field_str("total", &total.to_string());
    json.end_object();
    json_response(200, json)
}

fn send(wallet: &Wallet, request: &Request) -> Response {
    let asked = match asked(wallet, request) {
        Ok(asked) => asked,
        Err(refusal) => return refusal,
    };
    // Set only by pressing the button the refusal below puts up, so a fee out
    // of all proportion is paid once somebody has read the number and said
    // again that they mean it.
    let meant = request
        .field("anyway")
        .is_some_and(|text| text.trim() == "1");
    let spend = if meant {
        wallet.send_over_the_odds(asked.recipient, asked.amount, asked.fee)
    } else {
        wallet.send(asked.recipient, asked.amount, asked.fee)
    };

    match spend {
        Err(error @ WalletError::FeeOutOfProportion { .. }) => steep(&error.to_string()),
        Err(error) => refusal(&error.to_string()),
        Ok(sent) => {
            let mut json = Writer::new();
            json.begin_object();
            json.field_bool("sent", true);
            json.field_str("id", &sent.id.to_string());
            json.field_str("amount", &sent.amount.to_string());
            json.field_str("fee", &sent.fee.to_string());
            json.field_str("change", &sent.change.to_string());
            json.field_usize("notes", sent.notes);
            json.field_usize("from_cold", sent.from_cold);
            json.field_bool("handed_on", sent.handed_on);
            json.end_object();
            json_response(200, json)
        }
    }
}

fn parse_amount(text: &str) -> Option<Amount> {
    Amount::from_cairn(text.trim())
}

fn refusal(message: &str) -> Response {
    let mut json = Writer::new();
    json.begin_object();
    json.field_bool("sent", false);
    json.field_str("error", message);
    json.end_object();
    json_response(200, json)
}

/// A refusal the person asking is allowed to overrule.
///
/// Marked apart from the others so the page can put up a button rather than
/// only a sentence. Overpaying is sometimes the point, and a wallet that made
/// it impossible would be one that decided for its owner how much their hurry
/// is worth.
fn steep(message: &str) -> Response {
    let mut json = Writer::new();
    json.begin_object();
    json.field_bool("sent", false);
    json.field_bool("steep", true);
    json.field_str("error", message);
    json.end_object();
    json_response(200, json)
}

fn json_response(status: u16, json: Writer) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8",
        cache: "no-store",
        body: json.finish().into_bytes(),
    }
}

fn served(body: &[u8], content_type: &'static str) -> Response {
    Response {
        status: 200,
        content_type,
        cache: "no-store",
        body: body.to_vec(),
    }
}

fn text(status: u16, message: &str) -> Response {
    Response {
        status,
        content_type: "text/plain; charset=utf-8",
        cache: "no-store",
        body: message.as_bytes().to_vec(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{amount_of, constant_time_eq, parse_address, turned_away, Opened};
    use cairn_http::Request;

    fn opened() -> Opened {
        Opened {
            address: "127.0.0.1:7777".parse().unwrap(),
            secret: "abcdef".to_owned(),
        }
    }

    fn asking(host: &str, origin: &str, query: &str) -> Request {
        Request {
            path: "/api/state".to_owned(),
            query: query.to_owned(),
            head_only: false,
            post: false,
            body: String::new(),
            host: host.to_owned(),
            origin: origin.to_owned(),
        }
    }

    #[test]
    fn the_wallet_answers_only_what_its_own_page_asks() {
        let opened = opened();
        assert!(
            turned_away(&opened, &asking("127.0.0.1:7777", "", "k=abcdef")).is_none(),
            "its own page, with the secret, on the loopback"
        );

        // A page open somewhere else in the same browser, which is the whole
        // reason any of this is here.
        assert!(
            turned_away(
                &opened,
                &asking("127.0.0.1:7777", "https://example.com", "k=abcdef")
            )
            .is_some(),
            "a page somewhere else in the same browser is the whole reason for this"
        );

        // A browser sends an origin on a POST even to the page's own address,
        // so refusing every origin would refuse this wallet's own spend form.
        assert!(
            turned_away(
                &opened,
                &asking("127.0.0.1:7777", "http://127.0.0.1:7777", "k=abcdef")
            )
            .is_none(),
            "its own page, posting, which is how a spend arrives"
        );

        // A name someone else controls, pointed at this machine.
        assert!(
            turned_away(&opened, &asking("wallet.example.com:7777", "", "k=abcdef")).is_some(),
            "a host that is not the loopback is somebody else's name for it"
        );

        // Guessing the port is not enough.
        assert!(
            turned_away(&opened, &asking("127.0.0.1:7777", "", "k=wrong")).is_some(),
            "the secret decides"
        );
        assert!(
            turned_away(&opened, &asking("127.0.0.1:7777", "", "")).is_some(),
            "and there is no way in without it"
        );
    }

    /// What a test here can hold, and it is not what the name used to claim.
    ///
    /// The name was `comparing_the_secret_says_nothing_by_how_long_it_takes`,
    /// and what it asserts is four equalities. Replace the comparison with
    /// `==` and every one of them still holds, because the two answer the same
    /// thing and differ only in what they do on the way. So the name stated a
    /// property the test could not fail on, which is the shape this repository
    /// looks for everywhere else.
    ///
    /// What holds the timing property is the note on `constant_time_eq`, and
    /// it is a reading of the code rather than anything here.
    #[test]
    fn the_comparison_answers_what_a_comparison_should() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));

        // A difference at either end, because a comparison that stopped early
        // would still answer both of these correctly and this is where
        // somebody reading the test should notice that it cannot tell.
        assert!(!constant_time_eq(b"Xbc", b"abc"), "the first byte");
        assert!(!constant_time_eq(b"abX", b"abc"), "the last byte");
    }

    /// The secret's own characters in another order are a wrong key.
    ///
    /// Every refusal above differs from the secret in one byte, which is the
    /// one case where it does not matter how the differences are gathered.
    /// Gathered with `^` rather than `|`, two differences cancel, and the
    /// comparison asks only whether the key's bytes XOR to what the secret's
    /// do. Any reordering of the secret does. So does about one guess in
    /// thirty two of the right length, against the one in 2^192 that
    /// `SECRET_BYTES` is there to buy, for the page that spends the money.
    #[test]
    fn the_secret_in_another_order_does_not_open_the_page() {
        let opened = opened();
        assert!(
            turned_away(&opened, &asking("127.0.0.1:7777", "", "k=bacdef")).is_some(),
            "two characters of the secret swapped opened the page"
        );
        assert!(
            !constant_time_eq(b"ab", b"ba"),
            "two differences that cancel each other are still two differences"
        );
    }

    /// An address, written out of a key rather than typed.
    ///
    /// The accepting half of this used to be `"11".repeat(32)`, a string of
    /// bytes that happened to decompress to a point on the curve. It is not an
    /// address and never was: it carries a torsion component, so no secret
    /// reaches it and nothing could ever be spent from it. The parser took it
    /// until the subgroup check went in, and then this test was asserting that
    /// the parser accepted a thing nobody holds.
    fn an_address() -> String {
        cairn_crypto::SecretKey::from_bytes(&[5; 32])
            .public_key()
            .to_string()
    }

    /// And the spellings a sign makes, which one of the two readers took.
    ///
    /// `u8::from_str_radix("+a", 16)` is ten. Walking a key two characters at
    /// a time through it read `"+a"` as the byte `0a`, so a key carrying that
    /// byte had a second spelling at this endpoint, and the spelling the
    /// command line refuses was the one accepted here.
    ///
    /// The bend has to land on a pair that already reads `0a`. Bend any other
    /// pair and the bent string is a different key, the subgroup check refuses
    /// it, and the test passes green on the parser it was written to catch.
    #[test]
    fn a_sign_is_not_a_hex_digit() {
        let carrying = (0u8..=255).find_map(|seed| {
            let text = cairn_crypto::SecretKey::from_bytes(&[seed; 32])
                .public_key()
                .to_string();
            let at = (0..32)
                .map(|pair: usize| pair.saturating_mul(2))
                .find(|&at| text.get(at..at.saturating_add(2)) == Some("0a"))?;
            Some((text, at))
        });
        assert!(
            carrying.is_some(),
            "no key in two hundred and fifty six seeds carries the byte 0a, so this \
             test no longer reaches the parser at all"
        );
        let (real, at) = carrying.unwrap();

        let mut bent = real.clone();
        bent.replace_range(at..at.saturating_add(2), "+a");
        assert_ne!(bent, real, "the bend has to change the string");
        assert!(parse_address(&real).is_ok(), "the key itself");
        assert!(
            parse_address(&bent).is_err(),
            "a sign was read as a digit at {at}, so this key has a second spelling"
        );
    }

    /// A missing amount and a wrong one are told apart.
    ///
    /// The two fields beside it already did this and this one did not: a
    /// request with no amount at all was answered "that is not an amount of
    /// CAIRN", a sentence about a value nobody typed.
    #[test]
    fn a_missing_amount_is_asked_for_and_a_wrong_one_is_named() {
        let missing = amount_of(None).unwrap_err();
        let blank = amount_of(Some("  ".to_owned())).unwrap_err();
        let wrong = amount_of(Some("lots".to_owned())).unwrap_err();

        assert_eq!(missing, blank, "blank is missing, not wrong");
        assert_ne!(
            missing, wrong,
            "a missing amount and a malformed one get different sentences"
        );
        assert!(
            !missing.contains("not an amount"),
            "nothing was typed, so nothing was not an amount: {missing}"
        );
        assert!(wrong.contains("not an amount"), "{wrong}");
        assert!(
            amount_of(Some("1.5".to_owned())).is_ok(),
            "and a real one reads"
        );
    }

    #[test]
    fn an_address_is_read_only_when_it_is_one() {
        let real = an_address();
        assert!(parse_address(&real).is_ok());
        assert!(parse_address(&format!("  {real}  ")).is_ok());
        assert!(parse_address("").is_err());
        assert!(parse_address(&real[..62]).is_err(), "too short");
        assert!(parse_address(&"zz".repeat(32)).is_err(), "not hexadecimal");
        assert!(parse_address(&"00".repeat(32)).is_err(), "not a usable key");
        // And the whole reason the line above says "usable" rather than
        // "decodable": a string can be a point on the curve and still be an
        // address nobody holds.
        assert!(
            parse_address(&"11".repeat(32)).is_err(),
            "a point outside the prime order subgroup is not an address"
        );
    }
}
