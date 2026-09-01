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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use cairn_crypto::{random_bytes, PublicKey};
use cairn_http::{Request, Response, Writer};
use cairn_primitives::Amount;

use crate::{Wallet, WalletError};

/// Bytes of secret in the address of the page.
const SECRET_BYTES: usize = 24;

/// Notes listed on the page. Enough to show where the money sits, and not a
/// list that grows with the wallet.
const NOTES_SHOWN: usize = 200;

/// Movements listed on the page, newest first.
const MOVEMENTS_SHOWN: usize = 100;

/// A running wallet page.
#[derive(Debug)]
pub struct Opened {
    pub address: SocketAddr,
    pub secret: String,
}

impl Opened {
    /// The address to open in a browser, secret and all.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/?k={}", self.address, self.secret)
    }
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
    json.field_str("stranded", &holdings.stranded.to_string());
    json.field_bool("anything", !holdings.notes.is_empty());
    json.field_usize("held", holdings.notes.len());

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

    let covered = wallet.history_covers();
    match covered.from {
        Some(from) => json.field_u64("history_from", from),
        None => json.field_null("history_from"),
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

fn asked(wallet: &Wallet, request: &Request) -> Result<Asked, Response> {
    let Some(to) = request.field("to") else {
        return Err(refusal("who is being paid?"));
    };
    let Ok(recipient) = parse_key(&to) else {
        return Err(refusal(
            "that is not a public key: it is 64 hexadecimal characters",
        ));
    };
    let Some(amount) = request.field("amount").and_then(|text| parse_amount(&text)) else {
        return Err(refusal("that is not an amount of CAIRN"));
    };
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
    let floor = wallet.floor_for(asked.recipient, asked.amount);
    let total = asked
        .amount
        .checked_add(asked.fee)
        .unwrap_or(Amount::MAX_MONEY);

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

fn parse_key(text: &str) -> Result<PublicKey, WalletError> {
    let text = text.trim();
    let mut bytes = [0u8; 32];
    if text.len() != 64 {
        return Err(WalletError::NothingToSend);
    }
    for (index, slot) in bytes.iter_mut().enumerate() {
        let at = index.checked_mul(2).ok_or(WalletError::NothingToSend)?;
        let pair = text
            .get(at..at.saturating_add(2))
            .ok_or(WalletError::NothingToSend)?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| WalletError::NothingToSend)?;
    }
    PublicKey::from_bytes(&bytes).map_err(|_| WalletError::NothingToSend)
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
    use super::{constant_time_eq, parse_key, turned_away, Opened};
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

    #[test]
    fn comparing_the_secret_says_nothing_by_how_long_it_takes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn an_address_is_read_only_when_it_is_one() {
        assert!(parse_key(&"11".repeat(32)).is_ok());
        assert!(parse_key(&format!("  {}  ", "11".repeat(32))).is_ok());
        assert!(parse_key("").is_err());
        assert!(parse_key(&"11".repeat(31)).is_err(), "too short");
        assert!(parse_key(&"zz".repeat(32)).is_err(), "not hexadecimal");
        assert!(parse_key(&"00".repeat(32)).is_err(), "not a usable key");
    }
}
