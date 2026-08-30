//! The website, compiled into the program.
//!
//! Nothing is read from disk while the explorer runs, so there is no path a
//! request can name and no directory an operator has to remember to ship. The
//! binary is the site.

use cairn_http::{Request, Response};

const INDEX: &str = include_str!("../../../web/index.html");
const STYLE: &str = include_str!("../../../web/cairn.css");
const SCRIPT: &str = include_str!("../../../web/cairn.js");

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const JSON: &str = "application/json; charset=utf-8";

/// Every translation, English first because it is the one the others are
/// written from.
///
/// A language is a file here and nothing else: no code changes when one is
/// added, which is the only way a translation stays worth having.
pub(crate) const LOCALES: [(&str, &str, &str); 2] = [
    ("en", "English", include_str!("../../../web/i18n/en.json")),
    ("fr", "Français", include_str!("../../../web/i18n/fr.json")),
];

/// The papers, served from the chain's own address.
///
/// A protocol whose whole argument is that you should check things for
/// yourself has to be readable somewhere that is not a code host showing HTML
/// as source. Each is written as a fragment, so the declaration a browser
/// needs is glued on in front at compile time; nothing else is added, and in
/// particular no navigation and no script, so nothing on the page can change
/// what the paper says.
///
/// They name no font from anywhere else. That is what lets the site's policy
/// stay as strict as it is, and what stops a paper meant to outlast us from
/// needing somebody else's server to be read.
macro_rules! paper {
    ($language:literal, $file:literal) => {
        concat!(
            "<!doctype html>\n<html lang=\"",
            $language,
            "\">\n<meta charset=\"utf-8\">\n",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "<meta name=\"color-scheme\" content=\"dark light\">\n",
            include_str!($file)
        )
    };
}

const PAPERS: [(&str, &str); 3] = [
    (
        "/whitepaper",
        paper!("en", "../../../docs/cairn-whitepaper.html"),
    ),
    ("/design", paper!("en", "../../../docs/cairn-design.html")),
    (
        "/prior-art",
        paper!("fr", "../../../docs/cairn-prior-art.html"),
    ),
];

/// The look of each paper, kept beside it rather than inside it.
///
/// The site refuses a style written into the page, for the same reason it
/// refuses a script written into the page: what a page carries inline is what
/// an injection carries too, and a rule that admits one admits both. The href
/// in each paper is relative, so the same file works served from here and
/// opened from a folder.
const PAPER_STYLES: [(&str, &str); 3] = [
    (
        "/cairn-whitepaper.css",
        include_str!("../../../docs/cairn-whitepaper.css"),
    ),
    (
        "/cairn-design.css",
        include_str!("../../../docs/cairn-design.css"),
    ),
    (
        "/cairn-prior-art.css",
        include_str!("../../../docs/cairn-prior-art.css"),
    ),
];

/// Serves a compiled-in file, or the page itself for anything else.
///
/// An unknown path returns the page rather than a not-found, because the
/// address bar is where a person lands when they follow a link to a block.
/// The page reads the path and asks the API for what it names.
pub(crate) fn answer(request: &Request) -> Response {
    match request.path.as_str() {
        "/" => Response::asset(HTML, INDEX),
        "/cairn.css" => Response::asset(CSS, STYLE),
        "/cairn.js" => Response::asset(JS, SCRIPT),
        "/languages.json" => Response::json(languages()),
        path if PAPERS.iter().any(|(at, _)| *at == path) => {
            match PAPERS.iter().find(|(at, _)| *at == path) {
                Some((_, body)) => Response::asset(HTML, body),
                None => Response::error(404, "no such paper"),
            }
        }
        path if PAPER_STYLES.iter().any(|(at, _)| *at == path) => {
            match PAPER_STYLES.iter().find(|(at, _)| *at == path) {
                Some((_, body)) => Response::asset(CSS, body),
                None => Response::error(404, "no such style"),
            }
        }
        path => {
            if let Some(tag) = path
                .strip_prefix("/i18n/")
                .and_then(|file| file.strip_suffix(".json"))
            {
                if let Some((_, _, body)) = LOCALES.iter().find(|(code, _, _)| *code == tag) {
                    return Response::asset(JSON, body);
                }
                return Response::error(404, "no such language");
            }
            Response::asset(HTML, INDEX)
        }
    }
}

/// What the language menu is built from.
fn languages() -> String {
    let mut json = cairn_http::Writer::new();
    json.begin_array();
    for (code, name, _) in LOCALES {
        json.begin_object();
        json.field_str("code", code);
        json.field_str("name", name);
        json.end_object();
    }
    json.end_array();
    json.finish()
}
