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
