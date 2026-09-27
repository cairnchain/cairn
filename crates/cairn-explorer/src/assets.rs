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
/// as source. Each file is the whole page, declaration, language, character
/// set and viewport included, written by `cairn-docs` from the document's own
/// front matter; nothing is added here, and in particular no navigation and no
/// script, so nothing on the page can change what the paper says.
///
/// The shell used to be glued on here at compile time, with the language typed
/// a second time beside each file. A file opened from a checkout then had no
/// character set, and the language had two sources that nothing held equal.
///
/// They name no font from anywhere else. That is what lets the site's policy
/// stay as strict as it is, and what stops a paper meant to outlast us from
/// needing somebody else's server to be read.
macro_rules! paper {
    ($file:literal) => {
        include_str!($file)
    };
}

pub(crate) const PAPERS: [(&str, &str); 6] = [
    ("/whitepaper", paper!("../../../docs/cairn-whitepaper.html")),
    (
        "/specification",
        paper!("../../../docs/cairn-specification.html"),
    ),
    (
        "/threat-model",
        paper!("../../../docs/cairn-threat-model.html"),
    ),
    ("/design", paper!("../../../docs/cairn-design.html")),
    (
        "/open-questions",
        paper!("../../../docs/cairn-open-questions.html"),
    ),
    ("/prior-art", paper!("../../../docs/cairn-prior-art.html")),
];

/// The look of each paper, kept beside it rather than inside it.
///
/// The site refuses a style written into the page, for the same reason it
/// refuses a script written into the page: what a page carries inline is what
/// an injection carries too, and a rule that admits one admits both. The href
/// in each paper is relative, so the same file works served from here and
/// opened from a folder.
pub(crate) const PAPER_STYLES: [(&str, &str); 3] = [
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
        path => {
            // Asked once each, where each was asked twice: whether it is here
            // and then where, with a refusal between the two for the case the
            // first answer had already ruled out.
            if let Some((_, body)) = PAPERS.iter().find(|(at, _)| *at == path) {
                return Response::asset(HTML, body);
            }
            if let Some((_, body)) = PAPER_STYLES.iter().find(|(at, _)| *at == path) {
                return Response::asset(CSS, body);
            }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{answer, LOCALES, PAPERS, PAPER_STYLES};
    use cairn_http::{Request, Response};

    /// The value of `name="` in the first element that carries `marker`.
    fn attribute_of<'a>(page: &'a str, marker: &str, name: &str) -> Option<&'a str> {
        let element = page.split_once(marker)?.1.split_once('>')?.0;
        element
            .split_once(&format!("{name}=\""))?
            .1
            .split_once('"')
            .map(|(value, _)| value)
    }

    /// **Every document rendered is a paper served, and every paper served is
    /// a rendered document, byte for byte.**
    ///
    /// The two lists are kept by hand in two crates. A document added to one
    /// and not the other was generated and never served, or served from a
    /// file nothing regenerated, and nothing said either.
    #[test]
    fn the_papers_served_are_the_documents_rendered() {
        assert_eq!(
            PAPERS.len(),
            cairn_docs::DOCUMENTS.len(),
            "the explorer serves a different number of papers than cairn-docs renders"
        );
        for document in cairn_docs::DOCUMENTS {
            let committed = std::fs::read_to_string(cairn_docs::html_path(document)).unwrap();
            assert!(
                PAPERS.iter().any(|(_, body)| *body == committed),
                "{document} is rendered and not served as it is on disk"
            );
        }
    }

    /// **Each paper's language is written once, and the stylesheet it links is
    /// one this serves.**
    ///
    /// The language used to be typed here beside each file and again in the
    /// front matter, and nothing held the two equal. And a stylesheet a paper
    /// names that is not in the list below is answered with the site's index
    /// page, which a browser drops for its type, so the paper rendered
    /// unstyled with no error anywhere.
    #[test]
    fn each_paper_declares_one_language_and_links_a_stylesheet_that_is_served() {
        for (path, body) in PAPERS {
            let page = attribute_of(body, "<html", "lang").unwrap();
            let paper = attribute_of(body, "<div class=\"paper\"", "lang").unwrap();
            assert_eq!(page, paper, "{path} declares two languages");
            let sheet = attribute_of(body, "<link rel=\"stylesheet\"", "href").unwrap();
            assert!(
                PAPER_STYLES
                    .iter()
                    .any(|(served, _)| served.strip_prefix('/') == Some(sheet)),
                "{path} links {sheet}, which the explorer does not serve"
            );
        }
    }

    /// **The folder holds the pages rendered and the stylesheets they link,
    /// and nothing else.**
    ///
    /// A page left behind after its document was removed, or a stylesheet no
    /// page links, was noticed by nothing.
    #[test]
    fn the_documents_folder_holds_no_page_or_stylesheet_nothing_uses() {
        for entry in std::fs::read_dir(cairn_docs::folder()).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            if let Some(stem) = name.strip_suffix(".html") {
                assert!(
                    cairn_docs::DOCUMENTS.contains(&stem),
                    "docs/{name} is a page no document renders"
                );
            } else if std::path::Path::new(&name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("css"))
            {
                assert!(
                    PAPER_STYLES
                        .iter()
                        .any(|(served, _)| served.strip_prefix('/') == Some(name.as_str())),
                    "docs/{name} is a stylesheet the explorer does not serve"
                );
            }
        }
    }

    fn get(path: &str) -> Response {
        answer(&Request {
            path: path.to_owned(),
            query: String::new(),
            head_only: false,
            post: false,
            body: String::new(),
            host: String::new(),
            origin: String::new(),
        })
    }

    /// Each paper, each paper's stylesheet and each language file is served
    /// at its own address as itself.
    ///
    /// An address this module does not know is answered with the page, which
    /// is how a link into the page works. So a paper whose route went missing
    /// was answered with the page as well, status 200, and nothing noticed;
    /// the same held for a language file answered in the other language, and
    /// for a list of languages that listed none.
    #[test]
    fn each_paper_style_and_language_is_served_as_itself() {
        for (path, body) in PAPERS.iter().chain(PAPER_STYLES.iter()) {
            let served = get(path);
            assert_eq!(served.status, 200, "{path}");
            assert!(
                served.body == body.as_bytes(),
                "{path} was served as something else"
            );
        }
        for (code, _, body) in LOCALES {
            let served = get(&format!("/i18n/{code}.json"));
            assert!(
                served.body == body.as_bytes(),
                "{code} was served as something else"
            );
        }
        assert_eq!(get("/i18n/xx.json").status, 404, "a language nobody wrote");

        let listed = String::from_utf8(get("/languages.json").body).unwrap();
        for (code, name, _) in LOCALES {
            assert!(
                listed.contains(&format!("\"code\":\"{code}\"")) && listed.contains(name),
                "{code} is not in {listed}"
            );
        }
    }

    /// Words a document of this length cannot avoid, and which differ enough
    /// between the two languages to tell one from the other.
    ///
    /// A tell rather than a dictionary. What is being caught is a paper served
    /// under the wrong language, not a clumsy sentence.
    const MARKERS: [(&str, [&str; 6]); 2] = [
        ("en", [" the ", " of ", " and ", " is ", " that ", " with "]),
        ("fr", [" le ", " des ", " est ", " qui ", " pour ", " une "]),
    ];

    fn score(text: &str, words: &[&str]) -> usize {
        words.iter().map(|word| text.matches(word).count()).sum()
    }

    /// A browser believes `<html lang>`. It hyphenates by it, chooses a font by
    /// it, and it is the voice a screen reader speaks in, so a French paper
    /// announced as English is read aloud as nonsense to the one reader who
    /// cannot see that it is French. What each paper says about itself is held
    /// here against what it is written in.
    #[test]
    fn each_paper_is_declared_in_the_language_it_is_written_in() {
        for (path, body) in PAPERS {
            let declared = LOCALES
                .iter()
                .map(|(code, _, _)| *code)
                .find(|code| body.contains(&format!("<html lang=\"{code}\"")))
                .unwrap_or_else(|| panic!("{path} declares no language the site speaks"));
            let reads_as = MARKERS
                .iter()
                .max_by_key(|(_, words)| score(body, words))
                .map(|(code, _)| *code)
                .unwrap();
            assert_eq!(declared, reads_as, "{path} says {declared}");
        }
    }
}
