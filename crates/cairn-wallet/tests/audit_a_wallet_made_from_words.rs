//! A wallet made from twenty four words, and made again from them.
//!
//! `new` shows the words once, asks for three of them back, and only then
//! writes the key file. `restore` reads the words from its input and writes
//! the same key file. Both are run here as a person runs them, through the
//! program, because what is being held is what reaches the person: which
//! words are shown, what is asked, what is refused and what is left on disk.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The first BIP-39 vector of twenty four words.
const ABANDON_ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon art";

/// The key those words make along `m/44'/1'/0'/0'/0'`, worked out apart from
/// this program: PBKDF2-HMAC-SHA512 and SLIP-0010 written out with Python's
/// `hashlib` and `hmac`, from the two specifications.
const ABANDON_ART_KEY: &str = "99da0b339e5c3e3dddd59678b52a7c7e5f9e02bd07af4e220cd69228766bcddb";

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("cairn-words-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Runs the wallet with `input` on its standard input.
fn wallet(arguments: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the wallet runs");
    // A refusal can come before the input is read, and then the pipe is
    // closed under the write; what is being tested is the answer.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}

/// The words `new` printed, in the order of their numbers.
fn the_words_shown(output: &str) -> Vec<String> {
    let mut numbered: Vec<(usize, String)> = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for pair in tokens.windows(2) {
            let Some(number) = pair[0].strip_suffix('.') else {
                continue;
            };
            let Ok(number) = number.parse::<usize>() else {
                continue;
            };
            if pair[1].chars().all(|c| c.is_ascii_lowercase()) {
                numbered.push((number, pair[1].to_owned()));
            }
        }
    }
    numbered.sort();
    assert_eq!(
        numbered.iter().map(|(at, _)| *at).collect::<Vec<_>>(),
        (1..=24).collect::<Vec<_>>(),
        "every word from one to twenty four, each once: {output}"
    );
    numbered.into_iter().map(|(_, word)| word).collect()
}

fn the_address(output: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix("address"))
        .map(|rest| rest.trim().to_owned())
        .expect("an address line")
}

/// **The words `new` shows make, through `restore`, the key `new` wrote.**
#[test]
fn the_words_new_shows_restore_the_key_it_wrote() {
    let home = scratch("round-trip");
    let made_key = home.join("made.key");
    let made = wallet(&["new", text(&made_key), "--unsafe-skip-word-check"], "");
    assert!(made.status.success(), "{}", said(&made));
    let shown = String::from_utf8_lossy(&made.stdout).into_owned();
    let words = the_words_shown(&shown);
    assert!(
        shown.contains("on paper") && shown.contains("Never in a photo"),
        "the words come with what to do with them: {shown}"
    );

    let restored_key = home.join("restored.key");
    // Six to a line, as somebody copying off paper types them.
    let typed = words
        .chunks(6)
        .map(|line| line.join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    let restored = wallet(&["restore", text(&restored_key)], &format!("{typed}\n"));
    assert!(restored.status.success(), "{}", said(&restored));
    assert_eq!(
        std::fs::read(&restored_key).unwrap(),
        std::fs::read(&made_key).unwrap(),
        "the key file restored from the words is the one new wrote"
    );
    assert_eq!(
        the_address(&String::from_utf8_lossy(&restored.stdout)),
        the_address(&shown),
        "and says the same address"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// **A restore writes the key the specifications give, on every test
/// network.**
#[test]
fn a_restore_writes_the_key_worked_out_apart_from_this_program() {
    let home = scratch("known-answer");
    for network in ["testnet-8", "devnet"] {
        let key = home.join(format!("{network}.key"));
        let restored = wallet(
            &["restore", text(&key), "--network", network],
            &format!("{ABANDON_ART}\n"),
        );
        assert!(restored.status.success(), "{}", said(&restored));
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            format!("{ABANDON_ART_KEY}\n"),
            "the key file holds the derived key in the format it always had, on {network}"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// **`new` writes nothing until three words have come back as shown.**
#[test]
fn new_writes_the_key_only_once_three_words_come_back() {
    let home = scratch("checked");
    let key = home.join("mine.key");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cairn-wallet"))
        .args(["new", text(&key)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut seen = String::new();
    let mut words: Option<Vec<String>> = None;
    let mut answered = 0;
    let mut asked_for = Vec::new();
    let mut byte = [0u8; 1];
    while stdout.read(&mut byte).unwrap() == 1 {
        seen.push(char::from(byte[0]));
        let Some(prompt) = seen.rsplit('\n').next().map(str::to_owned) else {
            continue;
        };
        let Some(asked) = prompt
            .strip_prefix("word ")
            .and_then(|rest| rest.strip_suffix(": "))
        else {
            continue;
        };
        let at: usize = asked.parse().unwrap();
        assert!(
            !key.exists(),
            "the key file is written before the words came back"
        );
        let shown = words.get_or_insert_with(|| the_words_shown(&seen));
        // In capitals the first time, as somebody might type it.
        writeln!(stdin, "{}", shown[at - 1].to_uppercase()).unwrap();
        answered += 1;
        asked_for.push(at);
        seen.push('\n');
    }
    let status = child.wait().unwrap();
    assert!(status.success(), "{seen}");
    assert_eq!(answered, 3, "three words are asked back: {seen}");
    asked_for.dedup();
    assert_eq!(
        asked_for.len(),
        3,
        "three different words, or the check proves one word was copied: {seen}"
    );
    assert!(key.exists(), "and then the key file is written");
    assert!(seen.contains("key written to"), "{seen}");
    let _ = std::fs::remove_dir_all(&home);
}

/// **A word that does not come back, or input that ends, leaves no key.**
#[test]
fn new_writes_nothing_when_the_words_do_not_come_back() {
    let home = scratch("unchecked");

    let key = home.join("ended.key");
    let ended = wallet(&["new", text(&key)], "");
    assert!(!ended.status.success(), "{}", said(&ended));
    assert!(!key.exists(), "the input ended and a key was written");
    assert!(
        said(&ended).contains("--unsafe-skip-word-check"),
        "and the way a script gets past it is named: {}",
        said(&ended)
    );

    // Nine wrong answers: three tries at the first word asked, and the rest
    // never read.
    let key = home.join("wrong.key");
    let wrong = wallet(&["new", text(&key)], &"cairn\n".repeat(9));
    assert!(!wrong.status.success(), "{}", said(&wrong));
    assert!(
        !key.exists(),
        "a word that never came back and a key was written"
    );
    assert!(said(&wrong).contains("They are void"), "{}", said(&wrong));
    let _ = std::fs::remove_dir_all(&home);
}

/// **A name already taken is refused before any word is shown.**
///
/// Words copied onto paper for a key the write then refuses are words for
/// nothing, and the person holding them cannot tell.
#[test]
fn new_and_restore_refuse_a_name_already_taken_before_any_word() {
    let home = scratch("taken");
    let key = home.join("mine.key");
    std::fs::write(&key, "held\n").unwrap();

    let made = wallet(&["new", text(&key), "--unsafe-skip-word-check"], "");
    assert!(!made.status.success(), "{}", said(&made));
    assert!(
        !String::from_utf8_lossy(&made.stdout).contains(" 1. "),
        "words were shown for a key that was never going to be written: {}",
        said(&made)
    );

    let restored = wallet(&["restore", text(&key)], &format!("{ABANDON_ART}\n"));
    assert!(!restored.status.success(), "{}", said(&restored));
    assert_eq!(
        std::fs::read_to_string(&key).unwrap(),
        "held\n",
        "and nothing was written over it"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// **`restore` takes no words from its command line, and does not repeat
/// them.**
#[test]
fn restore_refuses_words_on_its_command_line_without_repeating_them() {
    let home = scratch("command-line");
    let key = home.join("mine.key");
    let mut arguments = vec!["restore", text(&key)];
    arguments.extend(ABANDON_ART.split_whitespace());
    let refused = wallet(&arguments, "");
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(!key.exists());
    let told = said(&refused);
    assert!(told.contains("history"), "{told}");
    assert!(
        !told.contains("abandon"),
        "the refusal repeats a word of the phrase: {told}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// **A word not in the list, and words that do not fit together, are said
/// plainly and leave no key.**
#[test]
fn restore_says_which_word_is_wrong_or_that_the_check_fails() {
    let home = scratch("wrong-words");
    let key = home.join("mine.key");

    let mut words: Vec<&str> = ABANDON_ART.split_whitespace().collect();
    words[4] = "abandn";
    let misspelt = wallet(&["restore", text(&key)], &words.join(" "));
    assert!(!misspelt.status.success());
    assert!(
        said(&misspelt).contains("word 5 is not one of"),
        "{}",
        said(&misspelt)
    );
    assert!(!key.exists());

    let mut words: Vec<&str> = ABANDON_ART.split_whitespace().collect();
    words[23] = "zoo";
    let unfit = wallet(&["restore", text(&key)], &words.join(" "));
    assert!(!unfit.status.success());
    assert!(
        said(&unfit).contains("do not fit together"),
        "{}",
        said(&unfit)
    );
    assert!(!key.exists());

    let short = wallet(&["restore", text(&key)], "abandon abandon abandon\n");
    assert!(!short.status.success());
    assert!(said(&short).contains("that is 3 words"), "{}", said(&short));
    assert!(!key.exists());
    let _ = std::fs::remove_dir_all(&home);
}

/// **What the words do not bring back is said where they are made and where
/// they are used.**
///
/// The finding of `audit_what_a_restore_on_a_new_machine_finds`: money that
/// fell out of the set every node holds before the last few blocks is found
/// with history.dat, or by `recover` reading the whole chain again, and both
/// are named.
#[test]
fn new_and_restore_say_the_words_do_not_carry_the_account() {
    let home = scratch("account");
    let made = wallet(
        &["new", text(&home.join("a.key")), "--unsafe-skip-word-check"],
        "",
    );
    let restored = wallet(
        &["restore", text(&home.join("b.key"))],
        &format!("{ABANDON_ART}\n"),
    );
    for output in [&made, &restored] {
        let told = said(output)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(output.status.success(), "{told}");
        assert!(
            told.contains("found with history.dat"),
            "what the words leave behind is not said: {told}"
        );
        assert!(told.contains("cairn-wallet recover"), "{told}");
        assert!(told.contains("cairn-wallet backup"), "{told}");
    }
    let _ = std::fs::remove_dir_all(&home);
}
