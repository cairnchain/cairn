//! What an existing user's history file is worth after this release.
//!
//! `History::save` appends a hash of the body and `History::load` refuses
//! anything that does not carry one. A file written by the release before that
//! carries no stamp, so every wallet that updates meets this once. The refusal
//! is right and stays; what it must not do is happen in silence, because the
//! movements below where the rescan restarts do not come back and a wallet
//! that quietly forgot yesterday looks exactly like one that is wrong.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use cairn_crypto::{PublicKey, SecretKey};
use cairn_ledger::block::{Block, BlockHeader};
use cairn_ledger::note::{NetworkId, Note};
use cairn_ledger::transaction::CoinbaseTransaction;
use cairn_primitives::codec::Encode;
use cairn_primitives::{Amount, Hash32};
use cairn_wallet::history::{Discarded, History};

fn key(seed: u8) -> PublicKey {
    SecretKey::from_bytes(&[seed; 32]).public_key()
}

fn block(height: u64, to: PublicKey) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            network: NetworkId::TESTNET,
            height,
            previous: Hash32::ZERO,
            state_root: Hash32::ZERO,
            transactions_root: Hash32::ZERO,
            history: Hash32::ZERO,
            timestamp: 1_000 + height,
            difficulty: 1,
            total_work: u128::from(height),
            nonce: 0,
        },
        coinbase: CoinbaseTransaction::new(
            height,
            vec![Note::new(Amount::from_cairn("50").unwrap(), to)],
        ),
        transfers: Vec::new(),
    }
}

fn an_account(mine: PublicKey) -> History {
    let mut history = History::new();
    for height in 0..40 {
        history.take(&block(height, mine), mine);
    }
    history
}

fn scratch(name: &str) -> std::path::PathBuf {
    let directory =
        std::env::temp_dir().join(format!("cairn-zz-history-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory.join("history.dat")
}

/// The stamp is written and it is checked. Both halves.
#[test]
fn a_file_this_release_wrote_reads_back() {
    let mine = key(1);
    let path = scratch("roundtrip");
    let history = an_account(mine);
    history.save(&path).unwrap();

    let (read, why) = History::load(&path);
    assert_eq!(why, None, "a file it wrote itself is not news");
    assert_eq!(read.len(), 40);
    assert_eq!(read.next(), 40);
    assert_eq!(read.from(), Some(0));
}

/// A body changed under a stamped file is refused, and the wallet is told the
/// disk changed it rather than that it is simply old.
#[test]
fn a_changed_body_is_refused_and_named_as_changed() {
    let mine = key(1);
    let path = scratch("changed");
    an_account(mine).save(&path).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[9] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let (read, why) = History::load(&path);
    assert!(
        read.is_empty(),
        "a changed body is not served as an account"
    );
    assert_eq!(
        why,
        Some(Discarded::DidNotVerify),
        "the disk changed it, which is not the same news as an update"
    );
}

/// The file the previous release wrote is the encoded account and nothing
/// else, so it cannot verify. It is still refused, and it is now told apart
/// from a file the disk changed, because the two need different words: this
/// one happens once, to everybody, on the day they update.
#[test]
fn a_history_from_the_previous_release_is_discarded_and_said_so() {
    let mine = key(1);
    let path = scratch("unstamped");
    let history = an_account(mine);

    // Byte for byte what `save` wrote before the stamp existed:
    //     std::fs::write(&partial, self.encode())
    std::fs::write(&path, history.encode()).unwrap();

    let (read, why) = History::load(&path);
    assert!(read.is_empty(), "forty movements read back as none at all");
    assert_eq!(read.next(), 0, "and the account starts again from block 0");
    assert_eq!(read.from(), None);
    assert_eq!(
        why,
        Some(Discarded::BeforeTheStamp),
        "which is what turns a silent forgetting into a line the face shows"
    );
}

/// A wallet that has never run is not a wallet that lost something, and the
/// two must not produce the same line.
#[test]
fn a_wallet_that_never_ran_has_nothing_to_report() {
    let path = scratch("absent");
    let (read, why) = History::load(&path.with_extension("missing"));
    assert!(read.is_empty());
    assert_eq!(why, None);
}

/// Nothing reads an unstamped file once and rewrites it with a stamp, which
/// would be trusting bytes on the strength of their shape. The refusal is the
/// design; only the silence was the defect.
#[test]
fn nothing_migrates_an_unstamped_file() {
    let mine = key(1);
    let path = scratch("nomigration");
    an_account(mine).save(&path).unwrap();
    let stamped = std::fs::read(&path).unwrap();
    let body = &stamped[..stamped.len() - 32];
    std::fs::write(&path, body).unwrap();

    let (read, why) = History::load(&path);
    assert!(read.is_empty());
    assert_eq!(why, Some(Discarded::BeforeTheStamp));

    // The bytes decode perfectly well; it is only the stamp that is absent,
    // which is exactly why the shape alone is not evidence of anything.
    let mut reader = cairn_primitives::codec::Reader::new(body);
    let decoded = <History as cairn_primitives::codec::Decode>::decode_from(&mut reader);
    assert!(decoded.is_ok_and(|history| history.len() == 40));

    // And it stays refused on a second start, rather than being taken up by
    // the file the wallet writes over it.
    let (again, why_again) = History::load(&path);
    assert!(again.is_empty());
    assert_eq!(why_again, Some(Discarded::BeforeTheStamp));
}

/// A downgrade is not a damaged disk, and must not be reported as one.
///
/// A wallet that knows more fields writes a body this one cannot decode, and
/// stamps it. The stamp holds, which is the whole of the evidence: nothing
/// touched the file, this build is simply behind it. Telling somebody their
/// disk is suspect over that sends them looking at hardware that is fine.
#[test]
fn a_file_from_a_newer_wallet_is_named_as_newer_rather_than_as_damage() {
    use cairn_primitives::hash::{hash, Domain};

    let mine = key(1);
    let path = scratch("newer");

    // What a version with one more field would write: the body this build
    // knows, then something it does not, then the stamp over both.
    let mut body = an_account(mine).encode();
    body.extend_from_slice(&[0xab; 9]);
    let mut bytes = body.clone();
    bytes.extend_from_slice(hash(Domain::WalletHistory, &body).as_bytes());
    std::fs::write(&path, &bytes).unwrap();

    let (read, why) = History::load(&path);
    assert!(read.is_empty(), "it is not read, which is right");
    assert_eq!(
        why,
        Some(Discarded::FromANewerVersion),
        "the stamp held, so nothing changed the file"
    );
}
