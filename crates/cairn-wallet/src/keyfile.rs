//! Keeping a secret key in a file.
//!
//! One key, written as hexadecimal, one line. Plain text on purpose: the point
//! of a key file is that its owner can read it, copy it, and print it onto
//! paper, and an encrypted format that only this program understands would take
//! that away without adding anything a filesystem permission does not.
//!
//! The key still passes through memory here, as bytes on one side and as
//! hexadecimal on the other, and a buffer that is merely freed keeps what it
//! held until something else claims that memory. Both are wiped before they
//! are released, so that a core dump, a page written out to swap, or the next
//! allocation handed the same address finds zeroes. Two gaps stay open and are
//! worth naming rather than hiding: a value returned from another crate has
//! already been written to a stack slot this module cannot name, and the
//! hexadecimal parser builds a vector of its own that it frees itself. Closing
//! either means changing `cairn-primitives`, and neither of them outlives the
//! process the way a file does.
//!
//! There was a third, and naming two of them is what kept it out of sight: a
//! list of what cannot be closed reads as a list of everywhere the key goes.
//! The one place outside [`read`] that opens a key file is the refusal
//! [`write`] gives when one is already there, which reads it to tell an empty
//! file from a full one, and the full one is the key holding the money. It
//! read into a buffer nothing wiped. That one closes in this module, so it is
//! closed; [`whitespace_only`] is where a key file is read outside [`read`],
//! and it is the only such place because it is now the only one there is a
//! name for.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use cairn_crypto::SecretKey;
use zeroize::Zeroizing;

/// Reads a key file.
///
/// Two things are checked before the contents are believed, and both are
/// things a person cannot be expected to work out from a parse failure. A file
/// that is there and empty is what a write that never finished leaves behind,
/// and the message has to say to delete it, because refusing to overwrite it
/// is the other half of this module and the two together are a trap. And a
/// file anyone with an account on this machine can read is a key anyone with
/// an account on this machine has: that is what restoring from a backup, or
/// copying off a memory stick, or a `chmod` down a whole directory, leaves.
pub fn read(path: &Path) -> Result<SecretKey, String> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
    );
    // Emptiness is settled first. A file with no key in it holds nothing worth
    // protecting, and telling somebody to tighten the permissions on it would
    // send them round the same loop the message below exists to break.
    if text.trim().is_empty() {
        return Err(format!(
            "{} is empty: it holds no key at all. A file left like this is what a write that \
             never finished leaves behind, so there is nothing in it to lose. Delete it and run \
             `cairn-wallet new` again. If money was ever paid to an address made from this file, \
             the key for it is only in a copy you took yourself.",
            path.display()
        ));
    }
    guard_the_mode(path)?;
    let bytes = key_bytes(&text).ok_or_else(|| {
        format!(
            "{} is not a key file: a key file holds 64 hexadecimal characters on one line, and \
             this holds something else. Check that it is the file you meant.",
            path.display()
        )
    })?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Refuses a key file other people on this machine can read.
///
/// A warning would be the softer answer and it would be the wrong one: the
/// warning goes past once, the file stays readable for as long as the wallet
/// is used, and whoever else has an account here has had the money the whole
/// time. Refusing costs one command, and the message is that command.
#[cfg(unix)]
fn guard_the_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    let mode = metadata.permissions().mode() & 0o777;
    // The group and other bits. Clippy would rather this counted trailing
    // zeroes, which is the same test written so that nobody reading it can see
    // it is about permissions.
    #[allow(clippy::verbose_bit_mask)]
    if mode & 0o077 == 0 {
        return Ok(());
    }
    Err(format!(
        "{} can be read by other accounts on this machine, and anyone who reads it holds the \
         money. Its permissions are {mode:04o} and they have to be 0600. Run `chmod 600 {}` and \
         try again. If this machine is shared, treat the key as one somebody else may already \
         have and move the money to a new one.",
        path.display(),
        path.display()
    ))
}

/// The same, where there is no mode to read.
///
/// Windows decides who may read a file by an access control list inherited
/// from the directory, which is the state of affairs `create_private` sets out
/// at length. There is nothing here to check that would mean anything.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn guard_the_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// What this platform could not be asked about a key file, if anything.
///
/// On Unix there is nothing to say: [`read`] refuses a key file other accounts
/// can read, so either it is private or the wallet did not open. Everywhere
/// else there is no mode to read, and the reasoning about that was written on
/// `create_private`, in a doc comment, which is the one place the person whose
/// money it is will never look. A guard that answers `Ok(())` where it means
/// "not checked" is the same sentence said to the compiler instead of to them.
///
/// So this is that sentence, addressed to them, and it is a statement rather
/// than a refusal because refusing would be a claim as well: nothing here
/// knows that the directory is shared, only that nothing asked.
#[must_use]
pub const fn what_was_not_checked() -> Option<&'static str> {
    #[cfg(unix)]
    {
        None
    }
    #[cfg(not(unix))]
    {
        Some(
            "This platform has no file mode for this wallet to check, so it has not checked \
             one. A key file here is exactly as private as the folder it sits in: under your \
             own user profile that means you, the system and the administrators, which is the \
             intent. In a folder several accounts share it means whoever that folder lets in, \
             and anyone who can read the file holds the money. Keep it under your own profile.",
        )
    }
}

/// Writes a key file, refusing to overwrite one that already exists.
///
/// Overwriting a key file destroys the only copy of whatever it held, so it is
/// never done implicitly.
///
/// The file is created private and refused if it is already there, both in the
/// one call that creates it. Writing it first and restricting it afterwards
/// would leave a moment where anyone with an account on the machine could read
/// the key, and checking that it is absent before writing would leave a moment
/// where something else could create it in between. How much private is worth
/// on a given platform is said at `create_private`.
///
/// And it is on the disk before this returns, which is not what writing a file
/// means. `File::flush` is documented to do nothing at all, because a `File`
/// holds no buffer of its own to flush: what it leaves behind is bytes the
/// kernel will write out at some point in the next few seconds. That is fine
/// for a cache and it is not fine here. A person runs this, reads the address
/// off the screen, gives it to somebody who pays it, and loses power inside
/// that window; the money is then at an address whose key was never written
/// down. So the file is synced, and on Unix the directory holding it is synced
/// too, because a file whose name has not reached the disk is a file that is
/// not there.
pub fn write(path: &Path, secret: &SecretKey) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            make_private_directory(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }

    let mut file = create_private(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return already_there(path);
        }
        format!("could not write {}: {error}", path.display())
    })?;

    // The newline goes out in a call of its own rather than being appended to
    // the key. A string holding the key that has to grow leaves its old buffer
    // behind, freed and unwiped, with nothing left pointing at it to wipe.
    let text = key_hex(secret);
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    drop(file);

    if let Err(error) = written {
        // What is on the disk now is a file holding part of a key or none of
        // it, under the name the next attempt will refuse to touch. Taking it
        // away loses nothing, because nothing usable was ever in it, and
        // leaving it turns a full disk into a wallet that cannot be made.
        let _ = std::fs::remove_file(path);
        return Err(format!(
            "could not write {}: {error}. Nothing was left behind, so there is a name free to \
             try again at.",
            path.display()
        ));
    }

    if let Err(error) = sync_the_directory(path) {
        return Err(format!(
            "{} was written but this machine would not confirm it: {error}. Check the file is \
             there before giving out the address it names.",
            path.display()
        ));
    }
    Ok(())
}

/// Where a backup put the two files a wallet is made of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackedUp {
    /// The copy of the key file.
    pub key: PathBuf,
    /// The copy of the account.
    pub account: PathBuf,
}

/// Copies a key file and the account beside it into one directory, together.
///
/// A wallet is two files and they live apart: the key wherever its owner put
/// it, the account in the data directory. The key spends the money. The
/// account is the only record of where a note that has fallen out of the set
/// every node holds now sits, and without it that money cannot be found by
/// this wallet, by an archivist or by anybody, because the set is a list of
/// hashes with no owner attached. A restore from the key alone finds only
/// what is still in the set every node holds, so a backup is both files or
/// it is not a backup, and a key with no account beside it is refused rather
/// than copied on its own.
///
/// Neither copy is ever written over, and both names are checked before
/// either is written, so a refusal leaves nothing behind: in particular no
/// copy of the key, written and then removed, in the free space of a memory
/// stick. The key is read the way the wallet reads it, so what is copied is a
/// key and a private one, and it is written the way `new` writes one. A
/// directory this makes is its owner's alone; one already there is left as
/// its owner set it.
pub fn back_up(key: &Path, data: &Path, into: &Path) -> Result<BackedUp, String> {
    let secret = read(key)?;
    let account = data.join(crate::HISTORY_FILE);
    let held = match std::fs::read(&account) {
        Ok(held) => held,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{} holds no {}, which is the account this wallet starts the first time it \
                 reads the chain. A key without it is half of a backup, so nothing was copied. \
                 Run the wallet with this --data first (`cairn-wallet balance` does), then back \
                 up.",
                data.display(),
                crate::HISTORY_FILE
            ))
        }
        Err(error) => return Err(format!("could not read {}: {error}", account.display())),
    };
    let named = key
        .file_name()
        .ok_or_else(|| format!("{} does not name a file", key.display()))?;
    let copies = BackedUp {
        key: into.join(named),
        account: into.join(crate::HISTORY_FILE),
    };
    for copy in [&copies.key, &copies.account] {
        if std::fs::symlink_metadata(copy).is_ok() {
            return Err(format!(
                "{} is already there, and a backup never writes over a file: the copy it \
                 would replace is the one you would need if this one went wrong. Name a \
                 directory that holds neither file.",
                copy.display()
            ));
        }
    }
    make_private_directory(into)
        .map_err(|error| format!("could not create {}: {error}", into.display()))?;
    write(&copies.key, &secret)?;
    if let Err(error) = write_private(&copies.account, &held) {
        // The key copy is this call's own, made a moment ago, and a key with
        // no account beside it is the half backup this refuses to leave.
        let _ = std::fs::remove_file(&copies.key);
        return Err(format!(
            "could not write {}: {error}. Nothing was left behind.",
            copies.account.display()
        ));
    }
    Ok(copies)
}

/// Writes bytes that are nobody else's business to a file made new for them,
/// and makes them durable.
///
/// A file this made and could not finish is taken away again; one that was
/// already at the name is not touched, because the call that creates the file
/// refuses it.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = create_private(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if written.is_err() {
        let _ = std::fs::remove_file(path);
    }
    written?;
    sync_the_directory(path)
}

/// What to say about a key file that is already where one was asked for.
///
/// An empty one is the case worth telling apart. That is what a write cut off
/// by a full disk or a power cut leaves, and the plain refusal sends whoever
/// hit it round a loop: writing says the file is already there, reading says
/// it is not a key, and neither says the file is empty and can go.
fn already_there(path: &Path) -> String {
    if whitespace_only(path) {
        return format!(
            "{} is already there and it is empty: it holds no key. That is what a write that \
             never finished leaves behind, and there is nothing in it to lose. Delete it and run \
             this again.",
            path.display()
        );
    }
    format!(
        "{} already exists; move it aside if you really mean to replace it. Whatever is in it is \
         the only copy, so replacing it would destroy the money it holds.",
        path.display()
    )
}

/// Whether a file holds nothing but whitespace.
///
/// The only place outside [`read`] that opens a key file, and it is a named
/// place so that it stays the only one. What it is asked is whether the file
/// is empty; what it has in its hands while answering is whatever the file
/// holds, which on the branch that matters is the key somebody is about to be
/// told not to overwrite. So it wipes it, like everything else here that has
/// held a key, rather than leaving the one buffer in this module that did not.
fn whitespace_only(path: &Path) -> bool {
    std::fs::read(path)
        .map(Zeroizing::new)
        .is_ok_and(|held| held.iter().all(u8::is_ascii_whitespace))
}

/// Makes the file's name durable, where the platform has a way to say so.
///
/// Unix has one: syncing the directory itself. Windows will not open a
/// directory as a file, so there it is left as it is, which is the same
/// position `cairn-store` records for the same reason.
#[cfg(unix)]
pub(crate) fn sync_the_directory(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    match parent {
        Some(parent) => std::fs::File::open(parent)?.sync_all(),
        None => std::fs::File::open(".")?.sync_all(),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sync_the_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Makes a directory, and any above it that are missing, readable by its
/// owner alone.
///
/// One already there is left as it is: its mode was somebody's choice. One
/// this program makes is this program's choice, and a directory made at the
/// umask to hold a key tells every account on the machine that this one holds
/// a wallet, and what its file is called. Where there is no mode to ask for,
/// the directory takes the access control of the one it is made in, as a key
/// file does.
fn make_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Makes a file new at `path`, private to its owner, taking away whatever
/// stood at that name first.
///
/// For the two files this wallet writes again every run beside the chain: the
/// account's partial file and the page's link. Both were opened in place,
/// which follows a symbolic link standing at the name, and truncated, which
/// empties whatever the link names. A link planted in the data directory, or
/// brought back by a restore, chose the file the account or the spending token
/// went into and emptied it first, the key file included.
///
/// So the name is cleared, and the file is made by the call that refuses one
/// already there, which a link planted in between is. The mode comes from that
/// same call, as the key file's does, so there is no file left from an earlier
/// run to carry a mode it was widened to in the meantime.
pub(crate) fn create_anew(path: &Path) -> std::io::Result<std::fs::File> {
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    create_private(path)
}

/// The key as the file spells it, in a buffer that wipes itself on the way out.
fn key_hex(secret: &SecretKey) -> Zeroizing<String> {
    let bytes = Zeroizing::new(secret.to_bytes());
    Zeroizing::new(cairn_primitives::hex::encode(bytes.as_slice()))
}

/// The key a file spells, in a buffer that wipes itself on the way out.
fn key_bytes(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    cairn_primitives::hex::decode_array::<32>(text.trim()).map(Zeroizing::new)
}

/// Creates a file only its owner can read, and only if it is not there yet.
#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// The same on Windows, as far as the standard library reaches.
///
/// There is no mode to ask for. Who may read a file is decided by an access
/// control list, and a new file inherits the one of the directory it is made
/// in: under the owner's own profile that is the owner, the system and the
/// administrators, which is the intent, but in a directory several accounts
/// share it is whatever that directory hands out, up to everyone. Handing a
/// list of our own to the call that creates the file means building a security
/// descriptor, which the standard library does not expose and which would cost
/// this program a binding to the Win32 security API. The dependency tree is a
/// promise this project makes, so the honest statement is the one to prefer: on
/// Windows the key is exactly as private as the directory it is put in, and
/// putting it outside a profile makes it readable by everyone with an account.
///
/// What is left to do is refuse to share the handle, so that nothing can open
/// the file between its creation and the moment the key is fully written. That
/// is a window closed, not a wall built.
#[cfg(windows)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path)
}

/// The same, on a platform with no say over who may read what it creates.
#[cfg(not(any(unix, windows)))]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    /// A platform this wallet cannot ask has to say that it did not ask.
    ///
    /// Held on every platform rather than on the one it is about, because the
    /// shape is the claim: on Unix `read` refuses outright, so there is
    /// nothing left to say, and anywhere else the silence was the defect.
    #[test]
    fn a_platform_with_no_mode_to_read_says_so() {
        let said = what_was_not_checked();
        if cfg!(unix) {
            assert!(
                said.is_none(),
                "on Unix a key file other accounts can read is refused, so there is \
                 nothing left for this to warn about: {said:?}"
            );
        } else {
            let said =
                said.expect("this platform checked no mode and told nobody it had not checked");
            assert!(
                said.contains("as private as the folder"),
                "the one thing the person has to know is what the file's privacy \
                 actually rests on here: {said}"
            );
        }
    }

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("cairn-keyfile-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn a_key_survives_a_round_trip() {
        let path = scratch("roundtrip").join("key");
        let secret = SecretKey::from_bytes(&[9; 32]);
        write(&path, &secret).unwrap();

        let read_back = read(&path).unwrap();
        assert_eq!(read_back.to_bytes(), secret.to_bytes());
        assert_eq!(read_back.public_key(), secret.public_key());
    }

    /// The question the one other reader of a key file is asked.
    ///
    /// What wipes its buffer is the type it reads into, which no test can
    /// watch: a wipe leaves nothing behind by definition, and a test that
    /// claimed to see one would be reading a freed allocation. What is
    /// testable is that it still answers the question `already_there` puts to
    /// it, which is the half a change could break while the type went on
    /// looking right.
    #[test]
    fn a_file_of_whitespace_is_told_from_a_file_with_a_key_in_it() {
        let directory = scratch("whitespace");
        std::fs::create_dir_all(&directory).unwrap();

        let empty = directory.join("empty");
        std::fs::write(&empty, "").unwrap();
        assert!(whitespace_only(&empty));

        let blank = directory.join("blank");
        std::fs::write(&blank, "\n  \t\r\n").unwrap();
        assert!(whitespace_only(&blank), "a write cut off leaves this too");

        let held = directory.join("key");
        write(&held, &SecretKey::from_bytes(&[5; 32])).unwrap();
        assert!(
            !whitespace_only(&held),
            "this is the branch that matters: the file holds the money"
        );

        assert!(
            !whitespace_only(&directory.join("missing")),
            "a file that is not there is not an empty one, and saying it was \
             would tell somebody to delete a name that holds nothing"
        );
    }

    #[test]
    fn an_existing_key_is_never_overwritten() {
        let path = scratch("existing").join("key");
        write(&path, &SecretKey::from_bytes(&[1; 32])).unwrap();
        let outcome = write(&path, &SecretKey::from_bytes(&[2; 32]));
        assert!(outcome.is_err(), "the first key is still the one on disk");
        assert_eq!(read(&path).unwrap().to_bytes(), [1; 32]);
    }

    #[test]
    fn a_file_that_is_not_a_key_is_reported() {
        let directory = scratch("garbage");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("key");
        std::fs::write(&path, "hello").unwrap();
        // Private, so what is being tested is the contents and not the mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let read_back = read(&path).unwrap_err();
        assert!(read_back.contains("not a key file"), "{read_back}");
        assert!(read(&directory.join("missing")).is_err());
    }

    /// The key and the newline leave in two writes, and what a person prints
    /// out has to be the one line the format promises all the same.
    #[test]
    fn a_key_file_is_one_line_and_nothing_more() {
        let path = scratch("shape").join("key");
        let secret = SecretKey::from_bytes(&[3; 32]);
        write(&path, &secret).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            format!("{}\n", cairn_primitives::hex::encode(&secret.to_bytes()))
        );
    }

    /// Whether a freed buffer still holds the key is not something a test can
    /// go and look at: reading memory that has been given back is undefined,
    /// and this workspace forbids the `unsafe` it would take to try. What can
    /// be held to is the type, and the day either of these hands back a plain
    /// `String` or a bare array instead, this stops compiling.
    #[test]
    fn the_buffers_that_carry_the_key_wipe_themselves() {
        let secret = SecretKey::from_bytes(&[4; 32]);

        let text: Zeroizing<String> = key_hex(&secret);
        assert_eq!(*text, cairn_primitives::hex::encode(&secret.to_bytes()));

        let bytes: Zeroizing<[u8; 32]> = key_bytes(&text).unwrap();
        assert_eq!(*bytes, secret.to_bytes());
    }

    /// Never readable by anyone else, including for the instant between being
    /// created and being restricted. A key that was world readable for one
    /// moment on a shared machine was world readable.
    #[cfg(unix)]
    #[test]
    fn a_key_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch("permissions").join("key");
        write(&path, &SecretKey::from_bytes(&[5; 32])).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // The mode comes from the creation itself, so a umask that would
        // otherwise widen it has nothing to widen.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.trim().len(), 64, "and it still holds the key");
    }

    /// A directory made to hold a key is its owner's alone.
    ///
    /// It was made at the umask, `0755` on most machines, so
    /// `cairn-wallet new ~/wallets/alice.key` told every account on the machine
    /// that this one holds a Cairn wallet and what its file is called. The key
    /// inside was private, and nothing asked about the directory around it.
    #[cfg(unix)]
    #[test]
    fn a_directory_made_to_hold_a_key_is_its_owner_s_alone() {
        use std::os::unix::fs::PermissionsExt;

        let top = scratch("directory");
        let wallets = top.join("wallets");
        let path = wallets.join("alice").join("key");
        write(&path, &SecretKey::from_bytes(&[8; 32])).unwrap();
        for made in [wallets.clone(), wallets.join("alice")] {
            let mode = std::fs::metadata(&made).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "a directory made to hold a key is open to other accounts"
            );
        }
    }

    /// A key file named without a directory is made durable in the directory
    /// it is written to, which is the one the wallet was started in.
    ///
    /// No test named a key file without a directory, so a sync that read the
    /// directory the wrong way round passed: for every path the tests used it
    /// synced the current directory in place of the right one, which succeeds.
    /// Given a bare name it asks for a directory with no name at all, and
    /// `write` then tells somebody whose key is safely on disk that the machine
    /// would not confirm it.
    #[test]
    fn a_key_named_without_a_directory_is_made_durable_where_it_is_written() {
        assert!(
            sync_the_directory(Path::new("key")).is_ok(),
            "a key file named on its own lives in the directory the wallet runs \
             in, and syncing that directory was refused"
        );
    }

    /// A key file whose directory will not confirm it is not reported as
    /// written.
    ///
    /// The address a new key makes is read off the screen and given out, so
    /// "written" has to mean on the disk under its name. Nothing held that to
    /// the directory: a write that skipped syncing it, or synced some other
    /// directory, passed every test, because every directory the tests used
    /// answered.
    ///
    /// A directory that lets files be made in it and cannot itself be opened
    /// is one that will not answer. Somebody who can read anything reads this
    /// one too, so under root there is nothing to refuse and the test says so
    /// by returning early.
    #[cfg(unix)]
    #[test]
    fn a_key_whose_directory_will_not_confirm_it_is_not_called_written() {
        use std::os::unix::fs::PermissionsExt;

        let sealed = scratch("unconfirmed").join("sealed");
        std::fs::create_dir_all(&sealed).unwrap();
        let mode = |bits| std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(bits));
        mode(0o300).unwrap();
        if std::fs::File::open(&sealed).is_ok() {
            mode(0o700).unwrap();
            return;
        }

        let outcome = write(&sealed.join("key"), &SecretKey::from_bytes(&[6; 32]));
        mode(0o700).unwrap();
        let said = outcome.expect_err(
            "a key file whose directory would not be synced was reported as written, \
             and its address would be given out",
        );
        assert!(said.contains("would not confirm it"), "{said}");
        assert!(
            said.contains("Check the file is there"),
            "and the person is told what to do before giving the address out: {said}"
        );
    }

    /// Windows has no mode to read back, so what is checked is the whole of
    /// what the standard library can promise there: while the handle writing
    /// the key is open, nobody else gets one. Everything past that instant is
    /// the directory's access control list, which this program does not set.
    #[cfg(windows)]
    #[test]
    fn a_key_file_is_nobody_elses_while_it_is_written() {
        let directory = scratch("sharing");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("key");

        let held = create_private(&path).unwrap();
        assert!(
            std::fs::read_to_string(&path).is_err(),
            "the key cannot be read out from under the write that is putting it there"
        );
        drop(held);
        assert!(
            std::fs::read_to_string(&path).is_ok(),
            "and its owner reads it once the write is done"
        );
    }
}
