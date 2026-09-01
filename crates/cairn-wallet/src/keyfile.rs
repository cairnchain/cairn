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

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

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
            std::fs::create_dir_all(parent)
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

/// What to say about a key file that is already where one was asked for.
///
/// An empty one is the case worth telling apart. That is what a write cut off
/// by a full disk or a power cut leaves, and the plain refusal sends whoever
/// hit it round a loop: writing says the file is already there, reading says
/// it is not a key, and neither says the file is empty and can go.
fn already_there(path: &Path) -> String {
    if std::fs::read(path).is_ok_and(|held| held.iter().all(u8::is_ascii_whitespace)) {
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

/// Makes the file's name durable, where the platform has a way to say so.
///
/// Unix has one: syncing the directory itself. Windows will not open a
/// directory as a file, so there it is left as it is, which is the same
/// position `cairn-store` records for the same reason.
#[cfg(unix)]
fn sync_the_directory(path: &Path) -> std::io::Result<()> {
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
fn sync_the_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
