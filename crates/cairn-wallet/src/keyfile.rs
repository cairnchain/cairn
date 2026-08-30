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
pub fn read(path: &Path) -> Result<SecretKey, String> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?,
    );
    let bytes = key_bytes(&text)
        .ok_or_else(|| format!("{} does not hold 32 bytes of hexadecimal", path.display()))?;
    Ok(SecretKey::from_bytes(&bytes))
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
pub fn write(path: &Path, secret: &SecretKey) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }

    let mut file = create_private(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return format!(
                "{} already exists; move it aside if you really mean to replace it",
                path.display()
            );
        }
        format!("could not write {}: {error}", path.display())
    })?;

    // The newline goes out in a call of its own rather than being appended to
    // the key. A string holding the key that has to grow leaves its old buffer
    // behind, freed and unwiped, with nothing left pointing at it to wipe.
    let text = key_hex(secret);
    file.write_all(text.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.flush())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
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
        assert!(read(&path).is_err());
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
