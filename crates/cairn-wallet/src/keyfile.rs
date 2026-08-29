//! Keeping a secret key in a file.
//!
//! One key, written as hexadecimal, one line. Plain text on purpose: the point
//! of a key file is that its owner can read it, copy it, and print it onto
//! paper, and an encrypted format that only this program understands would take
//! that away without adding anything a filesystem permission does not.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use cairn_crypto::SecretKey;

/// Reads a key file.
pub fn read(path: &Path) -> Result<SecretKey, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let bytes = cairn_primitives::hex::decode_array::<32>(text.trim())
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
/// where something else could create it in between.
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

    let text = format!("{}\n", cairn_primitives::hex::encode(&secret.to_bytes()));
    file.write_all(text.as_bytes())
        .and_then(|()| file.flush())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
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

/// The same, on a platform with no say over the mode a file is created with.
#[cfg(not(unix))]
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
}
