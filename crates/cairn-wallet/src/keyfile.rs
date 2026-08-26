//! Keeping a secret key in a file.
//!
//! One key, written as hexadecimal, one line. Plain text on purpose: the point
//! of a key file is that its owner can read it, copy it, and print it onto
//! paper, and an encrypted format that only this program understands would take
//! that away without adding anything a filesystem permission does not.

use std::path::Path;

use cairn_crypto::SecretKey;

/// Reads a key file.
pub(crate) fn read(path: &Path) -> Result<SecretKey, String> {
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
pub(crate) fn write(path: &Path, secret: &SecretKey) -> Result<(), String> {
    if path.exists() {
        return Err(format!(
            "{} already exists; move it aside if you really mean to replace it",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("could not create {}: {error}", parent.display()))?;
        }
    }

    let text = format!("{}\n", cairn_primitives::hex::encode(&secret.to_bytes()));
    std::fs::write(path, text)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    restrict(path)
}

/// Makes the file readable only by its owner, where the platform has a say.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), String> {
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn a_key_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch("permissions").join("key");
        write(&path, &SecretKey::from_bytes(&[5; 32])).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
