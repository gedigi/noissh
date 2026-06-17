//! Configuration: key storage, known_hosts, authorized_keys, file layout.

use std::fs;
use std::path::{Path, PathBuf};

use auth::{AuthorizedKeys, KnownHosts};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use noise_core::{generate_keypair, Keypair};

use crate::RuntimeError;

/// The noissh config directory (`$XDG_CONFIG_HOME/noissh` or `~/.config/noissh`).
pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Path::new(&xdg).join("noissh");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".config").join("noissh")
}

/// Load a static keypair from `path`, or generate and persist one on first use.
/// File format: two lines, `private <base64>` and `public <base64>`.
pub fn load_or_generate_keypair(path: &Path) -> Result<Keypair, RuntimeError> {
    if path.exists() {
        let contents = fs::read_to_string(path)?;
        let mut private = None;
        let mut public = None;
        for line in contents.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next()) {
                (Some("private"), Some(b64)) => {
                    private = Some(STANDARD.decode(b64).map_err(|_| RuntimeError::BadKeyFile)?)
                }
                (Some("public"), Some(b64)) => {
                    public = Some(STANDARD.decode(b64).map_err(|_| RuntimeError::BadKeyFile)?)
                }
                _ => {}
            }
        }
        match (private, public) {
            (Some(private), Some(public)) => Ok(Keypair { private, public }),
            _ => Err(RuntimeError::BadKeyFile),
        }
    } else {
        let kp = generate_keypair()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = format!(
            "private {}\npublic {}\n",
            STANDARD.encode(&kp.private),
            STANDARD.encode(&kp.public)
        );
        fs::write(path, body)?;
        set_private_perms(path);
        Ok(kp)
    }
}

#[cfg(unix)]
fn set_private_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_perms(_path: &Path) {}

/// Load known_hosts (empty if the file does not exist).
pub fn load_known_hosts(path: &Path) -> Result<KnownHosts, RuntimeError> {
    if path.exists() {
        Ok(KnownHosts::parse(&fs::read_to_string(path)?)?)
    } else {
        Ok(KnownHosts::new())
    }
}

/// Persist known_hosts.
pub fn save_known_hosts(path: &Path, kh: &KnownHosts) -> Result<(), RuntimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, kh.to_text())?;
    Ok(())
}

/// Load authorized_keys (empty if the file does not exist).
pub fn load_authorized_keys(path: &Path) -> Result<AuthorizedKeys, RuntimeError> {
    if path.exists() {
        Ok(AuthorizedKeys::parse(&fs::read_to_string(path)?))
    } else {
        Ok(AuthorizedKeys::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_persists_and_reloads() {
        let dir = std::env::temp_dir().join(format!("noissh-cfg-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("id");
        let _ = fs::remove_file(&path);
        let k1 = load_or_generate_keypair(&path).unwrap();
        let k2 = load_or_generate_keypair(&path).unwrap();
        assert_eq!(k1.private, k2.private);
        assert_eq!(k1.public, k2.public);
        let _ = fs::remove_dir_all(&dir);
    }
}
