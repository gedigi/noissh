//! Configuration: key storage, known_hosts, authorized_keys, file layout.

use std::fs;
use std::path::{Path, PathBuf};

use auth::{AuthorizedKeys, KnownHosts};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use noise_core::{Keypair, generate_keypair};

use crate::RuntimeError;

/// The noissh config directory (`$XDG_CONFIG_HOME/noissh` or `~/.config/noissh`).
pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Path::new(&xdg).join("noissh");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".config").join("noissh")
}

/// Load a static keypair from `path`, or generate and persist one on first use.
/// File format: two lines, `private <base64>` and `public <base64>`.
pub fn load_or_generate_keypair(path: &Path) -> Result<Keypair, RuntimeError> {
    if path.exists() {
        // Tighten an over-permissive key file before reading it (defends against
        // a key left group/world-readable by an older version or bad umask).
        tighten_if_loose(path);
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
        write_private(path, body.as_bytes())?;
        Ok(kp)
    }
}

/// Write a private file, creating it with `0600` atomically so the secret is
/// never momentarily world-readable (no write-then-chmod window).
#[cfg(unix)]
fn write_private(path: &Path, body: &[u8]) -> Result<(), RuntimeError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body)?;
    f.sync_all()?; // durably persist the key before returning
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, body: &[u8]) -> Result<(), RuntimeError> {
    fs::write(path, body)?;
    Ok(())
}

/// If `path` is group/other-accessible, restrict it to `0600`.
#[cfg(unix)]
fn tighten_if_loose(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
fn tighten_if_loose(_path: &Path) {}

/// Load known_hosts (empty if the file does not exist).
pub fn load_known_hosts(path: &Path) -> Result<KnownHosts, RuntimeError> {
    if path.exists() {
        Ok(KnownHosts::parse(&fs::read_to_string(path)?))
    } else {
        Ok(KnownHosts::new())
    }
}

/// Persist known_hosts atomically: write a sibling temp file, fsync it, then
/// rename it into place. A crash mid-write can therefore never truncate or
/// corrupt the existing pin file (which would silently re-enable TOFU and weaken
/// the man-in-the-middle protection).
pub fn save_known_hosts(path: &Path, kh: &KnownHosts) -> Result<(), RuntimeError> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(kh.to_text().as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
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

/// Path to the optional config file (`<config_dir>/config`).
pub fn config_file_path() -> PathBuf {
    config_dir().join("config")
}

/// Parsed config-file settings. All fields are optional so callers can fall
/// back to their own defaults; the file itself is optional too.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Default UDP port for direct connections.
    pub port: Option<u16>,
}

/// Parse a simple config file. The format is one setting per line as either
/// `key = value` or `key value`. Blank lines and lines beginning with `#`
/// (after optional leading whitespace) are ignored. Unknown keys and lines
/// that fail to parse are ignored, so a malformed file never aborts startup.
///
/// A missing file returns [`Config::default`].
pub fn load_config(path: &Path) -> Config {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Config::default(),
    };
    let mut cfg = Config::default();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Accept either `key = value` or `key value`. Split on the first `=`
        // if present, otherwise on the first run of whitespace.
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => match line.split_once(char::is_whitespace) {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue, // a bare key with no value: nothing to set
            },
        };
        if value.is_empty() {
            continue;
        }
        // Only `port` is recognized today; unknown keys are ignored so a config
        // written for a newer version never aborts startup.
        if key == "port"
            && let Ok(p) = value.parse::<u16>()
        {
            cfg.port = Some(p);
        }
    }
    cfg
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

    fn write_temp_config(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "noissh-config-test-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config");
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn config_parses_valid_lines_both_separators() {
        // Both `key = value` and `key value` separators work; unknown keys ignored.
        let path = write_temp_config("valid", "port = 2222\nterm xterm-256color\n");
        let cfg = load_config(&path);
        assert_eq!(cfg.port, Some(2222));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn config_ignores_comments_and_blank_lines() {
        let body = "# a comment\n\n   \n  # indented comment\nport=51820\n";
        let path = write_temp_config("comments", body);
        let cfg = load_config(&path);
        assert_eq!(cfg.port, Some(51820));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn config_missing_file_returns_default() {
        let path = std::env::temp_dir().join("noissh-config-test-does-not-exist-xyz/config");
        let cfg = load_config(&path);
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.port, None);
    }

    #[test]
    fn config_ignores_bad_and_unknown_lines() {
        // Bad port value, unknown key, bare key with no value, and a junk line
        // are all skipped without aborting the parse.
        let body = "port = not-a-number\nunknown = whatever\nbareword\n=novalue\n";
        let path = write_temp_config("bad", body);
        let cfg = load_config(&path);
        assert_eq!(cfg.port, None); // bad value ignored, no default applied here
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn config_file_path_is_under_config_dir() {
        assert_eq!(config_file_path(), config_dir().join("config"));
    }
}
