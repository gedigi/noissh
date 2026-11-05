//! Configuration: key storage, known_hosts, authorized_keys, file layout.

use std::fs;
use std::path::{Path, PathBuf};

use auth::{AuthorizedKeys, KnownHosts};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use noise_core::{Keypair, generate_keypair, public_from_private};

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

/// The public-key file that accompanies the private key file `path`:
/// `<path>.pub` (e.g. `id` → `id.pub`), as with ssh.
pub fn public_key_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".pub");
    PathBuf::from(p)
}

/// Load a static keypair from `path`, or generate and persist one on first use.
///
/// As with ssh, a key lives in two files:
/// - `path` holds only the private key, as `private <base64>`, mode `0600`;
/// - `path.pub` holds the public key as an authorized_keys line,
///   `noissh-x25519 <base64> user@host`, so it can be appended to a server's
///   `authorized_keys` as is.
///
/// The public key is derived from the private one, so `path.pub` is a copy for
/// people and tools to read: it is written whenever it is missing and never
/// consulted when loading. A key file from noissh 0.6.0 or earlier, which holds both
/// halves (`private` and `public` lines), still loads, and is rewritten to hold
/// only the private key (with its `.pub` written alongside).
pub fn load_or_generate_keypair(path: &Path) -> Result<Keypair, RuntimeError> {
    if path.exists() {
        // Tighten an over-permissive key file before reading it (defends against
        // a key left group/world-readable by an older version or bad umask).
        tighten_if_loose(path);
        let contents = fs::read_to_string(path)?;
        let mut private = None;
        let mut legacy_public = None;
        for line in contents.lines() {
            let mut it = line.split_whitespace();
            match (it.next(), it.next()) {
                (Some("private"), Some(b64)) => {
                    private = Some(STANDARD.decode(b64).map_err(|_| RuntimeError::BadKeyFile)?)
                }
                (Some("public"), Some(b64)) => {
                    legacy_public =
                        Some(STANDARD.decode(b64).map_err(|_| RuntimeError::BadKeyFile)?)
                }
                _ => {}
            }
        }
        let private = private.ok_or(RuntimeError::BadKeyFile)?;
        let public = public_from_private(&private).ok_or(RuntimeError::BadKeyFile)?;
        // A legacy file's stored public half must be the one its private half
        // derives; anything else means the file is corrupt.
        if legacy_public.as_ref().is_some_and(|p| *p != public) {
            return Err(RuntimeError::BadKeyFile);
        }
        let kp = Keypair { private, public };
        if legacy_public.is_some() {
            // Migrate to the private-only format. Best-effort: the key works
            // either way, so a read-only directory must not stop a connection.
            if let Err(e) = rewrite_private(path, private_key_text(&kp).as_bytes()) {
                eprintln!(
                    "noissh: could not split the public key out of {}: {e}",
                    path.display()
                );
            }
        }
        ensure_public_key_file(path, &kp);
        Ok(kp)
    } else {
        let kp = generate_keypair()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_private(path, private_key_text(&kp).as_bytes())?;
        ensure_public_key_file(path, &kp);
        Ok(kp)
    }
}

/// The private key file's contents.
fn private_key_text(kp: &Keypair) -> String {
    format!("private {}\n", STANDARD.encode(&kp.private))
}

/// The comment ssh puts on a public key: `user@host`.
fn key_comment() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    let host = nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    match (user.is_empty(), host.is_empty()) {
        (false, false) => format!("{user}@{host}"),
        (false, true) => user,
        (true, false) => host,
        (true, true) => String::new(),
    }
}

/// Write `path.pub` for `kp` if it is missing; warn if one exists but holds a
/// different key (it is left alone: it may be the user's own file). Never
/// fails: the public key file is informational.
fn ensure_public_key_file(path: &Path, kp: &Keypair) {
    let Ok(public) = auth::PublicKey::from_bytes(&kp.public) else {
        return;
    };
    let pub_path = public_key_path(path);
    match fs::read_to_string(&pub_path) {
        Ok(existing) => {
            let matches = existing
                .lines()
                .any(|l| auth::PublicKey::from_text(l).is_ok_and(|k| k == public));
            if !matches {
                eprintln!(
                    "noissh: {} does not hold the public key of {}; the private key is \
                     used. Delete it to have it rewritten.",
                    pub_path.display(),
                    path.display()
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let comment = key_comment();
            let line = if comment.is_empty() {
                format!("{}\n", public.to_text())
            } else {
                format!("{} {comment}\n", public.to_text())
            };
            if let Err(e) = fs::write(&pub_path, line) {
                eprintln!("noissh: could not write {}: {e}", pub_path.display());
            }
        }
        Err(_) => {}
    }
}

/// Atomically replace the private file `path`: write a `0600` sibling temp
/// file, fsync it, then rename it into place, so the key is never lost or
/// momentarily world-readable.
fn rewrite_private(path: &Path, body: &[u8]) -> Result<(), RuntimeError> {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let result = write_private(&tmp, body).and_then(|()| Ok(fs::rename(&tmp, path)?));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
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

    fn key_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("noissh-key-test-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pub_line_key(path: &Path) -> auth::PublicKey {
        let text = fs::read_to_string(public_key_path(path)).unwrap();
        auth::PublicKey::from_text(text.trim()).unwrap()
    }

    #[test]
    fn new_key_is_split_into_private_and_public_files() {
        let dir = key_dir("split");
        let path = dir.join("id");
        let kp = load_or_generate_keypair(&path).unwrap();

        // `id`: the private key only, owner-only.
        let private_text = fs::read_to_string(&path).unwrap();
        assert!(private_text.starts_with("private "), "{private_text}");
        assert!(!private_text.contains("public"), "{private_text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // `id.pub`: an authorized_keys line for the same key.
        assert_eq!(dir.join("id.pub"), public_key_path(&path));
        let pubkey = pub_line_key(&path);
        assert_eq!(pubkey, auth::PublicKey::from_bytes(&kp.public).unwrap());

        // Reloading yields the same identity (public derived from private).
        let again = load_or_generate_keypair(&path).unwrap();
        assert_eq!(again.private, kp.private);
        assert_eq!(again.public, kp.public);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_combined_key_file_is_migrated() {
        let dir = key_dir("legacy");
        let path = dir.join("id");
        let kp = generate_keypair().unwrap();
        fs::write(
            &path,
            format!(
                "private {}\npublic {}\n",
                STANDARD.encode(&kp.private),
                STANDARD.encode(&kp.public)
            ),
        )
        .unwrap();

        let loaded = load_or_generate_keypair(&path).unwrap();
        assert_eq!(loaded.private, kp.private);
        assert_eq!(loaded.public, kp.public);
        let private_text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            private_text,
            format!("private {}\n", STANDARD.encode(&kp.private))
        );
        assert_eq!(
            pub_line_key(&path),
            auth::PublicKey::from_bytes(&kp.public).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "migrated key must stay owner-only");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_file_with_mismatched_public_half_is_rejected() {
        let dir = key_dir("mismatch");
        let path = dir.join("id");
        let a = generate_keypair().unwrap();
        let b = generate_keypair().unwrap();
        let body = format!(
            "private {}\npublic {}\n",
            STANDARD.encode(&a.private),
            STANDARD.encode(&b.public)
        );
        fs::write(&path, &body).unwrap();
        assert!(matches!(
            load_or_generate_keypair(&path),
            Err(RuntimeError::BadKeyFile)
        ));
        // A corrupt file is left exactly as it was.
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_public_file_is_recreated_and_a_foreign_one_left_alone() {
        let dir = key_dir("pubfile");
        let path = dir.join("noisshd_key");
        let kp = load_or_generate_keypair(&path).unwrap();
        let pub_path = public_key_path(&path);

        fs::remove_file(&pub_path).unwrap();
        load_or_generate_keypair(&path).unwrap();
        assert_eq!(
            pub_line_key(&path),
            auth::PublicKey::from_bytes(&kp.public).unwrap()
        );

        // Someone else's key in the .pub file is not overwritten; the private
        // key still decides the identity.
        let other = auth::PublicKey::from_bytes(&generate_keypair().unwrap().public).unwrap();
        fs::write(&pub_path, format!("{}\n", other.to_text())).unwrap();
        let loaded = load_or_generate_keypair(&path).unwrap();
        assert_eq!(loaded.public, kp.public);
        assert_eq!(pub_line_key(&path), other);
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
