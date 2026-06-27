#![forbid(unsafe_code)]
//! Authentication & trust model for noissh.
//!
//! - `authorized_keys`-equivalent: the set of client static public keys a
//!   server user permits.
//! - `known_hosts`-equivalent with TOFU (trust on first use): the client pins a
//!   server's static public key on first contact; a later mismatch is a hard
//!   failure, exactly like SSH.
//!
//! Keys are X25519 public keys in the text form `noissh-x25519 <base64>`.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use thiserror::Error;

/// The textual algorithm tag for noissh keys.
pub const KEY_TYPE: &str = "noissh-x25519";

/// Length of an X25519 public key.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("malformed key line")]
    MalformedLine,
    #[error("unknown key type {0:?}")]
    BadKeyType(String),
    #[error("base64 decode failed")]
    BadBase64,
    #[error("key must be {KEY_LEN} bytes, got {0}")]
    BadKeyLen(usize),
}

/// A 32-byte X25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() != KEY_LEN {
            return Err(AuthError::BadKeyLen(bytes.len()));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(bytes);
        Ok(PublicKey(k))
    }

    /// Parse from base64 (no algorithm tag).
    pub fn from_base64(b64: &str) -> Result<Self, AuthError> {
        let raw = STANDARD
            .decode(b64.trim())
            .map_err(|_| AuthError::BadBase64)?;
        PublicKey::from_bytes(&raw)
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Full text form: `noissh-x25519 <base64>`.
    pub fn to_text(&self) -> String {
        format!("{KEY_TYPE} {}", self.to_base64())
    }

    /// Parse `noissh-x25519 <base64> [comment...]` (comment ignored).
    pub fn from_text(line: &str) -> Result<Self, AuthError> {
        let mut it = line.split_whitespace();
        let ty = it.next().ok_or(AuthError::MalformedLine)?;
        if ty != KEY_TYPE {
            return Err(AuthError::BadKeyType(ty.to_string()));
        }
        let b64 = it.next().ok_or(AuthError::MalformedLine)?;
        PublicKey::from_base64(b64)
    }
}

/// The set of client keys a server user authorizes (`~/.config/noissh/authorized_keys`).
#[derive(Debug, Default, Clone)]
pub struct AuthorizedKeys {
    keys: Vec<(PublicKey, String)>,
}

impl AuthorizedKeys {
    pub fn new() -> Self {
        AuthorizedKeys::default()
    }

    /// Parse a file's contents. Blank lines and `#` comments are ignored.
    /// Malformed lines are skipped (to match SSH's lenient parsing) but a
    /// strict parse is available via [`AuthorizedKeys::parse_strict`].
    pub fn parse(contents: &str) -> Self {
        let mut keys = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(key) = PublicKey::from_text(line) {
                let comment = line.split_whitespace().nth(2).unwrap_or("").to_string();
                keys.push((key, comment));
            }
        }
        AuthorizedKeys { keys }
    }

    /// Strict parse: errors on the first malformed non-comment line.
    pub fn parse_strict(contents: &str) -> Result<Self, AuthError> {
        let mut keys = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = PublicKey::from_text(line)?;
            let comment = line.split_whitespace().nth(2).unwrap_or("").to_string();
            keys.push((key, comment));
        }
        Ok(AuthorizedKeys { keys })
    }

    pub fn add(&mut self, key: PublicKey, comment: impl Into<String>) {
        self.keys.push((key, comment.into()));
    }

    /// Whether `key` is authorized.
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|(k, _)| k == key)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Outcome of a TOFU check against the known_hosts store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tofu {
    /// Host not seen before; the key was recorded (pinned).
    New,
    /// Host seen before and the key matches the pin.
    Match,
    /// Host seen before but the key DIFFERS — hard failure.
    Mismatch,
}

/// The client's pinned server keys (`~/.config/noissh/known_hosts`).
#[derive(Debug, Default, Clone)]
pub struct KnownHosts {
    hosts: BTreeMap<String, PublicKey>,
}

impl KnownHosts {
    pub fn new() -> Self {
        KnownHosts::default()
    }

    /// Parse `known_hosts` contents: `<host> noissh-x25519 <base64>` per line.
    ///
    /// Malformed lines are skipped (not fatal), matching how SSH treats its
    /// `known_hosts`: a single hand-edited or truncated line must not lock the
    /// user out of every other pinned host.
    pub fn parse(contents: &str) -> Self {
        let mut hosts = BTreeMap::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((host, rest)) = line.split_once(char::is_whitespace) else {
                continue;
            };
            if let Ok(key) = PublicKey::from_text(rest.trim()) {
                hosts.insert(host.to_string(), key);
            }
        }
        KnownHosts { hosts }
    }

    /// Serialize back to `known_hosts` text form.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for (host, key) in &self.hosts {
            s.push_str(host);
            s.push(' ');
            s.push_str(&key.to_text());
            s.push('\n');
        }
        s
    }

    /// Look up the pinned key for `host`.
    pub fn get(&self, host: &str) -> Option<&PublicKey> {
        self.hosts.get(host)
    }

    /// Iterate the pinned `(host, key)` entries in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PublicKey)> {
        self.hosts.iter()
    }

    /// Number of pinned hosts.
    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    /// Whether any hosts are pinned.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Remove the pin for an exact host label (e.g. `host:51820`), returning the
    /// key that was removed if there was one. Used to recover from an intentional
    /// server re-key without hand-editing `known_hosts`.
    pub fn remove(&mut self, host: &str) -> Option<PublicKey> {
        self.hosts.remove(host)
    }

    /// Remove every pin whose label matches `host` or `host:<port>` (any port),
    /// returning the labels removed. Lets `--forget-host example.com` clear the
    /// pin regardless of which port it was stored under.
    pub fn remove_matching(&mut self, host: &str) -> Vec<String> {
        let prefix = format!("{host}:");
        let to_remove: Vec<String> = self
            .hosts
            .keys()
            .filter(|label| label.as_str() == host || label.starts_with(&prefix))
            .cloned()
            .collect();
        for label in &to_remove {
            self.hosts.remove(label);
        }
        to_remove
    }

    /// TOFU check. On first contact the key is recorded and `New` returned.
    /// On a later visit, `Match` or `Mismatch` is returned without mutating.
    pub fn check_or_add(&mut self, host: &str, key: &PublicKey) -> Tofu {
        match self.hosts.get(host) {
            None => {
                self.hosts.insert(host.to_string(), *key);
                Tofu::New
            }
            Some(pinned) if pinned == key => Tofu::Match,
            Some(_) => Tofu::Mismatch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PublicKey {
        PublicKey([n; KEY_LEN])
    }

    #[test]
    fn public_key_text_roundtrip() {
        let k = key(7);
        let text = k.to_text();
        assert!(text.starts_with("noissh-x25519 "));
        assert_eq!(PublicKey::from_text(&text).unwrap(), k);
    }

    #[test]
    fn parse_rejects_wrong_type_and_bad_len() {
        assert_eq!(
            PublicKey::from_text("ssh-ed25519 AAAA"),
            Err(AuthError::BadKeyType("ssh-ed25519".to_string()))
        );
        let short = format!("{KEY_TYPE} {}", STANDARD.encode([1u8; 4]));
        assert_eq!(PublicKey::from_text(&short), Err(AuthError::BadKeyLen(4)));
    }

    #[test]
    fn authorized_keys_parse_and_contains() {
        let contents = format!(
            "# my keys\n{}  laptop\n\n{} phone\n",
            key(1).to_text(),
            key(2).to_text()
        );
        let ak = AuthorizedKeys::parse(&contents);
        assert_eq!(ak.len(), 2);
        assert!(ak.contains(&key(1)));
        assert!(ak.contains(&key(2)));
        assert!(!ak.contains(&key(3)));
    }

    #[test]
    fn authorized_keys_skips_garbage_lenient() {
        let contents = format!("garbage line here\n{}\n", key(5).to_text());
        let ak = AuthorizedKeys::parse(&contents);
        assert_eq!(ak.len(), 1);
        assert!(ak.contains(&key(5)));
    }

    #[test]
    fn authorized_keys_strict_errors_on_garbage() {
        assert!(AuthorizedKeys::parse_strict("not a key").is_err());
    }

    #[test]
    fn tofu_new_then_match() {
        let mut kh = KnownHosts::new();
        assert_eq!(kh.check_or_add("host.example", &key(1)), Tofu::New);
        assert_eq!(kh.check_or_add("host.example", &key(1)), Tofu::Match);
    }

    #[test]
    fn tofu_mismatch_is_hard_failure() {
        let mut kh = KnownHosts::new();
        assert_eq!(kh.check_or_add("host.example", &key(1)), Tofu::New);
        assert_eq!(kh.check_or_add("host.example", &key(2)), Tofu::Mismatch);
        // The original pin is NOT overwritten by a mismatch.
        assert_eq!(kh.get("host.example"), Some(&key(1)));
    }

    #[test]
    fn known_hosts_text_roundtrip() {
        let mut kh = KnownHosts::new();
        kh.check_or_add("a.example", &key(1));
        kh.check_or_add("b.example:9999", &key(2));
        let text = kh.to_text();
        let parsed = KnownHosts::parse(&text);
        assert_eq!(parsed.get("a.example"), Some(&key(1)));
        assert_eq!(parsed.get("b.example:9999"), Some(&key(2)));
    }

    #[test]
    fn known_hosts_remove_exact_and_matching() {
        let mut kh = KnownHosts::new();
        kh.check_or_add("a.example:51820", &key(1));
        kh.check_or_add("a.example:2222", &key(2));
        kh.check_or_add("b.example:51820", &key(3));
        // Exact removal.
        assert_eq!(kh.remove("a.example:51820"), Some(key(1)));
        assert_eq!(kh.remove("a.example:51820"), None);
        // Port-agnostic removal clears every label for the host.
        let removed = kh.remove_matching("a.example");
        assert_eq!(removed, vec!["a.example:2222".to_string()]);
        assert_eq!(kh.get("a.example:2222"), None);
        // Other hosts are untouched, and the host name isn't a prefix false-match.
        assert_eq!(kh.get("b.example:51820"), Some(&key(3)));
        assert!(kh.remove_matching("a").is_empty());
    }

    #[test]
    fn known_hosts_parse_skips_malformed_lines() {
        // A malformed line is skipped, but valid lines around it still load
        // (so one bad line can't lock the user out of every pinned host).
        let text = format!("onlyhost\ngood.example {}\n", key(3).to_text());
        let parsed = KnownHosts::parse(&text);
        assert_eq!(parsed.get("good.example"), Some(&key(3)));
        assert_eq!(parsed.get("onlyhost"), None);
    }
}
