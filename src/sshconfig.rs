#![forbid(unsafe_code)]
//! Minimal `~/.ssh/config` interop.
//!
//! noissh runs the SSH bootstrap through `ssh`, which already honours the user's
//! `~/.ssh/config`. But the resilient session runs over Noise/UDP, and noissh
//! resolves *that* address itself from the target string — so a `Host` alias
//! whose real address lives in `HostName` would never resolve for the UDP leg.
//! This module reads the relevant keys (`HostName`, `User`, `Port`) for an alias
//! so the UDP destination, the login user, and the SSH port all follow the same
//! config the user already maintains for `ssh`.
//!
//! This is a deliberately small subset of OpenSSH's config grammar: `Host`
//! blocks with `*`/`?`/`!` glob patterns and first-value-wins semantics. It does
//! not implement `Match`, `Include`, or token expansion — enough to make aliases
//! work without pretending to be a full ssh_config engine.

use std::path::PathBuf;

/// Resolved settings for a host alias (any field may be absent).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// The real host to connect to (`HostName`); falls back to the alias.
    pub hostname: Option<String>,
    /// The login user (`User`).
    pub user: Option<String>,
    /// The SSH port (`Port`).
    pub port: Option<u16>,
}

/// Path to the user's SSH client config (`~/.ssh/config`).
pub fn default_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh").join("config"))
}

/// Resolve `alias` against `~/.ssh/config` if it exists. Returns an empty
/// [`HostConfig`] when the file is missing/unreadable or the alias is unmatched,
/// so callers can always fall back to the alias itself.
pub fn resolve_default(alias: &str) -> HostConfig {
    match default_path().and_then(|p| std::fs::read_to_string(p).ok()) {
        Some(text) => resolve(&text, alias),
        None => HostConfig::default(),
    }
}

/// Resolve `alias` against the contents of an ssh_config file.
///
/// Semantics mirror OpenSSH: keys are scanned top-to-bottom and the *first*
/// value seen for each key (within any `Host` block whose pattern matches the
/// alias) wins. A bare `Host *` block therefore provides defaults that an
/// earlier, more specific block can override.
pub fn resolve(config_text: &str, alias: &str) -> HostConfig {
    let mut out = HostConfig::default();
    // Whether the current `Host` block applies to this alias.
    let mut active = false;
    for raw in config_text.lines() {
        // Strip comments and surrounding whitespace. (ssh treats `#` to
        // end-of-line as a comment when it begins a token; we keep it simple.)
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Keyword/value split on whitespace or `=` (ssh allows either).
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.trim(), v.trim_start_matches(['=', ' ', '\t']).trim()),
            None => continue,
        };
        if value.is_empty() {
            continue;
        }
        if key.eq_ignore_ascii_case("Host") {
            active = host_patterns_match(value, alias);
            continue;
        }
        if !active {
            continue;
        }
        match key.to_ascii_lowercase().as_str() {
            "hostname" if out.hostname.is_none() => out.hostname = Some(value.to_string()),
            "user" if out.user.is_none() => out.user = Some(value.to_string()),
            "port" if out.port.is_none() => {
                if let Ok(p) = value.parse::<u16>() {
                    out.port = Some(p);
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether any whitespace-separated pattern in a `Host` line matches `alias`.
/// Supports `*`/`?` globs and `!` negation (a matching negation excludes the
/// alias from the block, as in ssh).
fn host_patterns_match(patterns: &str, alias: &str) -> bool {
    let mut matched = false;
    for pat in patterns.split_whitespace() {
        if let Some(neg) = pat.strip_prefix('!') {
            if glob_match(neg, alias) {
                return false; // an explicit negation wins
            }
        } else if glob_match(pat, alias) {
            matched = true;
        }
    }
    matched
}

/// Glob match supporting `*` (any run) and `?` (one char), as ssh_config uses.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Classic two-pointer wildcard match with backtracking on `*`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("web*", "web01"));
        assert!(glob_match("*.example.com", "host.example.com"));
        assert!(glob_match("db?", "db1"));
        assert!(!glob_match("db?", "db12"));
        assert!(!glob_match("web*", "dbweb"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exacto"));
    }

    #[test]
    fn resolves_hostname_user_port() {
        let cfg = "\
Host prod
    HostName 10.0.0.5
    User deploy
    Port 2222
";
        let r = resolve(cfg, "prod");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.5"));
        assert_eq!(r.user.as_deref(), Some("deploy"));
        assert_eq!(r.port, Some(2222));
    }

    #[test]
    fn unmatched_alias_returns_empty() {
        let cfg = "Host prod\n    HostName 10.0.0.5\n";
        assert_eq!(resolve(cfg, "staging"), HostConfig::default());
    }

    #[test]
    fn first_value_wins_and_wildcard_defaults_apply() {
        // ssh semantics: the first value for each key wins, so a specific block
        // before a `Host *` default overrides it; the default still fills gaps.
        let cfg = "\
Host prod
    HostName 10.0.0.5
Host *
    User admin
    Port 9999
    HostName ignored.example
";
        let r = resolve(cfg, "prod");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.5")); // specific wins
        assert_eq!(r.user.as_deref(), Some("admin")); // from the default block
        assert_eq!(r.port, Some(9999));
    }

    #[test]
    fn equals_separator_and_comments() {
        let cfg = "Host=prod # the prod box\n  HostName = 10.0.0.9\n";
        let r = resolve(cfg, "prod");
        assert_eq!(r.hostname.as_deref(), Some("10.0.0.9"));
    }

    #[test]
    fn negation_excludes() {
        let cfg = "Host * !secret\n  User generic\n";
        assert_eq!(resolve(cfg, "public").user.as_deref(), Some("generic"));
        assert_eq!(resolve(cfg, "secret").user, None);
    }

    #[test]
    fn multiple_patterns_on_one_host_line() {
        let cfg = "Host alpha beta\n  HostName shared.example\n";
        assert_eq!(
            resolve(cfg, "beta").hostname.as_deref(),
            Some("shared.example")
        );
        assert_eq!(resolve(cfg, "gamma").hostname, None);
    }

    #[test]
    fn keys_are_case_insensitive() {
        let cfg = "host prod\n  hostname 1.2.3.4\n  USER bob\n";
        let r = resolve(cfg, "prod");
        assert_eq!(r.hostname.as_deref(), Some("1.2.3.4"));
        assert_eq!(r.user.as_deref(), Some("bob"));
    }
}
