//! The three binaries answer `-h`/`--help` and `-V`/`--version` (and exit 0)
//! rather than treating them as unknown arguments or attempting to connect.

use std::process::Command;

fn run(bin: &str, args: &[&str]) -> (i32, String) {
    let out = Command::new(bin).args(args).output().expect("spawn binary");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}

#[test]
fn noissh_help_and_version() {
    let bin = env!("CARGO_BIN_EXE_noissh");
    for flag in ["-h", "--help"] {
        let (code, out) = run(bin, &[flag]);
        assert_eq!(code, 0, "{flag} should exit 0");
        assert!(out.contains("Usage:"), "{flag} should print usage: {out}");
        assert!(
            out.contains("command"),
            "{flag} should mention the positional command"
        );
    }
    for flag in ["-V", "--version"] {
        let (code, out) = run(bin, &[flag]);
        assert_eq!(code, 0, "{flag} should exit 0");
        assert!(
            out.contains(env!("CARGO_PKG_VERSION")),
            "{flag} should print the version: {out}"
        );
    }
}

#[test]
fn noissh_no_args_prints_usage_not_bootstrap_error() {
    // Running `noissh` with no host must explain that a host is required and
    // point at --help, NOT emit a misleading "SSH bootstrap failed" (it never
    // got far enough to bootstrap anything).
    let bin = env!("CARGO_BIN_EXE_noissh");
    let (code, out) = run(bin, &[]);
    assert_eq!(code, 2, "no-args should exit 2 (usage error): {out}");
    assert!(
        out.contains("no host given") && out.contains("--help"),
        "no-args should print a usage hint: {out}"
    );
    // It must tell the user HOW to fix it — show a concrete example invocation.
    assert!(
        out.contains("noissh user@example.com"),
        "no-args should show an example: {out}"
    );
    assert!(
        !out.contains("SSH bootstrap failed") && !out.contains("connect line"),
        "no-args must not report a bootstrap failure: {out}"
    );
}

#[test]
fn noissh_invalid_args_fail_loudly() {
    let bin = env!("CARGO_BIN_EXE_noissh");
    // Each of these is a usage mistake that must exit 2 with a helpful message,
    // not be silently ignored (which used to drop the user into a shell).
    for args in [
        &["--port", "abc", "host"][..],
        &["--put", "missing-colon", "host"][..],
        &["-L", "8080", "host"][..],
        &["-x", "host"][..],
    ] {
        let (code, out) = run(bin, args);
        assert_eq!(code, 2, "{args:?} should exit 2, got {code}: {out}");
        assert!(
            out.to_lowercase().contains("noissh:"),
            "{args:?} should print a noissh error: {out}"
        );
    }
}

#[test]
fn noissh_forget_host_removes_pin() {
    // `--forget-host` removes a pinned server key without connecting, so a
    // re-keyed server can be re-trusted without hand-editing known_hosts.
    let bin = env!("CARGO_BIN_EXE_noissh");
    let dir = std::env::temp_dir().join(format!("noissh-forget-test-{}", std::process::id()));
    let cfgdir = dir.join("noissh");
    std::fs::create_dir_all(&cfgdir).unwrap();
    let kh = cfgdir.join("known_hosts");
    // base64 of 32 zero bytes — a valid (if all-zero) noissh-x25519 public key.
    let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    std::fs::write(
        &kh,
        format!(
            "example.com:51820 noissh-x25519 {k}\nother.com:51820 noissh-x25519 {k}\n"
        ),
    )
    .unwrap();

    let out = Command::new(bin)
        .args(["--forget-host", "example.com"])
        .env("XDG_CONFIG_HOME", &dir)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("removed"), "should report removal: {stderr}");

    let remaining = std::fs::read_to_string(&kh).unwrap();
    assert!(
        !remaining.contains("example.com"),
        "forgotten host should be gone: {remaining}"
    );
    assert!(
        remaining.contains("other.com"),
        "other hosts must be preserved: {remaining}"
    );

    // Forgetting an unknown host is a no-op success with a clear message.
    let out = Command::new(bin)
        .args(["--forget-host", "nope.example"])
        .env("XDG_CONFIG_HOME", &dir)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no pinned host key"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn noisshd_help_and_version() {
    let bin = env!("CARGO_BIN_EXE_noisshd");
    let (code, out) = run(bin, &["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("Usage:"), "help should print usage: {out}");
    let (code, out) = run(bin, &["--version"]);
    assert_eq!(code, 0);
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "version: {out}");
}

#[test]
fn keygen_help_and_version() {
    let bin = env!("CARGO_BIN_EXE_noissh-keygen");
    let (code, out) = run(bin, &["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("Usage:"), "help should print usage: {out}");
    let (code, out) = run(bin, &["-V"]);
    assert_eq!(code, 0);
    assert!(out.contains(env!("CARGO_PKG_VERSION")), "version: {out}");
}
