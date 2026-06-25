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
    assert!(
        !out.contains("SSH bootstrap failed"),
        "no-args must not report a bootstrap failure: {out}"
    );
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
