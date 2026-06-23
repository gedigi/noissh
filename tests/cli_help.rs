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
