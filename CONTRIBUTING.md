# Contributing to noissh

Thanks for your interest! noissh is a Rust workspace; contributions of bug fixes,
tests, and features are welcome.

## Development setup

```sh
rustup toolchain install stable      # edition 2024; tested on 1.96+
git clone https://github.com/gedigi/noissh
cd noissh
cargo build
cargo test --workspace
```

## Before you open a PR

All of these must pass — CI and reviewers expect a clean tree:

```sh
cargo fmt --all                                   # formatting
cargo clippy --workspace --all-targets -- -D warnings   # zero warnings
cargo test --workspace                            # all tests green
```

## Project conventions

- **TDD.** Write a failing test first, then the minimal code to pass it. Every
  new function/behavior should have a test. See `docs/ARCHITECTURE.md` for the
  testing strategy.
- **Lean dependencies.** Enable only the crate features you actually use
  (`default-features = false` plus an explicit feature list where practical).
- **Focused crates.** Keep each crate's responsibility narrow; respect the
  dependency direction (no cycles). Lower crates must not depend on higher ones.
- **I/O-free cores.** Protocol logic belongs in the socket-free cores
  (`proto`, `ServerCore`/`ClientCore`) so it stays deterministically testable;
  add sockets/PTYs only in the runtime/driver layer.
- **Match the surrounding style.** Comment density, naming, and idioms should
  look like the code already there.

## Repository layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the crate map and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire format. The design rationale
is in [`docs/specs/2026-06-18-noissh-design.md`](docs/specs/2026-06-18-noissh-design.md).

## Platform notes

- The portable PTY/login path (`LocalLogin`) works on Linux and macOS with no
  root and is exercised by the test suite.
- The Linux privsep/PAM path (`PrivsepLogin`, `pty/pam` feature) requires Linux
  and root to run; it is `cfg`-gated and cannot be exercised on macOS.

## Commit messages

Use clear, imperative summaries (e.g. `fix: drop replayed datagrams in window`).
Group related changes; keep unrelated changes in separate commits.

## Security issues

Please report suspected vulnerabilities privately (see
[`docs/SECURITY.md`](docs/SECURITY.md)) rather than in a public issue.
