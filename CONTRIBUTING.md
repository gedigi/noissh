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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the crate map and design
rationale, and [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire format.

## Safety

The project is `#![forbid(unsafe_code)]` in every crate and binary. Do not add
`unsafe`; reach for a vetted safe-API crate (as we do with `pty-process`,
`daemonize`, `nix`, `terminal_size`) instead.

## Platform notes

- The PTY/login path (`LocalLogin`, via `pty-process`) works on Linux and macOS
  with no root and is exercised by the test suite.
- Multi-user deployments use the SSH-bootstrap model (server runs as the
  authenticated user); an optional root daemon can drop `uid`/`gid` before exec.

## Commit messages

Use clear, imperative summaries (e.g. `fix: drop replayed datagrams in window`).
Group related changes; keep unrelated changes in separate commits.

## Security issues

Please report suspected vulnerabilities privately (see
[`docs/SECURITY.md`](docs/SECURITY.md)) rather than in a public issue.
