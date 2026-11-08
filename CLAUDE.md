# Working on noissh

See `CONTRIBUTING.md` for the full conventions; the points below are the ones
that must never be skipped.

## Every PR keeps the documentation accurate

Before opening or updating any PR, check every document against the code as it
will be after the PR, and fix what is wrong or missing in the same PR, including
inaccuracies that were already there:

- `README.md`
- `docs/USER_GUIDE.md` (including the command reference and troubleshooting)
- `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, `docs/SECURITY.md`
- `docs/design/*.md` (status and anything the PR changes)
- `docs/man/*.1` (they ship in the release packages; check they render with
  `man -l`)
- `--help` text in `src/bin/*.rs`
- `contrib/` (systemd unit and its README)
- `CONTRIBUTING.md`
- `CHANGELOG.md`: user-visible changes under `## [Unreleased]`; a version
  heading only in the release PR that bumps `Cargo.toml`

Check claims against the code (constants, defaults, flags, file paths), not
against other docs. List the documentation changes in the PR description.

## Before pushing

```sh
cargo fmt --all --check
cargo clippy --all-targets --workspace -- -D warnings
cargo test --workspace
```

All three must pass. No `unsafe` code anywhere (`#![forbid(unsafe_code)]`).

## Releases

A release PR bumps `version` in `Cargo.toml` (workspace and package), the man
page headers, and renames `## [Unreleased]` in `CHANGELOG.md` to the version.
The release workflow runs on a `v*` tag, or manually with a tag name: run it only
after the release PR is merged, on `main`.
