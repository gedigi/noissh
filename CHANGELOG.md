# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Port forwarding** over the reliable stream multiplexer: local (`-L
  LPORT:HOST:PORT`) and remote (`-R RPORT:HOST:PORT`), `ssh -N`-style
  forward-only sessions, with real-socket end-to-end tests.
- **Session reattach**: a returning client (same static key) rebinds to its
  still-running shell and receives a full snapshot, instead of spawning a new one.
- **Keepalives + idle reaping**: clients send periodic Ping keepalives (server
  replies Pong) to refresh NAT and prove liveness; the server reaps sessions
  whose client has gone silent past a grace window.
- **Event-driven client loop** (`poll`-based) replacing the previous busy-poll —
  far lower idle CPU/bandwidth.
- **Unicode width handling** in the terminal: double-width CJK/emoji occupy two
  cells; zero-width combining marks no longer desync the grid.
- **Supply-chain CI**: `cargo-deny` + `cargo-audit`, a macOS test/clippy matrix
  leg, and release artifacts carry SHA-256 checksums + Sigstore build-provenance
  attestations (the installer verifies the checksum).

### Changed

- The `-R` listener binds to loopback (`127.0.0.1`) by default — forwarded ports
  are not exposed to the network (no implicit `GatewayPorts`).

## [0.1.0]

### Added

- **v1 — resilient interactive shell.**
  - Noise `XX` handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) with stateless
    per-datagram AEAD (`noise-core`).
  - Mini-QUIC-with-Noise transport (`transport`): cryptographic session id,
    address roaming, sliding-window anti-replay, reliable input channel.
  - Clean-room authoritative terminal emulator + latest-wins screen diff
    (`term`).
  - Client-side predictive-echo engine with adaptive safety (`predict`).
  - `known_hosts` TOFU + `authorized_keys` trust model (`auth`).
  - PTY/login backend built on the safe `pty-process` crate (`pty`); the whole
    workspace is `#![forbid(unsafe_code)]`.
  - `noissh` client and `noisshd` server binaries; config & key management.
  - Raw-mode interactive client with an incremental ANSI renderer.
- **v2 — reliable stream multiplexer** (`transport::StreamMux`): ordered,
  flow-controlled byte streams with ARQ over the same roaming session — the
  substrate for forthcoming port forwarding, file transfer, and agent forwarding.
- **SSH bootstrap** (`noissh --ssh`, `noisshd --one-shot`): use SSH
  only to launch the server and exchange the UDP port + ephemeral key, then run
  over Noise/UDP.
- Test suite: unit tests per crate, an in-process resilience harness
  (loss/reorder + mid-session source-address roaming), real-socket end-to-end
  tests (including client rebind roaming), security and fuzz tests, and an
  SSH-bootstrap end-to-end test.
- Documentation: README, architecture, protocol, user guide, and security model.

### Notes

- This is pre-release software (0.1). The protocol may change and has not been
  independently audited.
