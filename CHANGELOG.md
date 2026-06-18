# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2]

### Fixed

- **Restore the terminal on signals**: if the interactive client is killed by
  `SIGTERM`/`SIGINT`/`SIGHUP` (e.g. an external `kill`), it now resets the
  terminal out of raw mode before exiting, instead of leaving the shell unusable
  until `reset`.

## [0.4.1]

### Security

- **Hardened the reliable-stream layer against a malicious/misbehaving peer**:
  out-of-window or overflowing `StreamData` is dropped (no huge allocation or
  unbounded buffering), the peer FIN offset is recorded only once, acks for
  unsent data are ignored, peer stream-id parity is enforced, and concurrent
  peer-opened streams are capped.
- **Atomic `known_hosts` writes** (temp + fsync + rename) so a crash mid-write
  can't destroy the TOFU pin and silently re-enable trust-on-first-use; newly
  generated private keys are fsynced before use.

### Fixed

- **File transfer is now atomic**: uploads and downloads write to a temporary
  file and rename into place on success, so a failed or aborted transfer never
  truncates or partially overwrites an existing destination (notably
  `--get REMOTE:EXISTING_LOCAL` of a missing remote no longer clobbers the local
  file).
- **Forwarded-connection and transfer cleanup on session reap/reattach**: TCP
  file descriptors and transfer handles are no longer leaked, and an interrupted
  upload is no longer wrongly finalized as complete.
- **Lenient `known_hosts` parsing**: a single malformed line is skipped rather
  than failing the whole file (which previously could lock a user out of every
  pinned host).
- Bounded the `--exec` stdin staging buffer; single-quoted the auto-install
  installer URL.

## [0.4.0]

### Added

- **Dynamic (SOCKS) port forwarding** (`-D [BIND:]PORT`): a local SOCKS proxy
  whose connections tunnel dynamically, over the resilient session, to the
  host:port each client requests (resolved via the server). Speaks SOCKS5 (no
  authentication) and SOCKS4/4a, CONNECT only; binds loopback by default. Like
  `-L`/`-R`, it makes the session forward-only.
- **Remote command execution** (`--exec CMD`): run a single command
  non-interactively on the server, streaming its stdout and stderr separately to
  yours, forwarding stdin until EOF, and exiting with the command's exit code.
  Output is byte-for-byte (no PTY/terminal processing), so it is safe to redirect
  or pipe. Refused by a standalone daemon configured with a `--user` privilege
  drop (same posture as file transfer and agent forwarding).
- **RTT-based congestion control**: streams now use an adaptive,
  RTT-estimated retransmission timeout plus a congestion window (slow start /
  congestion avoidance), improving throughput on lossy or high-latency links.
- **Daemon observability** (`noisshd -v`/`--verbose`): logs session lifecycle
  (each session established and ended, with the current active session count) and
  fatal socket errors.
- **Auto-install of `noisshd` on first `--ssh` connect**: if the remote does not
  have `noisshd`, the first connect runs the published installer over the same
  SSH session (detecting OS/arch, downloading the matching prebuilt release,
  verifying its SHA-256 checksum, installing into `~/.local/bin`) and retries the
  handshake. Skipped with `--no-install` or a custom `--server-cmd`.
- **`noissh-keygen` man page** (`noissh-keygen.1`).

### Security

- **Handshake anti-amplification floor**: the client pads its initial handshake
  packet and the server refuses an undersized new-session init, so the handshake
  cannot be used as a UDP reflection/amplification vector.

### Removed

- **Never-wired second-factor control messages** (`AuthPrompt`/`AuthResponse`),
  which were defined but never used.

## [0.3.1]

### Security

- **Refuse file transfer (`--put`/`--get`) and agent forwarding (`-A`) when a
  `--user` privilege drop is configured.** In that mode the daemon process stays
  root while the shell drops to the target user, so the driver could otherwise
  perform file/agent I/O as root on a client's behalf. The supported models (SSH
  bootstrap, the portable backend, or a daemon already running as the target
  user) have process identity == session identity and are unaffected.

## [0.3.0]

### Added

- **File transfer** over the resilient session: one-shot upload
  (`--put LOCAL:REMOTE`) and download (`--get REMOTE:LOCAL`). The spec is split
  on the first colon; no shell is opened. Integrity comes from the reliable,
  authenticated (AEAD) stream — no separate checksum step — and paths are
  accessed as the server user.
- **Agent forwarding** (`-A`, `--forward-agent`) for interactive sessions: the
  server exposes an `SSH_AUTH_SOCK` whose connections tunnel back over a
  dedicated session stream to your local agent, letting remote `git`/`ssh` use
  your local keys without copying them to the server. Requires `SSH_AUTH_SOCK`
  to be set locally; if it is unset, noissh warns and continues without it.
- **MTU-safe datagram capping** so outbound datagrams stay within a safe size
  and avoid IP fragmentation.
- **RTO-based stream retransmission**: unacknowledged stream data is resent only
  after a retransmission timeout, instead of on every poll.
- **`noissh-keygen`**: a small tool to create/print the client keypair (ensures
  it exists with `0600` perms and prints the `noissh-x25519 <base64>` public-key
  line).
- **Config file** (`~/.config/noissh/config`) supporting `port` and `term`
  settings.
- **systemd unit + packaging helpers**: a `noisshd.service` unit under
  `contrib/`, plus Makefile/install support.

### Fixed

- A stream FIN set after all data was acknowledged is now reliably delivered, so
  end-of-stream is no longer missed.
- The forwarded agent socket is locked down to the owning user: its per-user
  directory is created mode 0700 (rejecting a pre-existing path not owned by the
  user) and the socket file is chmod 0600, so other local users on the server
  cannot reach the forwarded agent.

## [0.2.0]

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
