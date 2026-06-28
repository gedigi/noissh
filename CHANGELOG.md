# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.3]

### Changed

- **The server's version now rides in the Noise handshake** (the encrypted `m2`
  payload) instead of only a post-handshake message, so a direct connection knows
  it the instant the handshake completes — no extra round trip and no wait. The
  direct-upgrade prompt added in 0.5.2 therefore appears immediately. The
  post-handshake `ServerVersion` control message is kept as a fallback so a
  v0.5.3 client still learns the version from a v0.5.2 daemon, and a v0.5.2 client
  still learns it from a v0.5.3 daemon — no flag day.

## [0.5.2]

### Added

- **Direct connections can now offer to upgrade an outdated standing daemon.**
  The server announces its version in the session (a new `ServerVersion` control
  message sent right after the handshake), so a direct connection — not just the
  SSH bootstrap — notices when the remote `noisshd` is older than your client and
  offers the same `[y/N]` upgrade. Accepting installs the new binary over SSH;
  since a standing daemon keeps running the old binary until restarted, noissh
  tells you to restart it (e.g. `systemctl --user restart noisshd`) rather than
  pretending it took effect. The check runs only on interactive connections to a
  real terminal (scripts, transfers, and forwards are never paused) and is
  skipped by `--no-install`. Servers older than v0.5.2 don't announce a version,
  so they're simply not prompted until upgraded once.

## [0.5.1]

### Added

- **Debian/Ubuntu `.deb` packages.** Each release now publishes a `.deb` for
  `amd64` and `arm64` (alongside the tarballs), with a SHA-256 checksum and a
  Sigstore build-provenance attestation. Install with
  `sudo dpkg -i noissh-<target>.deb` (or `sudo apt install ./noissh-<target>.deb`);
  it installs `noissh`, `noisshd`, `noissh-keygen`, and their man pages.

## [0.5.0]

A combined UX-audit pass and feature pass closing the biggest gaps against
everyday `ssh`/Mosh use.

### Added

- **Connection-status overlay.** When the link goes quiet (roaming, Wi-Fi↔cellular
  handoff, a dead spot), the interactive client now shows a Mosh-style banner on
  the top row — `[noissh] last contact N s ago — reconnecting…  (Ctrl-^ . to
  quit)`. It appears only after the link is silent past the keepalive interval
  (so a healthy idle session never flashes it), counts up once a second, and
  clears the instant contact resumes. While stale, keepalives speed up so
  recovery is detected within about a second.
- **Detach / escape key.** `Ctrl-^` is a local escape prefix: `Ctrl-^ .` or
  `Ctrl-^ q` disconnects cleanly (restores the terminal and exits 0) so a wedged
  client no longer means killing the terminal window; `Ctrl-^ Ctrl-^` sends a
  literal `Ctrl-^`.
- **`~/.ssh/config` interop.** Host aliases now work for the resilient UDP leg,
  not just the SSH bootstrap: noissh reads `HostName`/`User`/`Port` for the
  target alias so `noissh myalias` resolves the same way `ssh myalias` does.
  (ProxyJump, IdentityFile, and the rest continue to be handled by `ssh` itself
  during the bootstrap.)
- **`--copy-id`.** Installs your public key into the remote `authorized_keys`
  over SSH (the direct-mode equivalent of `ssh-copy-id`), so setting up a
  standing-daemon direct connection no longer means hand-copying keys.
- **`--forget-host HOST`.** Removes the pinned server key(s) for a host so
  recovering from an intentional server re-key no longer means hand-editing
  `known_hosts` (the equivalent of `ssh-keygen -R`).
- **`-v` / `--verbose`.** Narrates the connection sequence (direct probe, DNS
  resolution, handshake, SSH bootstrap) to diagnose the most common failure —
  a connect that hangs because the UDP port is blocked.
- **File-transfer progress.** `--put`/`--get` now show a live progress line
  (percentage and sizes on upload; running byte count on download). It is
  TTY-only, so scripts and pipelines stay clean.
- **`-h`/`--help` works everywhere** and now notes that options precede the host.
- **`noisshd --user NAME`** drops sessions to a target user (the privilege-drop
  mode the docs described but the daemon didn't expose).
- **An optional `config` file** (`~/.config/noissh/config`) sets the default
  `port` for direct connections; `noissh-keygen` gained `-V`/`--version`.

### Fixed

- **No more "random screen refresh."** The renderer repainted the cursor on every
  event-loop wakeup (each keepalive/ack), emitting a hide→move→show cycle even
  when nothing changed — visible as flicker on an idle screen. It now does
  nothing when the frame is unchanged and only toggles cursor visibility when it
  actually changes. (Measured: cursor hide/show on a 9 s idle session dropped
  from 26 to 2.)
- **Clear, actionable error messages.** Many errors were vague or reused a single
  catch-all. Now:
  - `noissh` with no host explains what to do and shows an example (exit 2).
  - SSH-bootstrap failures surface `ssh`'s own diagnostic (auth denied, host
    unreachable, …) instead of a generic "no connect line".
  - `noisshd --one-shot` without `--authorize`, and other CLI mistakes, are
    reported as usage errors (exit 2), not "SSH bootstrap failed".
  - An invalid `--listen`/`--bind` address says so, instead of "malformed key
    file".
  - A host-key mismatch now tells you exactly how to recover (which file/line to
    remove) when you intentionally re-keyed the server.
  - A stray blank line before each error (a stray `\r\n`) is gone.
- **The terminal is always restored on exit.** Cursor visibility and text
  attributes are reset whenever raw mode ends (normal exit, signal, or error), so
  a full-screen program can't leave your shell with a hidden cursor.
- **The client advertises your real `$TERM`** instead of always claiming
  `xterm-256color`.

### Changed

- **Invalid command-line arguments now fail loudly.** A malformed `-L`/`-R`/`-D`
  or `--put`/`--get` spec, a non-numeric `--port`, or an unknown option is a
  usage error (exit 2) with a concrete example, instead of being silently ignored
  (which previously could drop you into an unexpected interactive shell).
- **First-run and trust-on-first-use are no longer silent.** Generating your key
  on first run prints its location and public key (so you can authorize it), and
  pinning a server's key on first direct connection is announced.

### Known limitations

- **Scrollback.** Like Mosh, noissh paints a live picture of the remote screen,
  so your terminal's native scrollback does not capture content that scrolls off
  the top. Run `tmux` or `screen` on the server for scrollback (and an even
  stronger detach story). See the User Guide.
- **Windows client.** The client is Unix-only (it needs a PTY and POSIX terminal
  handling). Windows support is tracked as future work; see the User Guide.

## [0.4.13]

### Fixed

- **Running `noissh` with no host now prints a clear usage error.** Previously it
  reported a misleading "SSH bootstrap failed: no connect line from remote
  noisshd" — it had never actually tried to bootstrap; there was simply no host
  to connect to. It now prints `noissh: no host given`, a one-line usage summary,
  and a pointer to `--help`, and exits with status 2.

## [0.4.12]

### Fixed

- **Accepting a remote-`noisshd` upgrade keeps you connected.** The upgrade
  offer (added in 0.4.11) no longer reconnects through the still-busy pinned UDP
  port, which could land the new server on an ephemeral, firewalled port and time
  out. Accepting now installs the new binary so it takes effect on your *next*
  connection and keeps using the current session right away.
- **Remote install/upgrade failures are no longer silently masked.** The
  auto-installer downloads to a temp file (with `set -e`) instead of piping
  `curl … | sh`, whose exit status reflected the shell, not the download — so a
  404 or network error during install is now reported as a failure instead of
  appearing to succeed.

## [0.4.11]

### Added

- **Optional upgrade of an outdated remote `noisshd`.** The one-shot server now
  reports its version during the SSH bootstrap. If the remote `noisshd` is older
  than the connecting client, noissh asks — `[y/N]`, defaulting to no — whether
  to upgrade it before continuing. Declining keeps the existing remote version
  and connects to it as before; accepting reinstalls via the published installer
  and reconnects. The prompt is skipped when stdin is not a terminal (so scripts
  never block) and when `--no-install` is set. Servers older than v0.4.11 don't
  report a version, so no prompt is shown for them until they're upgraded once.

## [0.4.10]

### Added

- **`-h`/`--help` and `-V`/`--version` on all three binaries.** `noissh`,
  `noisshd`, and `noissh-keygen` now print a usage summary or their version and
  exit, instead of treating `--help` as an unknown option. (`noissh --help`
  previously fell through to a confusing bootstrap attempt.)

## [0.4.9]

### Fixed

- **The prompt now appears immediately — no need to press Enter first.** A
  shell's line editor queries the terminal at startup (cursor-position report,
  `ESC[6n`, and device-attributes, `ESC[c`) and blocks until it gets a reply
  before drawing the prompt. The server-side emulator now answers these queries
  by writing the reply back to the shell, so the first prompt renders right away
  instead of waiting for a keystroke (whose bytes were previously being consumed
  as the missing reply).

### Changed

- **Remote commands are now ssh-style positional arguments.** Run a one-off
  command with `noissh user@host <cmd> [args...]` instead of the old `--exec`
  flag (which has been removed). Everything after the host is taken as the
  command verbatim — its own flags are not parsed by noissh — and is joined and
  run by the remote shell, so quoting, globs, pipes, and redirections behave as
  expected. As before, output is byte-exact, stderr is kept separate, and noissh
  exits with the command's status. Omit the command for an interactive shell.

## [0.4.8]

### Fixed

- **Roaming survives network changes again.** A failed UDP send (no route /
  network down while switching Wi-Fi/cellular or sleeping) and a corrupt, stale,
  or replayed datagram are now dropped instead of being fatal, so the session
  rides out the outage and resumes — roaming to the new address — once
  connectivity returns, rather than disconnecting.
- **No more spurious "HOST KEY MISMATCH" in auto mode.** `noissh host` now only
  attempts a direct connection when a standing server is already pinned for that
  host:port; otherwise it goes straight to the SSH bootstrap. This avoids
  pinning (or mismatching) the ephemeral key of a transient one-shot server that
  happens to be on the conventional port. `--direct` still forces a direct,
  trust-on-first-use connection.
- **`--exec` runs in your home directory** (matching the interactive shell),
  instead of the daemon's working directory.

## [0.4.7]

### Fixed

- **Login sessions now start in `$HOME`.** The spawned shell/command runs in the
  user's home directory (and gets `LOGNAME` set) instead of inheriting the
  daemon's working directory (which the bootstrap's daemonize left at `/`).

## [0.4.6]

### Fixed

- **Interactive sessions no longer crash with "Resource temporarily available"
  (EWOULDBLOCK).** Making stdin non-blocking also makes the shared-terminal
  stdout non-blocking, so a large screen repaint could fail mid-write; terminal
  output now rides out EWOULDBLOCK by waiting for writability. Command output
  from `--exec` is written the same way (no dropped bytes), and a full UDP send
  buffer is tolerated (the datagram is dropped and recovered) instead of being
  fatal.

## [0.4.5]

### Changed

- **The SSH bootstrap now uses the conventional UDP port by default** (`--port`,
  51820) instead of a random ephemeral one, so a single firewall rule covers
  both direct and bootstrapped sessions. The server falls back to an ephemeral
  port only if the conventional one is already taken. `--server-port N` still
  overrides.
- **The bootstrap key is no longer persisted to `known_hosts`.** It's an
  ephemeral, SSH-authenticated key; persisting it under a fixed `--server-port`
  label caused a spurious "HOST KEY MISMATCH" on the next connect. It's now
  trusted per-session (still validating the UDP handshake).

### Fixed

- **The bootstrap no longer re-downloads `noisshd` on every connect**: it tries
  the known install path (`~/.local/bin/noisshd`) before falling back to a
  reinstall (the binary isn't on the non-interactive SSH `PATH`).
- **One-shot servers now exit promptly after a non-interactive task.** A client
  finishing `--exec` or a file transfer sends a `Bye`, so the one-shot tears
  down (freeing its UDP port) instead of lingering until the idle-reap grace.

## [0.4.4]

### Added

- **`--server-port N`** pins the SSH-bootstrapped server to a fixed UDP port
  instead of an ephemeral one, so it can be opened in a firewall/NAT — useful on
  hosts that allow SSH but block arbitrary inbound UDP.

### Changed

- A bootstrapped session that connects over SSH but then times out on UDP now
  prints an actionable hint (the UDP port is likely firewalled; open it or use
  `--server-port`).

## [0.4.3]

### Changed

- **`noissh host` now connects automatically**: it first tries a direct UDP
  session to a standing server, and if none answers it falls back to the SSH
  bootstrap on its own (launching — and, if missing, installing — `noisshd` over
  SSH). `--ssh` now *forces* the bootstrap (skips the direct probe); the new
  `--direct` requires a direct connection and never falls back. A host-key
  mismatch on the direct attempt is a hard error and does not fall back.

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
