# noissh Security Model

> **Status:** noissh is new software (v0.1). The protocol and code have **not**
> been independently audited. Do not rely on it for high-stakes use yet. Reports
> of security issues are welcome — see [Reporting](#reporting).

## Cryptographic foundation

All session cryptography is the Noise Protocol Framework, pattern
`Noise_XX_25519_ChaChaPoly_BLAKE2s`, via the [`snow`](https://crates.io/crates/snow)
library. The `XX` pattern provides mutual authentication and identity hiding:
neither party reveals its static key to an unauthenticated peer until the
handshake commits. Transport data uses ChaCha20-Poly1305 AEAD with an explicit
per-datagram nonce.

## Trust model

noissh mirrors SSH's trust model with Noise static keys:

- **Server authentication (known_hosts / TOFU).** The client pins the server's
  static public key on first contact (`~/.config/noissh/known_hosts`). A later
  mismatch is a hard failure (`HOST KEY MISMATCH`), exactly like SSH. There is no
  certificate authority; trust is first-use or out-of-band.
- **Client authorization (authorized_keys).** The server holds the set of allowed
  client static public keys per user. The `XX` handshake proves the client holds
  the matching private key. **An unauthorized client key is rejected at handshake
  completion, before any session is created or any PTY/login work happens.**
- **Key-based authentication.** The Noise static key *is* the cryptographic
  authentication, analogous to SSH public-key auth. There is no password stack to
  brute-force. (An optional second factor over the control channel is defined in
  the protocol but not enabled by default.)

## What noissh protects against

- **Passive eavesdropping.** All session content is encrypted and authenticated.
- **Active tampering / injection.** Every datagram is AEAD-authenticated; forged
  or modified datagrams are dropped.
- **Replay.** A per-direction 64-packet sliding-window filter drops replayed or
  too-old datagrams (on top of Noise's strictly increasing nonces).
- **Session hijacking via spoofed source address.** Roaming updates the peer
  address **only after** a datagram authenticates, so an attacker who spoofs a
  source address but cannot produce a valid AEAD tag cannot steal or redirect a
  session.
- **Server impersonation.** Pinned known_hosts keys mean a substituted server key
  aborts the connection.

## What noissh does *not* protect against (current limitations)

- **Denial of service.** An attacker who can flood the UDP port can degrade
  service. There is no proof-of-work or cookie exchange before the handshake;
  each unknown session-id handshake allocates a small amount of state. This is a
  known area for hardening.
- **Traffic analysis.** Packet sizes and timing are not padded; an observer can
  infer activity (typing, screen updates).
- **Compromised endpoints.** noissh secures the link, not the machines. A
  compromised client or server is out of scope.
- **0-RTT / forward-secrecy edge cases for resumption.** v1 always performs a
  full `XX` handshake; resumption tickets / `IK` (a future optimization) are not
  implemented, so there is no 0-RTT attack surface yet.

## Memory safety

The entire codebase is `#![forbid(unsafe_code)]` — there is **no `unsafe` in any
noissh crate or binary**. The few operations that need OS primitives (PTY
allocation, fork/exec, daemonization, terminal ioctls) are delegated to
well-tested safe-API crates (`pty-process`, `daemonize`, `nix`, `terminal_size`),
so the whole protocol and privilege surface is written in safe Rust.

## Privilege model

The scariest surface in any network shell daemon is privileged code. noissh keeps
it minimal:

- All parsing, crypto, and protocol handling run in **unprivileged**, safe code
  and are fuzzed (the frame parser and packet handler never panic on arbitrary
  input — see the `security` and `wire` tests).
- The portable login backend allocates a real PTY and runs the shell as the
  **current user** with **no root** required.
- **Multi-user deployments use the SSH-bootstrap model:** the SSH bootstrap
  (`noissh --ssh`) launches the server *as the already-authenticated user* over
  SSH, so the session process is the right user from the start — no in-process
  `setuid` is performed, avoiding the well-known supplementary-group pitfalls of
  privilege dropping.
- A standalone daemon running as root can optionally drop to a target user's
  `uid`/`gid` before exec (via the safe `pty-process` API). This basic drop does
  not initialise supplementary groups; for full fidelity prefer the SSH-bootstrap
  model or run the daemon already as the target user (e.g. via a systemd unit).

## Cryptographic key storage

- Private keys are stored in the config directory with `0600` permissions.
- Keys are generated with the system CSPRNG (`getrandom`) via `snow`.
- Session ids are random 64-bit values; they are demux labels, not secrets.

## Reporting

Please report suspected vulnerabilities privately to the maintainer rather than
opening a public issue, and allow reasonable time for a fix before disclosure.
