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

### File transfer & agent forwarding identity

File transfer (`--put`/`--get`) and SSH agent forwarding (`-A`) perform their I/O
in the session process — i.e. **as the same identity the session runs as**. In
the supported models (SSH bootstrap, the portable backend, or a daemon already
running as the target user) that identity *is* the authenticated user, so these
features can touch exactly what the user's own shell could touch — no more. File
paths are therefore not restricted to a sandbox or home directory, matching the
reach the user already has interactively.

The one case where the process identity would differ from the session identity
is a standalone daemon started as **root with a `--user` privilege drop**: there
the shell drops to the target user at exec, but the daemon process itself stays
root and cannot confine file/agent I/O to that user without in-process `setuid`
(deliberately avoided; see above). To prevent the daemon from acting with root
privileges on a client's behalf, **file transfer and agent forwarding are
refused whenever a `--user` drop is configured.** Use the SSH-bootstrap model or
run the daemon as the target user to use these features.

## Cryptographic key storage

- Private keys are stored in the config directory with `0600` permissions.
- Keys are generated with the system CSPRNG (`getrandom`) via `snow`.
- Session ids are random 64-bit values; they are demux labels, not secrets.

## Release integrity (supply chain)

Prebuilt binaries are built only by the GitHub Actions release workflow, never
uploaded by hand. Each release archive carries:

- a **SHA-256 checksum** (`.sha256`) — the installer verifies it before
  installing, and aborts on mismatch; and
- a **Sigstore build-provenance attestation** (via `actions/attest-build-provenance`),
  which cryptographically ties the artifact to the exact repository, commit, and
  workflow that produced it. Verify it with
  `gh attestation verify <file> --repo gedigi/noissh`.

Caveats and remaining trust assumptions:

- The `curl … | sh` convenience installer trusts TLS for the initial fetch of
  the script and binaries. The checksum protects against corruption/MITM of the
  archive specifically; for the strongest guarantee, verify the provenance
  attestation (above) or build from source (`cargo install --git`).
- A co-located `.sha256` alone does not defend against a fully compromised
  release (an attacker who can replace the binary could replace its checksum) —
  that is what the provenance attestation is for.

## Reporting

Please report suspected vulnerabilities privately to the maintainer rather than
opening a public issue, and allow reasonable time for a fix before disclosure.
