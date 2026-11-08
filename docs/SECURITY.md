# noissh Security Model

> **Status:** noissh is new software (0.x). The protocol and code have **not**
> been independently audited. The binding of Noise into QUIC (`noise-quic`,
> new in 0.7) had an internal review before release (see
> [Review of the Noise-in-QUIC binding](#review-of-the-noise-in-quic-binding));
> that is not a substitute for an independent audit. Do not rely on it for
> high-stakes use yet. Reports of security issues are welcome — see
> [Reporting](#reporting).

## Cryptographic foundation

Authentication and key agreement use the Noise Protocol Framework, pattern
`Noise_XX_25519_ChaChaPoly_BLAKE2s`, via the [`snow`](https://crates.io/crates/snow)
library. The `XX` pattern provides mutual authentication and identity hiding:
neither party reveals its static key to an unauthenticated peer until the
handshake commits.

The session runs over QUIC ([`quinn-proto`](https://crates.io/crates/quinn-proto),
built without TLS), with the Noise handshake as QUIC's crypto layer (crate
`noise-quic`, see [PROTOCOL.md](PROTOCOL.md) section 2):

- The handshake messages travel in QUIC CRYPTO frames under Initial and
  Handshake packet keys that are derived from public values (as QUIC's Initial
  keys are): they only obfuscate. Confidentiality and integrity of the
  handshake come from Noise itself: static keys and the server's transport
  parameters are encrypted in Noise messages 2 and 3, and the client's
  parameters (message 1) are bound into the transcript.
- Application data is protected with 1-RTT keys from Noise's split, mixed with
  the final handshake hash: ChaCha20-Poly1305 per packet (nonce from the packet
  number), ChaCha20 header protection, keyed BLAKE2s for key derivation, and
  periodic key updates (RFC 9001 §6).
- A private QUIC version number keeps standard QUIC/TLS peers out, and the
  Noise prologue binds the transcript to it.

## Trust model

noissh mirrors SSH's trust model with Noise static keys:

- **Server authentication (known_hosts / TOFU).** The client pins the server's
  static public key on first contact (`~/.config/noissh/known_hosts`). A later
  mismatch is a hard failure (`HOST KEY MISMATCH`), exactly like SSH. There is no
  certificate authority; trust is first-use or out-of-band.
- **Client authorization (authorized_keys).** The server holds the set of allowed
  client static public keys per user. The `XX` handshake proves the client holds
  the matching private key. **An unauthorized client key fails the handshake,
  before any 1-RTT key, session, stream or PTY exists.** The client likewise
  checks the server key before sending its own identity (message 3).
- **Key-based authentication.** The Noise static key *is* the cryptographic
  authentication, analogous to SSH public-key auth. There is no password stack to
  brute-force.
- **Reattach.** A detached shell is handed only to a connection authenticated
  with the same client key.

## What noissh protects against

- **Passive eavesdropping.** All session content is encrypted and authenticated.
- **Active tampering / injection.** Every packet is AEAD-authenticated; forged
  or modified packets are dropped, and corrupting a handshake packet only costs
  a retransmission.
- **Replay.** QUIC packet numbers: a packet number is accepted once.
- **Session hijacking via spoofed source address.** A connection moves to a new
  address **only after** a packet from it authenticates, and the server then
  validates the new path; an attacker who spoofs a source address but cannot
  produce a valid AEAD tag cannot steal or redirect a session.
- **Server impersonation.** Pinned known_hosts keys mean a substituted server key
  aborts the connection.

## What noissh does *not* protect against (current limitations)

- **Denial of service.** An attacker who can flood the UDP port can degrade
  service. Spoofed handshakes are contained: above 16 handshakes in progress a
  new client must answer a QUIC Retry before the server keeps any state, at
  most 256 handshakes run at once (separately from up to 512 established
  sessions, so they can't crowd out real or detached sessions), and an
  unfinished handshake is dropped after 10 s. An on-path attacker can still
  abort a handshake (see below). noissh is hardened against being used as a
  reflection/amplification vector: the client pads its first packet to 1200
  bytes, smaller ones get no answer, and until the client's address is
  validated the server sends at most three times what it received.
- **Traffic analysis.** Packet sizes and timing are not padded; an observer can
  infer activity (typing, screen updates).
- **Compromised endpoints.** noissh secures the link, not the machines. A
  compromised client or server is out of scope.
- **0-RTT / forward-secrecy edge cases for resumption.** Every connection
  performs a full `XX` handshake; resumption / `IK` with 0-RTT data (a possible
  future optimization) is not implemented, so there is no 0-RTT attack surface.

## Review of the Noise-in-QUIC binding

Before 0.7.0 the `noise-quic` crate was reviewed against the threat model above
(a network attacker who can read, drop, inject and modify packets; a client
without an authorized key; a server impersonating a pinned one). Findings and
their resolution:

| Finding | Severity | Resolution |
|---|---|---|
| Header protection panicked at ChaCha20 block counter `0xffffffff`; the counter comes from the packet, so one spoofed Initial crashed the server | critical | fixed: the mask is computed with the ChaCha20 core over the whole counter range; regression tests (unit and a forged packet against a real endpoint) |
| Half-open handshakes shared the session cap, so ~9 spoofed packets/s could lock out new clients | medium | fixed: Retry above 16 handshakes in progress, a separate cap of 256, 10 s handshake timeout; tested with a 300-packet flood |
| Handshake-level keys are public, so an observer can forge Handshake packets for the whole handshake | low | accepted (abort only, no impersonation or tampering); documented |
| Bytes after a Noise message were kept across a key change | low | fixed: refused (RFC 9001 §4.1.3) |
| Exporter input was ambiguous and didn't bind the output length | info | fixed (unused by noissh) |
| Secrets weren't wiped from memory | info | fixed: private keys and secrets are zeroized on drop |

Checked and found sound: transcript binding of both sides' transport
parameters; mutual authentication before any 1-RTT key exists, with the
client's identity sent only after the server's key is accepted; packet nonces
(IV XOR packet number) per direction and key generation; key separation
between levels and directions; the key-update chain; integrity limits; header
protection layout; per-token AEAD keys for address-validation tokens; the Retry
tag; the handshake state machine (no skipped or repeated messages, bounded
buffering); and the absence of panics reachable from network input apart from
the one fixed above.

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
  input — see the `security` and `wire` tests). QUIC packet processing is
  `quinn-proto`'s, a widely used implementation.
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
privileges on a client's behalf, **file transfer, agent forwarding and remote
commands are refused whenever a `--user` drop is configured.** Use the SSH-bootstrap model or
run the daemon as the target user to use these features.

## Cryptographic key storage

- Private keys are stored in the config directory with `0600` permissions.
- Keys are generated with the system CSPRNG (`getrandom`) via `snow`.
- QUIC connection ids are random; they are routing labels, not secrets.
  Stateless-reset and address-validation token keys are random per process.

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
