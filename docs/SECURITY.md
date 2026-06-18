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
- **PAM split (sshd model).** The Noise static key *is* the cryptographic
  authentication (PAM's `auth` stack is bypassed, like SSH pubkey auth). When the
  Linux privsep backend with the `pam` feature is used, PAM still runs
  `acct_mgmt` (account validity) and `open_session`/`close_session` (logind
  registration, limits, env). An optional second factor over the control channel
  is specified but not enabled by default.

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
  infer activity (typing, screen updates), as with mosh.
- **Compromised endpoints.** noissh secures the link, not the machines. A
  compromised client or server is out of scope.
- **0-RTT / forward-secrecy edge cases for resumption.** v1 always performs a
  full `XX` handshake; resumption tickets / `IK` (a future optimization) are not
  implemented, so there is no 0-RTT attack surface yet.

## Privilege separation

The scariest surface in any network shell daemon is privileged code. noissh keeps
it minimal:

- All parsing, crypto, and protocol handling run in **unprivileged** code paths
  and are fuzzed (the frame parser and packet handler never panic on arbitrary
  input — see the `security` and `wire` tests).
- The portable `LocalLogin` backend runs the shell as the **current user** and
  needs **no root**.
- The Linux `PrivsepLogin` backend performs `setgid` → `initgroups` → `setuid`
  (in that order) before exec, with PAM session setup, only when run as root.
  PAM is behind the `pty/pam` cargo feature so the default build pulls in no PAM
  code at all.

## Cryptographic key storage

- Private keys are stored in the config directory with `0600` permissions.
- Keys are generated with the system CSPRNG (`getrandom`) via `snow`.
- Session ids are random 64-bit values; they are demux labels, not secrets.

## Reporting

Please report suspected vulnerabilities privately to the maintainer rather than
opening a public issue, and allow reasonable time for a fix before disclosure.
