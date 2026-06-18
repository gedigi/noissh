# noissh — design

## Context

`noissh` is a remote-shell utility that aims to be **exceptionally resilient** (instant feel
on lossy/high-latency links, survives IP changes, NAT rebinding, and laptop sleep, no
reconnect) and **as rich as SSH** (port forwarding, file transfer, agent forwarding),
built entirely on the **Noise Protocol Framework** for its cryptography rather than
SSH's bespoke crypto or TLS.

Motivation: the author wrote [noisecat](https://github.com/gedigi/noisecat) (a
netcat-over-Noise tool) and wants a "Noise all the way down" SSH equivalent. Noise's
static-key handshake maps cleanly onto SSH's `authorized_keys`/`known_hosts` trust model,
and its formal security properties (mutual auth, identity hiding, KCI resistance) apply to
the whole session.

The interesting, novel engineering here is the **hybrid resilient transport + predictive
TTY overlay** — not reinventing sshd's privilege/login machinery, which we reuse via PAM.

## Decisions (settled during brainstorming)

| Area | Decision |
|---|---|
| Transport spine | **Hybrid**: unreliable latest-wins datagrams for the interactive shell + reliable multiplexed streams for richness |
| Bootstrap/auth model | **Pure standalone daemon** (no SSH dependency, ever) |
| Authentication | Noise static-key handshake (≈ `authorized_keys`) + **PAM** for account/session/optional 2FA |
| Privilege | sshd-style **privilege separation** + setuid-to-user + PTY allocation |
| Language | **Rust** (`snow`, `nix`, `pam`) |
| Transport substrate | **mini-QUIC-with-Noise** — lean Noise-native layer mirroring QUIC's frame model |
| Crypto framework | **Noise is non-negotiable** — QUIC-with-TLS rejected |
| TTY for v1 | **Full predictive TTY**: state-sync **and** client-side predictive echo |

## Architecture

```
┌────────────────────── noisshd (root) ──────────────────────┐
│  listener: UDP socket, demux by session-id                  │
│                                                             │
│  ┌── privileged monitor (tiny, audited) ──┐                 │
│  │  pam_acct_mgmt → pam_open_session       │                │
│  │  setuid/setgid/initgroups → PTY → shell │                │
│  └────────────▲────────────────────────────┘                │
│               │ post-auth handoff (fd passing)              │
│  ┌── unprivileged session worker (per session) ──────────┐  │
│  │  Noise handshake (snow) + per-packet AEAD             │  │
│  │  session/transport layer (frames, ACKs, migration)    │  │
│  │  terminal emulator (authoritative screen state)       │  │
│  │  state-sync encoder (latest-wins screen diffs)        │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                         ▲ Noise-encrypted UDP
                         ▼
┌────────────────────── noissh (client) ─────────────────────┐
│  Noise handshake + known-hosts pinning (TOFU)               │
│  session/transport layer (roaming: send from any addr)      │
│  predictive-echo engine (guess → paint underlined →         │
│                          reconcile vs server truth)         │
│  local terminal renderer + raw-mode tty                     │
└─────────────────────────────────────────────────────────────┘
```

### Components (each independently testable)

1. **Noise session core** (`noise/`) — wraps `snow`. Handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`),
   transport-mode AEAD, rekeying. Pure function of bytes-in/bytes-out; no I/O. Knows nothing
   about UDP, terminals, or PAM.
2. **Transport/session layer** (`transport/`) — the mini-QUIC-with-Noise layer. Owns the
   wire frame format, the **cryptographic session id**, reliable-stream machinery (v2) and
   unreliable datagram delivery (v1), ACK/loss handling, congestion control, and **roaming**
   (update peer address on any authenticated packet). Sits *above* the Noise core (Noise
   encrypts each datagram; transport sees plaintext frames).
3. **Terminal model** (`term/`) — server-side authoritative emulator + screen-state
   representation + latest-wins diff encoder/decoder. Clean-room (no third-party GPL code).
4. **Predictive echo engine** (`predict/`) — client-side only. Echo-safety heuristics,
   cursor prediction, abandon-bad-guess reconciliation against authoritative diffs.
5. **Auth & PAM** (`auth/`) — `authorized_keys`-equivalent parsing, Noise static-key
   verification, PAM conversation (`pam_acct_mgmt`/`open_session`/`setcred`/optional
   `authenticate` tunneled over the Noise control channel).
6. **Privilege separation / login** (`privsep/`) — the privileged monitor: minimal surface
   that, post-auth, does `pam_open_session` → `setuid`/`setgid`/`initgroups` → allocate PTY →
   exec login shell. Communicates with the unprivileged worker via a narrow fd-passing IPC.
7. **CLI / config** (`cli/`) — `noissh` (client) and `noisshd` (server) binaries; config
   files; `known_hosts`/`authorized_keys` formats; systemd unit.

## Authentication & trust model

- **Server authentication / known-hosts:** client pins the server's Noise static public key.
  First contact = **TOFU** (Trust On First Use), recorded in `~/.config/noissh/known_hosts`
  keyed by host. Mismatch on later connects = hard failure, exactly like SSH.
- **Client authentication:** server holds an `authorized_keys`-equivalent of allowed client
  static public keys per local user (`~user/.config/noissh/authorized_keys`). The `XX`
  handshake proves the client holds the matching private key.
- **PAM split (sshd model):** the Noise static key *is* the cryptographic authentication
  (PAM's `auth` stack is bypassed, just like SSH pubkey auth). PAM still runs **`acct_mgmt`**
  (account validity) and **`open_session`/`close_session`** (logind registration, `pam_limits`,
  `loginuid`, motd, env). `pam_authenticate` is available as an **optional second factor**
  (password/OTP), tunneled over the Noise control channel like SSH `keyboard-interactive`.
- **Handshake pattern:** `XX` for first contact (mutual auth + identity hiding; neither party
  reveals its static key to an unauthenticated peer until the handshake commits). Once the
  server key is pinned, reconnects still use `XX` but require no human trust decision. A
  resumption ticket (or `IK`) for 0-RTT fast resume is a post-v1 optimization.

## Resilience mechanism (how roaming works)

- Every datagram carries the **session id** and is individually AEAD-authenticated under the
  Noise transport keys.
- The server demuxes incoming datagrams **by session id, not by source IP:port**. On any
  validly-authenticated datagram from a new address, it updates its notion of the peer's
  address. → survives IP change, NAT rebind, Wi-Fi↔cellular handoff, laptop sleep/resume,
  with no reconnect.
- The interactive shell rides **unreliable, latest-wins datagrams** (state-sync), so packet
  loss never stalls a byte stream — only the newest screen state matters. This is the same
  property that keeps an interactive session feeling alive on terrible links.
- Anti-replay: per-direction nonce window (Noise gives strictly increasing nonces); the
  transport layer additionally tracks a sliding window to drop replayed/very-old datagrams.

## TTY / predictive echo (v1, full predictive echo)

- **Server** runs the authoritative terminal emulator, owns the true screen, and emits
  latest-wins diffs of (screen grid, cursor, modes) toward the client.
- **Client** runs the **predictive echo engine**: on each keystroke it predicts the visible
  effect (echo of printable chars, cursor motion), paints predictions immediately (visually
  distinct, e.g. underline), tracks outstanding predictions, and reconciles/abandons them as
  authoritative diffs arrive. Heuristics decide when prediction is *safe* (e.g. don't predict
  inside what looks like a password prompt or a full-screen app until confidence is high).

## Scope — both v1 and v2 are committed deliverables

This plan covers the full path to a highly resilient, SSH-rich tool. v1 ships the resilient
interactive shell; v2 builds the reliable-stream layer on the **same session core** to
deliver SSH's richness. Both are in scope; v1 simply lands first because it de-risks v2.

**v1 — resilient interactive shell:**
- `noisshd` standalone privsep daemon + `noissh` client.
- `XX` Noise handshake, known-hosts TOFU, `authorized_keys` client auth, PAM acct/session.
- Noise/UDP session layer with session-id roaming and unreliable latest-wins datagrams.
- Server authoritative terminal emulator + state-sync.
- Client predictive-echo engine (instant local echo).
- Window-resize propagation, UTF-8, basic `noissh user@host` CLI, config + known_hosts files.

**v2 — SSH richness (reliable multiplexed streams):**
- **Reliable stream multiplexer** on the existing session: ordered, flow-controlled byte
  streams sharing the same Noise/UDP session and roaming as the v1 datagram path. The wire
  frame format is designed in v1 to carry both classes, so v2 adds stream frames + ARQ +
  congestion control without a protocol break.
- **Local & remote port forwarding** (`-L`/`-R` semantics): each forwarded connection = one
  reliable stream; a control message opens/closes streams and carries connect metadata.
- **File transfer** (`scp`-like and an `sftp`-like subsystem): a file-transfer subsystem
  rides a reliable stream; resumable transfers benefit directly from session roaming.
- **Agent forwarding:** forward the local SSH/Noise agent socket over a reliable stream
  (server-side `$SSH_AUTH_SOCK`-equivalent proxy).
- **Session multiplexing:** multiple shells/exec channels over one session (SSH `ControlMaster`
  analog), each its own stream.
- **0-RTT fast resume:** resumption ticket (or `IK`) so reconnects after the first skip a
  round trip.
- **Optional PAM second factor** (password/OTP) tunneled over the Noise control channel.

**Non-goals:** Windows *server* (no PAM; a client may come later), X11 forwarding,
GSSAPI/Kerberos, SSH wire-protocol compatibility/interop.

## Key risks & mitigations

- **Privsep + setuid in a network daemon** is the scariest surface → keep the privileged
  monitor tiny and audited; all parsing/crypto/protocol runs unprivileged; fuzz the frame
  parser and handshake.
- **Predictive-echo heuristics** are the fiddliest code → build behind the state-sync core so
  it can be developed/tested in isolation against recorded sessions.
- **Reinventing transport reliability** (v2) → borrow proven congestion-control logic; v1
  needs no reliable streams at all, so this risk is deferred.

## Verification

- **Unit:** Noise core (test vectors), frame codec (round-trip + fuzz), terminal emulator
  (against known escape-sequence corpora), diff encoder/decoder (property tests:
  apply(diff(a,b)) == b).
- **Resilience harness:** a UDP shim that injects loss/latency/reorder and **rewrites source
  address mid-session** to prove roaming; assert the session survives and screen converges.
- **Predictive-echo replay:** record real server diff streams, replay against the client
  engine, assert predictions reconcile to the authoritative state with no residual artifacts.
- **End-to-end:** `noisshd` on localhost (and a Linux VM for real PAM/setuid), `noissh`
  connects, run an interactive session, suspend the network / change the client's source port,
  confirm seamless resume. Manual: `vim`/`htop`/`tmux` feel test over `tc netem`-shaped links.
- **Security:** fuzz handshake + frame parser; verify known-hosts mismatch aborts; verify an
  unauthorized client key is rejected before any PAM/session work happens.
- **v2 streams:** property tests on the multiplexer (ordered/lossless delivery under injected
  loss+reorder); forwarding round-trips real TCP through `-L`/`-R`; file-transfer integrity
  (hash match) **including a transfer interrupted by a forced source-address change** to prove
  streams survive roaming; agent forwarding authenticates a downstream hop.

## Build sequence (high level)

**v1:**
1. Noise session core + frame codec (no I/O), with fuzz/test vectors. **Frame format reserves
   space for both datagram and stream frame classes from day one** so v2 needs no wire break.
2. UDP transport: session-id demux, datagram delivery, roaming, anti-replay.
3. Server terminal emulator + state-sync diff protocol.
4. Privsep monitor + PAM acct/session + setuid + PTY (Linux VM).
5. Client: handshake + known-hosts + raw-mode renderer applying diffs.
6. Predictive-echo engine + reconciliation.
7. CLI, config files, systemd unit, end-to-end + resilience harness.

**v2 (same session core, additive):**
8. Reliable stream multiplexer: stream frames, ordered delivery, flow control, ARQ +
   congestion control; verify streams and the v1 datagram overlay coexist and both roam.
9. Control protocol for opening/closing streams (channel-open/close, exit status).
10. Port forwarding (`-L`/`-R`) on top of streams.
11. File-transfer subsystem (`scp`-like + `sftp`-like), resumable across roams.
12. Agent forwarding (remote `$SSH_AUTH_SOCK` proxy over a stream).
13. Session multiplexing (multiple shells/exec per session).
14. 0-RTT fast resume (resumption ticket / `IK`) and optional PAM second-factor flow.
