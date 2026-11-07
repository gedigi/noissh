# Design: noissh 0.7 transport on QUIC (quinn-proto) with Noise

Status: **proposal** — for review before implementation.

## 1. Why

Field testing VS Code Remote-SSH over noissh 0.6 (Italy ↔ Finland, ~40 ms RTT)
and a local UDP proxy that adds the same latency exposed the limits of the
hand-written transport:

| Problem | Measured | Root cause |
|---|---|---|
| Throughput | 2 MB in 14 s (140 KB/s) in 0.6.4; 880 KB/s with the 0.6.5 timer fix, against a 256 KiB window that allows ~6 MB/s at 40 ms | RTO/RTT counted in loop iterations (fixed in 0.6.5); sending only on ticks; 1 KiB chunks; per-stream acks; timeout-only loss recovery; no pacing |
| Idle chatter | server ~90 pkts/s (0.6.3), client ~50 pkts/s (0.6.4) | acks re-sent on every tick (fixed in 0.6.4 / 0.6.5) |
| Router blocking the server | after ~20 s of the above | consequence of the chatter |
| Terminal lag during transfers | typing stalls while VS Code syncs | no prioritisation between interactive and bulk data |

Each of these was a bug in code that general-purpose transports solved long ago.
Rather than keep re-deriving TCP/QUIC loss recovery, congestion control, pacing
and flow control, noissh 0.7 adopts a mature QUIC state machine and keeps what
is genuinely noissh's own: the Noise identity model, the roaming/resumable
session, and the predictive terminal.

### Why this can beat ssh

ssh multiplexes every channel (shell, forwards, VS Code's tunnels, file copies)
over **one TCP connection**:

- one lost packet stalls every channel until it is retransmitted
  (head-of-line blocking);
- a network change or sleep kills the TCP connection: reconnecting costs TCP +
  key exchange + authentication (several RTTs), and the tools on top must
  recover their own state;
- TCP gives no way to prioritise the shell over a bulk transfer in the same
  connection.

QUIC streams are independent (a loss stalls only its own stream), connections
migrate across addresses natively, and the scheduler can put interactive
traffic first. On top of that noissh keeps local echo prediction, so typing
feels instant regardless of RTT.

## 2. Goals and non-goals

Goals, each with a benchmark target (section 9):

1. **Throughput** within 80 % of the path's capacity for bulk transfers (scp,
   VS Code sync), matching or beating ssh on clean links and clearly beating it
   with loss.
2. **Interactive latency**: keystroke-to-echo bounded by RTT (prediction makes
   it ~0 perceived), and *unaffected* by a concurrent bulk transfer.
3. **Idle cost**: ≤ 1 packet/s each way on an idle session.
4. **Resilience**: survive address changes, NAT rebinding and sleep without the
   applications noticing; reattach to the same shell after a client restart.
5. **Security**: unchanged model — Noise XX, mutual X25519 authentication,
   server key pinning (TOFU / ssh-bootstrap pin), `authorized_keys`.

Non-goals for 0.7: compatibility with 0.6 peers (clean break, agreed); TLS or
certificates; multi-user privilege separation beyond what exists today;
0-RTT (planned for a later release, section 7).

## 3. Architecture

```
noissh / noisshd
├── session layer (noissh's own)
│     shell state-sync + input, exec, forwards, SOCKS, agent, file transfer,
│     reattach-by-client-key, control messages
├── quinn-proto  (sans-IO QUIC state machine: streams, datagrams, loss
│                 recovery, Cubic/BBR congestion control, pacing, flow control,
│                 connection migration, keep-alive, idle timeout)
├── noise-quic   (new crate: quinn_proto::crypto::{Session, ClientConfig,
│                 ServerConfig} implemented with snow, Noise XX)
└── UDP driver   (poll-based, non-blocking; later GSO / recvmmsg via quinn-udp)
```

`quinn-proto` is the sans-IO core of the `quinn` QUIC implementation: no async
runtime, no sockets, no TLS required (built with `default-features = false`,
it pulls only `bytes`, `rand`, `tracing`, `slab`, `rustc-hash`, `lru-slab`,
`tinyvec`, `thiserror`; MIT/Apache-2.0). noissh drives it from its existing
synchronous poll loops, which keeps the binary small and the code free of an
async runtime.

The crates `transport/` (session ids, anti-replay, input channel, stream mux)
and the outer framing in `wire/` are replaced. `term/`, `predict/`, `auth/`,
`pty/` are unchanged. `proto/`'s state-sync plane and control messages are kept
and carried over QUIC (section 5).

## 4. Crypto: Noise inside QUIC (`noise-quic` crate)

QUIC delegates its handshake to a pluggable crypto layer; quinn-proto exposes it
as the `crypto::Session` trait (handshake bytes per encryption level, packet
and header-protection keys, key update, retry and reset tokens). TLS 1.3 is the
usual implementation; noissh plugs in Noise.

### Handshake: Noise XX over QUIC CRYPTO frames

`Noise_XX_25519_ChaChaPoly_BLAKE2s`, the pattern noissh already uses:

```
client                                   server
  Initial:   msg1  → e          [payload: client QUIC transport params]
  Initial:   msg2  ← e, ee, s, es [payload: server QUIC transport params + version]
  Handshake: msg3  → s, se      [payload: empty]
  1-RTT keys from Noise Split()
```

- **Transport parameters** travel in the Noise payloads, so they are bound to
  the handshake transcript: tampering with the client's (msg1 payload is not
  encrypted) changes the transcript hash and the handshake fails at msg2/msg3.
  The server's are encrypted in msg2.
- **Initial keys** are derived from the client's destination connection id
  with a noissh-specific salt (as QUIC does): obfuscation only, like QUIC's.
  Noise messages carry their own protection.
- **Handshake-level keys** (for msg3 and handshake-space ACKs) are derived from
  the Noise handshake hash after msg2 plus a key exported for the purpose; see
  open question Q1.
- **1-RTT keys**: `snow`'s split (feature `risky-raw-split`) gives the two raw
  32-byte cipher keys. From each, HKDF-SHA256 derives the packet key, IV and
  header-protection key (RFC 9001 §5 labels with a noissh prefix). Packets use
  ChaCha20-Poly1305 with the QUIC nonce (IV XOR packet number) and the header as
  AAD; header protection uses ChaCha20 (RFC 9001 §5.4.4). Both come from the
  `chacha20poly1305` / `chacha20` crates already in the dependency tree.
- **Key update** (`next_1rtt_keys`): HKDF "noissh ku" over the current secret,
  as RFC 9001 §6.
- **Authentication**: after msg3 the server checks the client's static key
  against `authorized_keys`; the client checks the server's static key against
  `known_hosts` or the ssh-bootstrap pin. Failure closes the connection with a
  crypto error before any application stream is accepted. Peer identity is
  exposed via `Session::peer_identity`.
- **Retry tokens, stateless reset, address-validation tokens**: HMAC and AEAD
  keys derived from a random per-process secret (server), provided through
  quinn-proto's `HmacKey` / `HandshakeTokenKey` traits.

### Version and ALPN

A private QUIC version number (`0x6e6f6973`, "nois") marks noissh 0.7, so a
noissh server never accepts a standard QUIC/TLS client and vice versa, and a
later incompatible change can use a new version and negotiate.

## 5. Mapping noissh onto QUIC

| noissh 0.6 | 0.7 |
|---|---|
| session id + roaming | QUIC connection ids + connection migration / NAT rebinding (built in) |
| anti-replay window | QUIC packet numbers (built in) |
| `StreamMux` streams (exec, forward, agent, xfer) | one bidirectional QUIC stream each; first bytes: kind + metadata header |
| exec stderr (extra server-opened stream) | a second, server-opened unidirectional stream |
| control messages (OpenShell, Resize, RemoteForward, Bye, …) | a bidirectional control stream opened first by the client |
| shell input (reliable byte stream) | a QUIC stream, highest priority |
| screen state (latest-wins diffs) | QUIC DATAGRAM frames (RFC 9221; unreliable, congestion-controlled), same SSP-style diff/ack logic as today, acks on the control stream |
| keepalive | QUIC keep-alive (PING) every 15 s |
| idle reap (~minutes) | QUIC idle timeout off/long + noissh's own detach/reattach timer |

**Prioritisation**: quinn-proto schedules streams by priority. Shell input,
screen datagrams and the control stream get the highest priority; VS Code /
forward streams the default; file transfers below. A bulk transfer can no
longer delay keystrokes.

**Reattach after client restart**: a new QUIC connection whose authenticated
client key owns a detached shell takes it over (today's logic, keyed by client
static key), then receives a full screen snapshot.

**Remote command / VS Code flow** (`noissh -T -D <port> host`): unchanged at
the CLI; underneath, the login shell is an exec stream and each SOCKS
connection is a forward stream.

## 6. I/O driver

- One non-blocking UDP socket per endpoint; `poll()` on the socket, the TTY,
  stdin and local TCP sockets; wake on quinn-proto's `poll_timeout()` instead of
  fixed ticks, so nothing is sent unless the state machine asks for it.
- Batch: drain all readable datagrams, then all `poll_transmit()` output, per
  wake-up.
- Later: GSO/GRO and `recvmmsg` through `quinn-udp` (safe API) for high
  throughput on Linux.

The server stays single-threaded at first; a busy session cannot starve others
because every operation is non-blocking.

## 7. Later: 0-RTT reconnect

With the server's static key pinned, the client can use Noise **IK** instead of
XX and send application data in its first flight (QUIC 0-RTT through
`early_crypto`). After sleep or a network change that QUIC migration can't
cover (e.g. the client process restarted), reconnecting then costs zero round
trips. Out of scope for 0.7.0; the version number leaves room for it.

## 8. Milestones

1. **noise-quic**: the crypto `Session` + configs, with unit tests: handshake
   between two in-memory quinn-proto endpoints, key update, wrong server key
   rejected, unauthorised client rejected, tampered transport params rejected.
2. **Benchmark harness** (section 9), measuring 0.6 first as the baseline.
3. **Transport driver + streams**: exec, forwards, SOCKS, agent, file transfer
   over QUIC; the VS Code test (`tests/ssh_compat.rs`) passes.
4. **Shell**: input stream + state-sync datagrams + prediction; reattach.
5. **Remove the 0.6 transport**; protocol and architecture docs updated.
6. **Tuning** against the benchmark (congestion controller choice, priorities,
   GSO), then release 0.7.0.

Each milestone keeps `cargo test`, clippy and fmt green and is a separate PR.

## 9. Benchmark

A `bench/` harness, run locally and in CI (Linux), with a userspace impairment
proxy (UDP for noissh, TCP for ssh) adding configurable one-way delay, jitter
and loss — no root or `tc` needed.

Scenarios: RTT ∈ {1, 40, 150} ms × loss ∈ {0, 1, 5} %.

Metrics, each compared against OpenSSH over the same impairment:

- bulk throughput (20 MB through `-D`/`-L`, and file transfer);
- keystroke-to-echo latency: idle, and during a concurrent bulk transfer;
- idle packets/s each way;
- time to recover after an address change, and after 30 s of total outage.

Targets: throughput ≥ ssh on clean links and ≥ 2× ssh at 1 % loss; echo latency
during bulk transfer within 1.5× of idle; idle ≤ 1 pkt/s each way.

## 10. Risks and open questions

- **Q1 — handshake-level keys.** QUIC expects distinct Handshake-space keys
  before the handshake completes. Options: (a) carry msg3 in the Initial space
  and switch straight to 1-RTT (needs checking against quinn-proto's state
  machine); (b) derive Handshake keys from an intermediate Noise secret. `snow`
  exposes the handshake hash (public) but not the chaining key, so (b) needs
  care. Milestone 1 settles this with a working implementation and tests.
- **Q2 — screen state over DATAGRAM vs a stream.** Datagrams keep latest-wins
  semantics (no retransmitting stale screens); size is bounded by the path MTU,
  so large diffs need splitting or a fallback to a stream. To prototype in
  milestone 4.
- **Security review** of the Noise ↔ QUIC binding before release: transcript
  binding of transport parameters, key separation between levels, nonce use.
- **Dependency footprint**: acceptable (listed above); `cargo deny` stays green.
