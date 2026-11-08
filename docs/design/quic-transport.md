# Design: noissh 0.7 transport on QUIC (quinn-proto) with Noise

Status: **implemented and released in 0.7.0** (milestones 1–6; the 0.6
transport is removed). Measurements are in section 9, the security review in
section 10. The
protocol as built is specified in [PROTOCOL.md](../PROTOCOL.md).

## 1. Why

Field testing VS Code Remote-SSH over noissh 0.6 (Italy ↔ Finland, ~40 ms RTT)
and a local UDP proxy that adds the same latency exposed the limits of the
hand-written transport:

| Problem | Measured | Root cause |
|---|---|---|
| Throughput | 2 MB in 14 s (140 KB/s) in 0.6.4; 880 KB/s with the wall-clock timer fix (unreleased), against a 256 KiB window that allows ~6 MB/s at 40 ms | RTO/RTT counted in loop iterations (fixed, unreleased); sending only on ticks; 1 KiB chunks; per-stream acks; timeout-only loss recovery; no pacing |
| Idle chatter | server ~90 pkts/s (0.6.3), client ~50 pkts/s (0.6.4) | acks re-sent on every tick (fixed in 0.6.4 and unreleased) |
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

Implemented in `crates/noise-quic` (milestone 1).

`Noise_XX_25519_ChaChaPoly_BLAKE2s`, the pattern noissh already uses, with the
prologue `"noissh-quic"` + the QUIC version so a transcript from another context
can't be replayed here. Each Noise message travels in CRYPTO frames prefixed
with its length (u16, big endian), since CRYPTO data can be split or merged
arbitrarily:

```
client                                         server
  Initial:   msg1 → e            [payload: client transport parameters]
  Handshake: msg2 ← e, ee, s, es [payload: server transport parameters]
  Handshake: msg3 → s, se        [payload: empty]
  1-RTT keys from Noise Split()
```

- **Why msg2 is at the Handshake level.** In quinn-proto a client becomes
  established only on receiving a Handshake-level packet, and a server discards
  the Handshake level as soon as its handshake completes. With msg2 at the
  Initial level the server would have nothing to send at the Handshake level
  after msg3 and the handshake could stall. So the client moves to the
  Handshake level right after sending msg1, and msg2 and msg3 both travel there.
- **Initial and Handshake keys are public**, i.e. obfuscation only, exactly
  like QUIC's Initial keys: Initial from the client's destination connection
  id, Handshake from the Noise handshake hash after msg1, each with its own
  salt. Everything the handshake must protect is protected by Noise itself:
  the static keys and the server's transport parameters are encrypted inside
  msg2/msg3; the client's parameters (msg1, unencrypted) are bound to the
  transcript, so changing them makes the client fail to decrypt msg2 (tested).
  An on-path attacker can disrupt the handshake but cannot impersonate either
  side or alter what they agree on. Note the disruption window is the whole
  handshake, not just the Initial level as with TLS: anyone who saw msg1 can
  derive the Handshake keys and forge Handshake-level packets (security review,
  section 10). Keying msg2/msg3 from `ee` would close it; not done in 0.7.
- **1-RTT keys**: `snow`'s split (feature `risky-raw-split`) gives the two raw
  32-byte cipher keys; each is mixed with the final handshake hash into that
  direction's secret. Packets use ChaCha20-Poly1305 with the QUIC nonce (IV XOR
  packet number) and the header as AAD; header protection uses ChaCha20
  (RFC 9001 §5.4.4).
- **Key derivation** uses keyed BLAKE2s-256 as a PRF (the hash of the Noise
  suite in use), one call per derived value with distinct labels: packet key,
  IV and header-protection key per direction, the key-update chain
  (RFC 9001 §6, header-protection keys unchanged across updates), and an
  exporter secret for `export_keying_material`.
- **Authentication**: the client checks the server's static key (against
  `known_hosts` or the ssh-bootstrap pin) as soon as msg2 arrives, before
  sending msg3; the server checks the client's against `authorized_keys` after
  msg3. A rejected key fails the handshake with crypto error 0x2a
  (`bad_certificate`) and a reason ("server key not trusted" / "client key not
  authorized") before any 1-RTT key exists. The authenticated key is exposed
  through `Session::peer_identity` as `noise_quic::PeerIdentity`.
- **Retry integrity tag**: ChaCha20-Poly1305 with a fixed noissh key over the
  RFC 9001 §5.8 pseudo-packet. **Stateless reset and address-validation
  tokens**: keyed BLAKE2s and per-token ChaCha20-Poly1305 keys derived from
  random per-process secrets (`Blake2sHmac`, `TokenKey`).

Tests (`cargo test -p noise-quic`): a full handshake between two in-memory
quinn-proto endpoints carrying a 200 KB stream and datagrams; rejection of an
unexpected server key and of an unauthorized client; transcript binding of the
client's parameters; 25 % packet loss during the handshake; key updates;
CRYPTO reassembly from 1-byte chunks; packet and header protection round
trips and tamper detection; retry tags.

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
| exec stderr (extra server-opened stream) | a second, server-opened bidirectional exec stream; the exit code in an `ExecExit` control message |
| control messages (OpenShell, Resize, RemoteForward, Bye, …) | a bidirectional control stream opened first by the client |
| shell input (reliable byte stream) | `Input` frames on the control stream (highest priority) |
| screen state (latest-wins diffs) | QUIC DATAGRAM frames (RFC 9221; unreliable, congestion-controlled), on the control stream when a diff doesn't fit; same SSP-style diff/ack logic, acks on the control stream |
| keepalive | QUIC keep-alive (PING) after 3 s of silence; every second while the link looks dead |
| idle reap (~minutes) | QUIC idle timeout (60 s); a shell then stays detached for 15 minutes; the client reconnects on its own |

**Prioritisation**: quinn-proto schedules streams by priority. Shell input,
screen datagrams and the control stream get the highest priority; VS Code /
forward streams the default; file transfers below. A bulk transfer can no
longer delay keystrokes.

**Reattach**: a new connection's `OpenShell` takes over a running shell of the
same client key whose connection is gone, or silent for 8 s (its client
restarted), then receives a full screen snapshot. Unlike 0.6, a shell whose
connection is alive is never taken, so a second window gets its own shell.

**Remote command / VS Code flow** (`noissh -T -D <port> host`): unchanged at
the CLI; underneath, the login shell is an exec stream and each SOCKS
connection is a forward stream.

## 6. I/O driver

- One non-blocking UDP socket per endpoint; `poll()` on the socket, the TTY,
  stdin and local TCP sockets; wake on quinn-proto's `poll_timeout()` instead of
  fixed ticks, so nothing is sent unless the state machine asks for it.
- Batch: drain all readable datagrams, then all `poll_transmit()` output, per
  wake-up.
- Once established, a received datagram only feeds QUIC; events, stream data
  and replies are processed once per batch.
- Descriptors whose stream is backed up (or at EOF) aren't polled for input,
  so a slow peer or a closed socket can't make the loop spin.
- Batched I/O through `quinn-udp` (safe API, `src/udp.rs`): GSO sends of up
  to 32 datagrams per call, `recvmmsg` and GRO receives, ECN both ways; a
  batch the socket can't take yet waits in a queue (polled for writability)
  rather than being dropped, and one the kernel refuses as a whole is resent
  datagram by datagram.

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

Each milestone keeps `cargo test`, clippy and fmt green. Milestones 3–5 landed
together: the cores kept their public interface, so replacing the transport
under them in one step was simpler than running both side by side.

Decisions taken while implementing: BBR instead of Cubic (Cubic reached
0.43 MB/s at 1 % loss and 40 ms; BBR 19–27 MB/s); the ACK-frequency
extension (acknowledge every 8th packet) to halve the receiver's per-packet
work; screen diffs paced at most every 8 ms, resent after 1.5 × RTT + 10 ms.

## 9. Benchmark

A `bench/` harness (`noissh-bench`, see `bench/README.md`), with a userspace
impairment proxy (UDP for noissh, TCP for ssh) adding configurable one-way
delay, jitter and loss — no root or `tc` needed. Loss is simulated on UDP only:
TCP's own retransmission hides userspace drops, so loss comparisons with ssh
need `netem` (Linux, root), with the harness's own delay set to 0.

Scenarios: RTT ∈ {1, 40, 150} ms × loss ∈ {0, 1, 5} %.

Metrics, each compared against OpenSSH over the same impairment:

- bulk throughput (20 MB through `-D`/`-L`, and file transfer);
- keystroke-to-echo latency: idle, and during a concurrent bulk transfer;
- idle packets/s each way;
- time to recover after an address change, and after 30 s of total outage.

Targets: throughput ≥ ssh on clean links and ≥ 2× ssh at 1 % loss; echo latency
during bulk transfer within 1.5× of idle; idle ≤ 1 pkt/s each way.

Implemented: bulk throughput and echo latency through `-L`, idle and under
load, and idle packets/s. File transfer and recovery times are still to add.

### 0.6 baseline

Measured with the harness on one Linux machine (loopback plus the userspace
link), 5 MB bulk, release builds of 0.6.4 and OpenSSH 9.6:

| path | tool | bulk MB/s | echo p50/p95 ms | echo under load p50/p95 ms | idle pkts/s up/down |
|---|---|---|---|---|---|
| 40 ms | noissh 0.6 | 1.67 | 55.9 / 56.9 | 55.7 / 59.5 | 3.4 / 3.4 |
| 40 ms | OpenSSH | 21.05 | 41.2 / 41.6 | 62.4 / 117.4 | — |
| 40 ms, 1 % loss | noissh 0.6 | 0.13 | 55.8 / 57.0 | 55.7 / 57.8 | 3.2 / 3.2 |
| 150 ms | noissh 0.6 | timed out (> 120 s) | 163.9 / 165.4 | 163.9 / 167.8 | 3.4 / 5.4 |
| 150 ms | OpenSSH | 7.34 | 151.6 / 152.2 | 151.5 / 186.9 | — |

0.6 is 12× slower than ssh at 40 ms, collapses with loss or a long RTT, and
adds ~15 ms of tick latency to every round trip; ssh's echo suffers under load
(head-of-line blocking behind the bulk transfer in one TCP connection).

### 0.7 (QUIC)

Same machine and method, 50 MB bulk:

| path | tool | bulk MB/s | echo p50/p95 ms | echo under load p50/p95 ms | idle pkts/s up/down |
|---|---|---|---|---|---|
| 1 ms | noissh 0.7 | 68.9 | 2.1 / 2.6 | 6.9 / 10.6 | 0.4 / 0.4 |
| 1 ms | OpenSSH | 522.0 | 2.0 / 2.2 | 2.7 / 39.0 | — |
| 40 ms | noissh 0.7 | 31.8 | 41.5 / 42.4 | 41.6 / 47.5 | 0.4 / 0.4 |
| 40 ms | OpenSSH | 38.5 | 41.3 / 41.7 | 41.7 / 81.6 | — |
| 150 ms | noissh 0.7 | 13.0 | 151.7 / 154.1 | 151.3 / 154.2 | 0.4 / 0.4 |
| 150 ms | OpenSSH | 12.3 | 151.4 / 151.8 | 151.9 / 196.1 | — |
| 40 ms, 1 % loss | noissh 0.7 | 26.6 | 41.4 / 42.1 | 41.4 / 47.5 | 0.4 / 0.4 |
| 40 ms, 5 % loss | noissh 0.7 | 22.1 | 41.4 / 151.5 | 41.9 / 96.5 | 0.4 / 0.4 |

Against the targets:

- **Echo latency under bulk ≤ 1.5× idle: met** (p95 47.5 vs 42.4 ms at 40 ms;
  ssh's p95 doubles under load).
- **Idle ≤ 1 pkt/s: met** (0.4 each way; 0.6 sent 3.4).
- **Throughput ≥ ssh: met at 150 ms, close at 40 ms, not on a 1 ms path.**
  On a near-zero RTT the limit is CPU per packet (one `sendto`/`recvfrom` per
  1200-byte datagram against ssh's 64 KB TCP writes). Over 300 MB at 40 ms
  (steady state, past BBR's start-up) noissh reached 43 MB/s.
  With batched I/O (GSO/GRO, `recvmmsg`) direct loopback rose from about 94 to
  about 150 MB/s (ssh: about 400). GSO itself adds about 5 %; most of the gain
  is the batched receive. Packet encryption now dominates the profile. Through
  the userspace link the numbers above don't change: at these rates the link
  proxy is the limit.
- **2× ssh at 1 % loss: met, by far** (CI, `netem`, below): 26.3 against
  0.57 MB/s.

### CI under `netem` (0.7.0)

GitHub runner, kernel `netem` on loopback (only the server ports; 1500-byte
MTU, offloads off), 20 MB bulk, OpenSSH 10.2 (`bench/netem.sh`, workflow
*Benchmark*):

| RTT | loss | tool | bulk MB/s | echo p50/p95 ms | echo under load p50/p95 ms |
|---|---|---|---|---|---|
| 40 ms | 0 % | noissh | 26.0 | 40.7 / 40.8 | 47.6 / 67.7 |
| 40 ms | 0 % | ssh | 24.3 | 40.6 / 40.7 | 40.3 / 43.2 |
| 40 ms | 1 % | noissh | 26.3 | 40.8 / 40.9 | 42.3 / 77.1 |
| 40 ms | 1 % | ssh | 0.57 | 40.6 / 40.7 | 583.8 / 911.3 |
| 150 ms | 0 % | noissh | 10.7 | 150.8 / 150.9 | 151.5 / 169.3 |
| 150 ms | 0 % | ssh | 5.1 | 150.7 / 150.7 | 150.4 / 280.7 |
| 40 ms | 5 % | noissh | 16.3 | 40.8 / 148.4 | 41.1 / 112.2 |
| 40 ms | 5 % | ssh | 0.21 | 40.2 / 303.1 | 3536 / 5175 |

With loss, ssh's single TCP connection collapses (46× slower than noissh at
1 %, 78× at 5 %) and a keystroke waits behind the bulk transfer for seconds;
noissh stays near the loss-free numbers. On a clean path the two are level
(ssh 2× slower at 150 ms). One target is narrowly missed: on a clean 40 ms
path, echo p95 under load is 1.66× idle (67.7 ms; target 1.5×), where ssh's
is 43 ms — BBR keeps some queue in the path during the transfer, and GSO
bursts add to it. A candidate for tuning after 0.7.0 (pacing GSO batches,
BBR's probe-RTT behaviour).

Noisy shared machine: repeated runs vary by ±20 %.

## 10. Risks and open questions

- **Q1 — handshake-level keys. Resolved** in milestone 1: public
  (obfuscation-only) Handshake keys from the handshake hash after msg1, with
  msg2 and msg3 at the Handshake level; see section 4.
- **Q2 — screen state over DATAGRAM vs a stream. Resolved** in milestone 4:
  datagrams, with a fallback to the control stream for a diff larger than the
  datagram limit (a full snapshot of a big terminal); a large diff is held
  back while 256 KiB of earlier ones are still queued, since a later diff
  supersedes it.
- **Security review** of the Noise ↔ QUIC binding: **done** before 0.7.0. One
  critical bug (a forged packet could panic the header-protection code) and a
  medium one (half-open handshakes could fill the session cap) were found and
  fixed; the rest are low or informational. Details and the list of what was
  checked: [SECURITY.md](../SECURITY.md#review-of-the-noise-in-quic-binding).
- **Dependency footprint**: acceptable (listed above); `cargo deny` stays green.
