# noissh Protocol

This document specifies the noissh wire protocol as implemented (0.7): QUIC
secured by a Noise handshake, the streams and datagrams noissh carries over it,
the session-layer frames, and the SSH bootstrap. It describes the current
implementation, not a frozen standard: the protocol is pre-1.0 and may change.
0.7 is not compatible with 0.6 peers.

Session-layer integers are **LEB128 unsigned varints** unless stated otherwise;
fixed-width integers are **big-endian**.

## 1. Transport: QUIC

Each session is one QUIC connection (RFC 9000 semantics, implemented by
`quinn-proto`) over UDP, from the client to the server's port (51820 by
default). QUIC provides what noissh needs from a transport:

- **Reliable, ordered streams** with per-stream and connection flow control,
  loss recovery and congestion control (BBR by default; `NOISSH_CC=cubic`
  selects Cubic).
- **Unreliable datagrams** (RFC 9221) for latest-wins data.
- **Connection migration**: a client that changes address (Wi-Fi ↔ cellular,
  NAT rebinding) keeps its connection; the server validates the new path and
  follows it. Packets are authenticated before they can move the connection.
- **Replay protection** through packet numbers, and **amplification limits**
  before the client's address is validated: the client's first datagram is
  padded to at least 1200 bytes, and the server sends at most three times what
  it received until then.
- **Address validation under load**: with more than 16 handshakes in progress,
  the server answers a new client with a Retry, and keeps state only once the
  client returns the Retry token (proving it receives at its address). At most
  256 handshakes are in progress at a time, separately from up to 512
  established sessions, and a handshake not done within 10 s is dropped.
- **ECN** marks are read and set, so congestion control can react to them; on
  Linux, datagrams are sent and received in batches (GSO, `recvmmsg`/GRO).

Version and parameters:

| | |
|---|---|
| QUIC version | `0x6e6f6973` ("nois"), private: a noissh endpoint never talks to a standard QUIC/TLS one |
| Idle timeout | 60 s |
| Client keep-alive | every 3 s of silence (a PING) |
| Stream receive window | 8 MiB per stream, 32 MiB per connection |
| Concurrent streams | 1024 bidirectional per side; no unidirectional streams |
| ACK frequency | the peer is asked to acknowledge every 8th packet (out-of-order arrival is acknowledged at once) |

## 2. Handshake: Noise XX inside QUIC

QUIC delegates its handshake to a crypto layer, usually TLS 1.3; noissh uses
`Noise_XX_25519_ChaChaPoly_BLAKE2s` (crate `noise-quic`). The Noise messages
travel in QUIC CRYPTO frames, each prefixed with its length (u16, big endian):

```
client                                         server
  Initial:   msg1 → e            [payload: client transport parameters]
  Handshake: msg2 ← e, ee, s, es [payload: server transport parameters]
  Handshake: msg3 → s, se        [payload: empty]
  1-RTT keys from Noise Split()
```

- **Prologue**: `"noissh-quic"` followed by the QUIC version (u32), so a
  transcript from another context can't be replayed here.
- **Authentication**: the client checks the server's static key (`s` in msg2)
  against its known hosts (TOFU) or the key pinned by the SSH bootstrap,
  before sending msg3. The server checks the client's static key (msg3) against
  `authorized_keys`. A rejected key fails the handshake with crypto error 0x2a
  and the reason `server key not trusted` / `client key not authorized`,
  before any application key exists.
- **Packet protection keys**: Initial keys are derived from the client's
  destination connection id and Handshake keys from the Noise handshake hash
  after msg1; both are public values (obfuscation only, as QUIC's Initial
  keys are). Everything the handshake must protect is protected by Noise itself:
  the static keys and the server's parameters are encrypted in msg2/msg3, and
  the client's parameters (msg1) are bound to the transcript, so altering them
  makes msg2 fail to decrypt. 1-RTT keys come from Noise's split, each mixed
  with the final handshake hash. Because the Handshake keys are public too, an
  observer of msg1 can forge Handshake-level packets (a close, an ACK) for the
  rest of the handshake: that can abort a handshake, never impersonate a side.
- **One message per level**: each side receives exactly one Noise message per
  encryption level; bytes after it are refused (they would be outside the
  transcript).
- **Packet protection**: ChaCha20-Poly1305 (nonce: IV XOR packet number, the
  header as associated data); header protection with ChaCha20 (RFC 9001
  §5.4.4); key derivation with keyed BLAKE2s-256. Key updates follow RFC 9001
  §6.
- **Retry** integrity tags use ChaCha20-Poly1305 with a fixed noissh key;
  stateless-reset and address-validation tokens are keyed from random
  per-process secrets.

Details and the reasoning behind each choice are in
[design/quic-transport.md](design/quic-transport.md), section 4.

## 3. Streams

Every stream is bidirectional and starts with a header in its opener's
direction:

```
[kind u8][meta length u16][meta bytes]
```

| kind | stream | opened by | meta |
|---|---|---|---|
| 0 | control | client, first, once per connection | (none) |
| 1 | forward (`-L`, `-D`, `-R`) | client (`-L`/`-D`), server (`-R`) | target `host:port` |
| 2 | file transfer | client | `PUT <size> <path>` or `GET <path>` |
| 3 | agent | server | (none) |
| 4 | exec | client (stdin/stdout), server (the same command's stderr) | the command (client); none (server) |

After the header, a stream is a plain byte pipe in each direction. A FIN is a
clean end of that direction; a reset (RESET_STREAM + STOP_SENDING, error code
1) aborts both. Unknown kinds and a second control stream are reset.

- **Forward**: the side that accepts the stream connects to the target and
  pipes bytes both ways; it resets the stream if the target is unreachable.
  For `-R`, the client first sends `RemoteForward` (section 5) and the server
  opens one stream per accepted connection.
- **File transfer**: `PUT`: the client sends the file and finishes its half;
  the server writes it to a temporary file, moves it into place, then finishes
  its half (success) or resets the stream (failure). `GET`: the server sends
  the file and finishes (or resets if it can't be read).
- **Exec**: the client's stream carries the command's stdin (client → server)
  and stdout (server → client); the server opens a second exec stream for
  stderr. Before finishing stdout, the server sends `ExecExit{id, status}` on
  the control stream, with `id` the client's stream id. The server resets the
  stream if the command can't be started.
- **Agent**: each connection to the forwarded agent socket on the server opens
  an agent stream, which the client pipes to its local `$SSH_AUTH_SOCK`.

Priorities: the control stream first (keystrokes, acks, screen updates), file
transfers last, everything else in between.

## 4. Session-layer frames

The control stream carries a sequence of messages, each a u32 length followed
by one encoded frame. QUIC datagrams carry one encoded frame each. A frame is a
type byte and its fields:

```
0x01 Ack       : seq varint                           (client → server)
0x02 Input     : data bytes                           (client → server)
0x03 StateDiff : seq varint, base varint, data bytes  (server → client)
0x20 Control   : data bytes  (a control message, section 5)
```

`bytes` is a varint length followed by the bytes.

### Interactive shell

- **Input**: keystrokes go as `Input` on the control stream (reliable and
  ordered); the server writes them to the shell's PTY. The client predicts
  their echo locally (section 6 of the architecture document).
- **Screen state**: the server keeps the authoritative terminal grid and gives
  each distinct screen an increasing `seq`. It sends `StateDiff{seq, base,
  data}`, a diff from the client's last **acknowledged** state `base`, as a
  QUIC datagram, or on the control stream when it doesn't fit in one. A diff is
  either a full snapshot (applicable regardless of base, e.g. after a resize or
  a reattach) or a delta of changed cells. The client applies snapshots always
  and deltas only when `base` matches its current state and `seq` is newer, and
  after every received diff, applied or not, it sends `Ack{seq}` with its
  current seq on the control stream. The server sends a new diff when the
  screen changes (at most every 8 ms) and resends the unacknowledged state
  after 1.5 × RTT + 10 ms (at least 30 ms). Lost or reordered diffs are thus
  simply superseded: only the newest screen matters.

### Screen diff encoding

```
[tag u8: 0=full, 1=delta]
[rows varint][cols varint][cursor_row varint][cursor_col varint][cursor_visible u8]
full : rows*cols cells
delta: [count varint] then count × ([index varint][cell])
cell : [char as varint][fg color][bg color][flags u8]
color: [0]                | [1][index u8] | [2][r u8][g u8][b u8]
```

## 5. Control messages (inside `Control` frames)

```
0x01 OpenShell     : cols varint, rows varint, term string, agent u8 (client → server)
0x02 Resize        : cols varint, rows varint                        (client → server)
0x03 Exit          : status zigzag varint                            (server → client)
0x06 RemoteForward : bind_port varint, target string                 (client → server, -R)
0x07 Bye           : (no payload)                                    (client → server)
0x08 ServerVersion : version string                                  (server → client)
0x09 ExecExit      : stream id varint, status zigzag varint          (server → client)
```

Strings are a varint length followed by UTF-8 bytes. Tags 0x04 and 0x05 are
reserved (a never-wired second-factor prompt, since removed).

- The client sends `OpenShell` (interactive sessions) and its `RemoteForward`
  requests right after the handshake, and again on every reconnection.
  `agent` asks the server for an agent socket (`-A`).
- The server sends `ServerVersion` as its first message on every connection;
  a direct client uses it to offer upgrading an outdated standing daemon.
- When the shell exits, the server sends `Exit`; the client closes the
  connection. The server closes it itself 2 s later if the client hasn't.
- `Bye` ends the session like a close does; current clients close the
  connection instead (section 6).

## 6. Session lifecycle

- **End**: the client ends a session by closing the connection with
  application error code 0 (on exit, after a command or transfer, or on the
  detach key). The server then stops the shell and retires the session.
- **Lost connection**: if the connection times out (no packet for 60 s) or
  is reset, the server keeps a running shell **detached** for 15 minutes. The
  interactive client opens a new connection; when it sends `OpenShell`, the
  server hands it the detached shell (same client key) and sends the screen as
  a full snapshot. A command, transfer or forward-only session ends with its
  connection.
- **Reattach after a client restart**: a new connection's `OpenShell` also
  takes over a running shell of the same client key whose own connection has
  been silent for at least 8 s (its client is gone). A shell whose connection
  is alive is never taken: a second window gets its own shell.
- **Liveness**: the client sends a PING after 3 s of silence (QUIC
  keep-alive), and every second while it has heard nothing for 4 s, so a
  recovered network is noticed within about a second.

## 7. SSH bootstrap (optional)

An SSH bootstrap: `ssh <host> noisshd --one-shot --authorize <client pub>`.
The one-shot server binds the UDP port the client asks for with `--bind` (51820
by default), or an ephemeral one if that port is taken, prints

```
NOISSH CONNECT <port> <base64 server pubkey> quic
```

on stdout (the final `quic` names the transport; a server before 0.7 omits it,
and a 0.7 client refuses such a server with a message to upgrade it), then detaches (daemonizes) and serves until its session has ended,
exiting if no client connects within 60 seconds. The client parses that line,
pins the server key (delivered over the authenticated SSH channel), and
connects over QUIC as above.
