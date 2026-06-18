# noissh Architecture

This document describes how noissh is structured, how data flows through it, and
why the pieces are split the way they are. For the wire format and protocol
details see [PROTOCOL.md](PROTOCOL.md); for the trust/threat model see
[SECURITY.md](SECURITY.md).

## Goals

noissh aims to be **as resilient as mosh** and **as rich as SSH**, with all
cryptography provided by the [Noise Protocol Framework](https://noiseprotocol.org/)
("Noise all the way down"). The novel engineering is the **hybrid resilient
transport + predictive TTY overlay**; account/login/privilege machinery reuses
the operating system (PAM, setuid) rather than reinventing it.

## High-level picture

```mermaid
flowchart TB
    subgraph client["noissh (client)"]
        direction TB
        c1["Noise XX handshake + known-hosts TOFU"]
        c2["transport: send from any local address (roaming)"]
        c3["predictive-echo engine (guess → paint → reconcile)"]
        c4["raw-mode TTY + incremental renderer"]
        c1 --> c2 --> c3 --> c4
    end

    subgraph server["noisshd (server)"]
        direction TB
        s1["UDP socket → demux by cryptographic session-id (not by IP)"]
        s2["Noise XX handshake (snow) + per-datagram AEAD"]
        s3["transport: frames, acks, anti-replay, roaming"]
        s4["login backend → PTY → login shell"]
        s5["authoritative terminal emulator + latest-wins state-sync"]
        s1 --> s2 --> s3 --> s4 --> s5
    end

    client <-->|"Noise-encrypted UDP datagrams<br/>(peer address may change at any time)"| server
```

## Crate layout

The project is a Cargo workspace. Each crate has one clear responsibility and is
independently testable; lower crates know nothing about higher ones.

```
crates/
  wire/        frame codec (varint, datagram + stream frame classes)
  noise-core/  snow wrapper: XX handshake + stateless transport AEAD
  transport/   session-id, roaming, anti-replay, input channel, stream mux
  term/        authoritative terminal emulator + latest-wins screen diff
  predict/     client-side predictive-echo engine
  auth/        known_hosts (TOFU) + authorized_keys, X25519 key text format
  pty/         portable PTY/login + Linux PAM/privsep (cfg-gated)
  proto/       handshake driver, control channel, state-sync data plane
src/           runtime (client/server cores + UDP drivers), config, tty, ssh
src/bin/       noissh (client) and noisshd (server) binaries
```

### Dependency direction

```mermaid
graph TD
    wire --> transport
    noise-core --> transport
    transport --> proto
    term --> predict
    predict --> proto
    term --> proto
    auth --> proto
    proto --> noissh["noissh (runtime + bins)"]
    pty --> noissh
    term --> noissh
    auth --> noissh
    noise-core --> noissh
```

There are no cycles. `wire` and `noise-core` are the foundations; `proto` is the
integration layer; the root `noissh` crate adds I/O (sockets, PTYs, TTY) and the
binaries.

## The two cores

A central design choice is that all protocol logic lives in **I/O-free cores**:

- `proto::ServerShell` / `proto::ClientShell` — the state-sync data plane,
  operating purely on `wire::Frame`s.
- `noissh::server::ServerCore` / `noissh::client::ClientCore` — full
  session handling (handshake, auth, control, roaming) that consumes raw
  datagrams and returns raw datagrams to send. No sockets.

The `Server`/`Client` UDP drivers wrap the cores with a `UdpSocket` and an event
loop. Because the cores are socket-free, the **resilience harness** can drive
them through an in-memory shim that injects loss/reorder and rewrites source
addresses — exercising the exact production code path deterministically.

## Data flow: an interactive session

1. **Handshake.** The client picks a random session id and runs the Noise `XX`
   handshake inside `[type=0][session-id][noise msg]` packets. On completion both
   sides hold each other's authenticated static key.
2. **Trust.** The client checks the server key against `known_hosts` (TOFU); the
   server checks the client key against `authorized_keys` *before* creating any
   session or spawning a PTY.
3. **Shell open.** The client sends an `OpenShell` control message (retransmitted
   until the server begins sending screen state). The server allocates a PTY and
   execs the login shell.
4. **Output (server → client).** The PTY's output feeds the authoritative
   terminal emulator. The server sends latest-wins diffs of the screen
   (`StateDiff` frames). The client applies them to its render grid and acks.
5. **Input (client → server).** Keystrokes are an append-only byte stream sent
   reliably (`Input` frames retransmitted until acked) and written to the PTY.
6. **Prediction.** The client predicts the visible echo of keystrokes and paints
   it immediately (distinct styling), reconciling against authoritative diffs as
   they arrive.
7. **Roaming.** Any authenticated datagram from a new source address updates the
   server's notion of the peer address, so the session survives IP changes, NAT
   rebinding, and sleep/resume with no reconnect.

## Resilience model

- Every datagram carries the session id and is individually AEAD-authenticated.
- The server demuxes by session id, **not** by source IP:port.
- The interactive shell rides **unreliable latest-wins** datagrams: only the
  newest screen state matters, so packet loss never stalls a byte stream.
- A per-direction sliding-window replay filter drops replayed/very-old datagrams
  (Noise already guarantees strictly increasing nonces per direction).

## TTY / predictive echo

The server runs the only authoritative terminal emulator. The client is a "dumb"
render target plus a prediction overlay: it never re-emulates escape sequences,
it just applies cell/cursor diffs and paints predictions on top. Prediction is
**adaptive** — it only displays once the server has confirmed an echo, which
naturally suppresses predictions at non-echoing prompts (passwords).

## v2: reliable streams

The wire frame format reserves a **stream frame class** from day one. The
`transport::StreamMux` implements reliable, ordered, flow-controlled byte streams
(ARQ retransmit, in-order reassembly, sliding receive window) over the same
Noise/UDP session, which roams exactly like the v1 datagram path. This is the
substrate SSH-style richness (port forwarding, file transfer, agent forwarding)
builds on.

## Privilege separation & login

The `pty` crate exposes a `LoginSession` trait with two backends:

- `LocalLogin` (all Unix): allocates a real PTY and execs the login shell as the
  current user — no root required. This is the tested, default path.
- `PrivsepLogin` (Linux, gated): `setgid`/`initgroups`/`setuid` to the target
  user before exec, with optional PAM `acct_mgmt`/`open_session` behind the
  `pty/pam` cargo feature. Requires running as root.

Keeping the privileged surface minimal and isolating all parsing/crypto/protocol
in unprivileged code is a deliberate security choice (see [SECURITY.md](SECURITY.md)).

## Testing strategy

- **Unit:** every crate (Noise transcript, frame round-trip + fuzz, emulator
  against escape-sequence corpora, `apply(diff(a,b)) == b` property tests, replay
  filter, input reassembly, stream mux under loss/reorder, predictive
  reconciliation).
- **Resilience harness:** in-process, real cores + real PTY, injecting
  loss/reorder and rewriting the source address mid-session.
- **Real-socket e2e:** actual `Server`/`Client` over loopback UDP, including a
  client socket rebind mid-session (roaming) and unauthorized-client rejection.
- **SSH bootstrap e2e:** a fake `ssh` launches the real one-shot server.
- **Security:** unauthorized key rejected before any session work; known_hosts
  mismatch; deterministic fuzzing of the packet handler and frame parser.
