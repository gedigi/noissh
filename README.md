# noissh

A remote-shell utility that aims to be **as resilient as mosh** (instant feel on
lossy/high-latency links; survives IP changes, NAT rebinding, and laptop sleep
with no reconnect) and **as rich as SSH**, built entirely on the
[Noise Protocol Framework](https://noiseprotocol.org/) for its cryptography —
"Noise all the way down".

See [`docs/specs/2026-06-18-noissh-design.md`](docs/specs/2026-06-18-noissh-design.md)
for the full design.

## Status

v1 (resilient interactive shell) is implemented and tested end-to-end, and the
v2 reliable-stream multiplexer that SSH-richness builds on is implemented and
tested. 121 tests pass; `cargo clippy --workspace --all-targets -- -D warnings`
is clean.

## Architecture

A Cargo workspace of focused, independently-testable crates plus two binaries:

| Crate | Responsibility |
|---|---|
| `wire` | Wire frame codec (datagram **and** stream frame classes from day one) + varint |
| `noise-core` | `snow` wrapper: `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake + stateless transport AEAD |
| `transport` | Session id, roaming, anti-replay window, reliable input channel, v2 stream multiplexer |
| `term` | Clean-room authoritative terminal emulator (`vte`-based) + latest-wins screen diff |
| `predict` | Client-side predictive-echo engine (guess → paint → reconcile) |
| `auth` | `known_hosts` TOFU + `authorized_keys`, X25519 key text format |
| `pty` | Portable PTY/login + Linux PAM/privsep (`cfg`-gated, PAM behind a feature) |
| `proto` | Handshake driver, control channel, server-authoritative state-sync data plane |
| `noissh` (root) | UDP client/server runtime, config, raw-tty renderer, SSH bootstrap, binaries |

The interesting design is the **hybrid resilient transport + predictive TTY
overlay**: every datagram carries a cryptographic session id and is
individually AEAD-authenticated, so the server demuxes by session id (not source
IP) and follows the client across address changes. The interactive shell rides
unreliable latest-wins state-sync so packet loss never stalls the stream.

## Build & test

```sh
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Requires Rust stable (edition 2024; tested on 1.96).

## Usage

### Standalone daemon

On the server, authorize a client's public key (printed by the client on first
run in `~/.config/noissh/id`) by adding its `noissh-x25519 <base64>` line to
`~/.config/noissh/authorized_keys`, then:

```sh
noisshd --listen 0.0.0.0:51820
```

Connect (first connect pins the server key via TOFU in `~/.config/noissh/known_hosts`):

```sh
noissh user@server      # uses --port 51820 by default
```

### mosh-style SSH bootstrap

If you can already SSH to the host, let SSH launch the server and hand back the
UDP port + an ephemeral key — no pre-shared `authorized_keys` needed:

```sh
noissh --ssh user@server          # runs `ssh user@server noisshd --one-shot ...`
```

SSH is used **only** to bootstrap; the session itself runs over Noise/UDP and
roams. The one-shot server detaches and survives the SSH connection closing,
just like `mosh-server`.

## Resilience

The session survives Wi-Fi↔cellular handoff, NAT rebinding, and laptop
sleep/resume with no reconnect: any authenticated datagram from a new source
address transparently updates the server's notion of the peer address. This is
covered by automated tests — both an in-process harness that injects
loss/reorder and rewrites the source address mid-session, and a real-socket e2e
that rebinds the client's UDP socket mid-session.

## Platform notes

- **Server:** Linux and macOS. The portable backend allocates a real PTY and
  runs the login shell as the current user (no root needed) — this is the
  tested path. The sshd-style privilege-separated backend
  (`setgid`/`initgroups`/`setuid` + optional PAM `acct_mgmt`/`open_session`) is
  Linux-only and requires running as root; PAM is behind the `pty/pam` cargo
  feature so the default build needs no libpam headers.
- **Non-goals:** Windows *server*, X11 forwarding, GSSAPI/Kerberos, SSH
  wire-protocol interop.

## Offline / vendored builds

For hermetic or air-gapped builds:

```sh
cargo vendor vendor > .cargo/config.toml
cargo build --offline
```

`vendor/` and the generated `.cargo/config.toml` are git-ignored (the full
cross-platform dependency tree is large); regenerate them on demand.
`Cargo.lock` is committed for reproducibility.
