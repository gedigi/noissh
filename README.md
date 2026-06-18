# noissh

**A remote shell that doesn't drop when your network does.**

Close your laptop, hop from Wi-Fi to cellular, change networks, walk through a
dead spot — your session is still right there when you come back. No reconnect,
no lost work. noissh gives you a resilient session with the everyday feel of a
normal shell, secured end-to-end by the modern
[Noise Protocol](https://noiseprotocol.org/).

```sh
# Once noisshd is installed on the server, connect over your existing SSH access:
noissh --ssh you@server
```

You get a normal shell — except it shrugs off flaky links and survives your
laptop going to sleep.

## Why you'll like it

- **It survives everything.** IP changes, NAT timeouts, Wi-Fi↔cellular handoff,
  suspend/resume — the session just keeps going.
- **It feels instant.** Your keystrokes show up immediately, even on a laggy or
  lossy connection, instead of waiting for a round trip to the server.
- **It's secure by design.** Every connection is mutually authenticated and
  encrypted. Servers are pinned on first use (like SSH's `known_hosts`); only
  authorized keys can connect.
- **It's easy to start.** Install the server component once, and from then on a
  single command connects over your existing SSH access — no daemon to keep
  running, no keys to copy around.
- **It's safe code.** Written in 100% safe Rust (`#![forbid(unsafe_code)]`),
  thoroughly tested, with zero compiler/linter warnings.

## Install

One line — grabs a prebuilt binary for your platform, or builds from source if
needed (it'll offer to install Rust for you):

```sh
curl -fsSL https://raw.githubusercontent.com/gedigi/noissh/main/install.sh | sh
```

Prefer something else?

```sh
cargo install --git https://github.com/gedigi/noissh   # with Rust's cargo
make install PREFIX=~/.local                            # from a clone
```

Put `noissh` on your laptop and `noisshd` on the server. (To remove it later:
`./install.sh --uninstall`.)

## Getting started

**The easy way — if you can already SSH to the host:**

```sh
noissh --ssh you@server
```

noissh uses your existing SSH access to start the server for you and then runs
the session over its own resilient, encrypted channel. (The server just needs
the `noisshd` binary installed.)

**Running your own always-on server:**

```sh
# on the server
noisshd --listen 0.0.0.0:51820

# on your machine (first connect remembers the server's key)
noissh you@server
```

Authorize a client by adding its public key (printed on first run, stored at
`~/.config/noissh/id`) to `~/.config/noissh/authorized_keys` on the server.

> **Tip:** noissh talks over **UDP**. If SSH works but noissh times out, the
> usual culprit is a firewall blocking the UDP port — open it and you're set.

Full walkthrough, configuration, and troubleshooting:
**[User Guide »](docs/USER_GUIDE.md)**

## How it works (the short version)

The server keeps the real terminal; your client shows a live picture of it and
predicts your typing locally so it feels instant. Every packet is encrypted and
tagged with a session id, so the server recognizes you no matter which network
address you appear from — that's what lets the connection roam. Packet loss never
stalls anything, because only the *latest* screen matters.

Want the details? See the **[Architecture](docs/ARCHITECTURE.md)** and
**[Protocol](docs/PROTOCOL.md)** docs.

## Project status

Working and tested end-to-end: the resilient interactive shell, predictive
typing, roaming, and the reliable-stream layer that future SSH-style features
(port forwarding, file transfer) build on. This is young software and hasn't had
an independent security audit yet — see the **[Security model](docs/SECURITY.md)**
before relying on it for anything sensitive.

## Documentation

| Guide | What's inside |
|---|---|
| [User Guide](docs/USER_GUIDE.md) | Install, connect, configure, troubleshoot |
| [Architecture](docs/ARCHITECTURE.md) | How the pieces fit together (with diagrams) |
| [Protocol](docs/PROTOCOL.md) | The wire format and handshake, in detail |
| [Security](docs/SECURITY.md) | Trust model and threat model |
| [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) | Hacking on noissh · history |

## License

MIT — see [LICENSE](LICENSE).
