# noissh

[![CI](https://github.com/gedigi/noissh/actions/workflows/ci.yml/badge.svg)](https://github.com/gedigi/noissh/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gedigi/noissh?sort=semver)](https://github.com/gedigi/noissh/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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
  suspend/resume — the session just keeps going. And if your client itself
  restarts, **reconnect and you're back in the same running session.**
- **It feels instant.** Your keystrokes show up immediately, even on a laggy or
  lossy connection, instead of waiting for a round trip to the server.
- **It tunnels too.** Local and remote **port forwarding** (`-L`/`-R`) ride the
  same resilient, encrypted session.
- **It moves files.** Copy files to and from the server (`--put`/`--get`) over
  the same authenticated channel — no second tool, no extra login.
- **It forwards your keys.** **Agent forwarding** (`-A`) lets commands on the
  server use the SSH keys on your laptop, without copying them anywhere.
- **It's secure by design.** Every connection is mutually authenticated and
  encrypted. Servers are pinned on first use (like SSH's `known_hosts`); only
  authorized keys can connect.
- **It's easy to start.** Install the server component once, and from then on a
  single command connects over your existing SSH access — no daemon to keep
  running, no keys to copy around.
- **It's safe code.** Written in 100% safe Rust (`#![forbid(unsafe_code)]`),
  thoroughly tested, with zero compiler/linter warnings.

## Install

One line — downloads a prebuilt binary for your platform (Linux and macOS,
`x86_64` and `arm64`), or builds from source if one isn't available:

```sh
curl -fsSL https://raw.githubusercontent.com/gedigi/noissh/main/install.sh | sh
```

Prebuilt binaries are on the [releases page](https://github.com/gedigi/noissh/releases/latest).
The installer verifies each download's SHA-256 checksum before installing.

### Verifying a download

Every release archive ships a `.sha256` checksum and a Sigstore **build
provenance attestation** (proving it was built by this repo's release workflow).
To verify a manual download:

```sh
# checksum
shasum -a 256 -c noissh-<target>.tar.gz.sha256

# provenance (requires the GitHub CLI)
gh attestation verify noissh-<target>.tar.gz --repo gedigi/noissh
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

**Port forwarding** works like SSH's `-L`/`-R` and rides the same session:

```sh
# Local: localhost:8080 (your machine) -> 10.0.0.5:80 (reachable from the server)
noissh --ssh user@server -L 8080:10.0.0.5:80

# Remote: server:9000 -> localhost:3000 (on your machine)
noissh --ssh user@server -R 9000:localhost:3000
```

Adding `-L`/`-R` makes the session forward-only (no shell), like `ssh -N`.

**Copying files** rides the same session — no separate transfer tool:

```sh
# Upload local -> remote
noissh --ssh user@server --put ./report.pdf:/home/user/report.pdf

# Download remote -> local
noissh --ssh user@server --get /var/log/app.log:./app.log
```

**Agent forwarding** (`-A`) lets remote `git`/`ssh` use your local keys:

```sh
noissh --ssh user@server -A
```

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
typing, roaming, local/remote port forwarding, file transfer (`--put`/`--get`),
and SSH agent forwarding (`-A`) — all over the same reliable-stream layer. This
is young software and hasn't had an independent security audit yet — see the
**[Security model](docs/SECURITY.md)** before relying on it for anything
sensitive.

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
