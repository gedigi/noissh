# noissh User Guide

noissh is a remote shell that feels instant on bad links and survives network
changes (Wi-Fi↔cellular, NAT rebind, laptop sleep) without reconnecting, using
the Noise Protocol Framework for all cryptography.

This guide covers installing, connecting, configuring, and troubleshooting.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Connecting](#connecting)
  - [SSH bootstrap](#ssh-bootstrap)
  - [Direct connection](#direct-connection)
- [Running the server](#running-the-server)
- [Keys & trust](#keys--trust)
- [Configuration & file layout](#configuration--file-layout)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)

## Install

Build from source (Rust stable, edition 2024 — tested on 1.96):

```sh
git clone https://github.com/gedigi/noissh
cd noissh
cargo build --release
# binaries: target/release/noissh (client), target/release/noisshd (server)
```

Install them somewhere on your `PATH` on both machines (the server host needs
`noisshd`; your laptop needs `noissh`).

## Quick start

The easiest path, if you can already SSH to the server:

```sh
noissh --ssh user@server
```

This uses your existing SSH access to launch the server and negotiate a Noise/UDP
session — no extra server configuration required. (Make sure UDP is reachable;
see [Troubleshooting](#troubleshooting).)

## Connecting

### SSH bootstrap

```sh
noissh --ssh [user@]host [--server-cmd noisshd] [--port N] [-- <extra ssh args>]
```

What happens:

1. noissh runs `ssh [user@]host noisshd --one-shot --authorize <your client key>`.
2. The remote `noisshd` binds an ephemeral UDP port, prints a connect line, and
   detaches so it survives the SSH connection closing.
3. noissh reads the port + the server's ephemeral public key (delivered over the
   authenticated SSH channel), pins it, and connects over Noise/UDP.

`--server-cmd` sets the remote command if `noisshd` is not on the default `PATH`
(e.g. `--server-cmd /opt/noissh/bin/noisshd`). Everything after `--` is passed
straight to `ssh` (e.g. `-- -p 2222 -i ~/.ssh/id_ed25519`).

### Direct connection

If a standalone `noisshd` is already running and your key is authorized:

```sh
noissh [user@]host            # default UDP port 51820
noissh --port 51820 host
```

On first connect the server's key is pinned (TOFU) in `known_hosts`. A later key
change aborts the connection with a `HOST KEY MISMATCH` error.

## Running the server

### Standalone daemon

```sh
noisshd --listen 0.0.0.0:51820
```

It loads (or generates on first run) its static key and reads `authorized_keys`
from the config directory. It prints its public key on startup so you can
distribute it.

Authorize a client by adding its public key line to `authorized_keys`:

```
noissh-x25519 <base64-public-key>  optional-comment
```

The client prints its own key on first run (it is stored in
`~/.config/noissh/id`).

### One-shot (used by SSH bootstrap)

You normally do not run this by hand; the client invokes it over SSH:

```sh
noisshd --one-shot --authorize <base64 client pubkey> [--bind 0.0.0.0:0] [--command ...]
```

## Keys & trust

- **Your identity (client):** `~/.config/noissh/id` — a static X25519 keypair,
  generated on first run, stored `0600`.
- **Server identity:** `~/.config/noissh/noisshd_key` on the server.
- **Server trust (client side):** `~/.config/noissh/known_hosts`, TOFU-pinned.
- **Client authorization (server side):** `~user/.config/noissh/authorized_keys`.

This mirrors SSH's `known_hosts` / `authorized_keys` model, but with Noise static
keys.

## Configuration & file layout

Files live under `$XDG_CONFIG_HOME/noissh` (or `~/.config/noissh`):

| File | Side | Purpose |
|---|---|---|
| `id` | client | your static keypair |
| `known_hosts` | client | pinned server public keys |
| `noisshd_key` | server | server static keypair |
| `authorized_keys` | server | allowed client public keys |

## Command reference

### `noissh`

```
noissh [--ssh] [--port N] [--server-cmd CMD] [user@]host [-- <ssh args>]
  --ssh           bootstrap the server over SSH
  --port N        UDP port for direct connection (default 51820)
  --server-cmd C  remote server command for --ssh (default "noisshd")
  -- <args>       pass remaining args to ssh (only with --ssh)
```

### `noisshd`

```
noisshd [--listen ADDR] [--key PATH] [--authorized-keys PATH] [--command CMD ...]
noisshd --one-shot --authorize <b64pub> [--bind ADDR] [--command CMD ...]
  --listen ADDR        bind address (default 0.0.0.0:51820)
  --key PATH           static key file (default <config>/noisshd_key)
  --authorized-keys P  authorized_keys file (default <config>/authorized_keys)
  --command CMD ...    run this command instead of the login shell
  --one-shot           ephemeral key, serve one session, then exit (SSH bootstrap)
  --authorize <b64>    the single client key to trust in one-shot mode
  --bind ADDR          bind address in one-shot mode (default 0.0.0.0:0)
```

## Troubleshooting

- **It hangs at connect.** The Noise/UDP session needs the server's UDP port to
  be reachable. Open the port in the firewall (standalone: your `--listen` port;
  SSH bootstrap: the ephemeral port range). TCP-only reachability (SSH works but
  noissh hangs) is the classic symptom of a blocked UDP path.
- **`HOST KEY MISMATCH`.** The server's key changed since you first connected.
  If this is expected (server reinstall), remove the host's line from
  `~/.config/noissh/known_hosts`; otherwise treat it as a potential
  man-in-the-middle and investigate.
- **`--ssh` fails with "no connect line".** The remote `noisshd` could not be
  launched. Check it is installed and on `PATH` on the server, or pass
  `--server-cmd /full/path/to/noisshd`.
- **The session freezes after changing networks.** It should recover
  automatically within a second; if not, check that the new network allows
  outbound UDP to the server.
- **Garbled display.** Ensure your local terminal is UTF-8 and that `$TERM` is
  sane; noissh advertises `xterm-256color` to the remote shell by default.
