# noissh User Guide

noissh is a remote shell that feels instant on bad links and survives network
changes (Wi-Fi↔cellular, NAT rebind, laptop sleep) without reconnecting, using
the Noise Protocol Framework for all cryptography.

This guide covers installing, connecting, configuring, and troubleshooting.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Connecting](#connecting)
  - [Direct connection (the first attempt)](#direct-connection-the-first-attempt)
  - [SSH bootstrap (the automatic fallback)](#ssh-bootstrap-the-automatic-fallback)
- [During a session: roaming, the status line, and detaching](#during-a-session-roaming-the-status-line-and-detaching)
- [Host aliases (`~/.ssh/config`)](#host-aliases-sshconfig)
- [Running the server](#running-the-server)
  - [Running noisshd under systemd](#running-noisshd-under-systemd)
- [Keys & trust](#keys--trust)
  - [Generating your key with noissh-keygen](#generating-your-key-with-noissh-keygen)
- [Configuration & file layout](#configuration--file-layout)
  - [Config file](#config-file)
- [Port forwarding](#port-forwarding)
- [Remote command execution](#remote-command-execution)
- [File transfer](#file-transfer)
- [Agent forwarding](#agent-forwarding)
- [Scrollback and long output](#scrollback-and-long-output)
- [Windows](#windows)
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

Just point noissh at a host you can already reach:

```sh
noissh user@server
```

That's it. noissh first tries to reach a standing `noisshd` directly over
Noise/UDP, and if nothing answers it automatically falls back to launching the
server over your existing SSH access — no extra server configuration required.
(Make sure UDP is reachable; see [Troubleshooting](#troubleshooting).)

## Connecting

The default — `noissh [user@]host` — does the right thing on its own. You do not
choose a mode up front:

1. **Direct first.** noissh tries a Noise/UDP session to a standing `noisshd` on
   the host (UDP port 51820 by default, or `--port N`), pinning the server's key
   via TOFU in `known_hosts`.
2. **SSH fallback.** If nothing answers within a few seconds (no daemon is
   running there), noissh automatically falls back to the SSH bootstrap: it
   launches `noisshd` over your existing SSH access — auto-installing it if
   missing — and runs the session.

You can pin either step explicitly:

- `--direct` requires a direct connection and never falls back to SSH.
- `--ssh` forces the SSH bootstrap and skips the direct attempt entirely, which
  is handy when you already know there is no standing daemon and want to avoid the
  few-second probe.

A host-key mismatch on the direct attempt is a hard error (`HOST KEY MISMATCH`):
noissh aborts rather than silently falling back to SSH.

### Direct connection (the first attempt)

This is what noissh tries first, and what `--direct` forces. It applies when a
standalone `noisshd` is already running and your key is authorized:

```sh
noissh [user@]host            # default UDP port 51820
noissh --port 51820 host
noissh --direct user@host     # require direct; never fall back to SSH
```

On first connect the server's key is pinned (TOFU) in `known_hosts`. A later key
change aborts the connection with a `HOST KEY MISMATCH` error.

### SSH bootstrap (the automatic fallback)

This is what noissh falls back to when the direct attempt finds no daemon, and
what `--ssh` forces (skipping the direct probe):

```sh
noissh --ssh [user@]host [--server-cmd noisshd] [--port N] [-- <extra ssh args>]
```

What happens:

1. noissh runs `ssh [user@]host noisshd --one-shot --authorize <your client key>`.
2. The remote `noisshd` binds an ephemeral UDP port, prints a connect line, and
   detaches so it survives the SSH connection closing.
3. noissh reads the port + the server's ephemeral public key (delivered over the
   authenticated SSH channel), pins it, and connects over Noise/UDP.

If the remote does not have `noisshd` yet, the bootstrap installs it for you
automatically: noissh runs the published installer over the same SSH session,
which detects the remote OS/arch, downloads the matching prebuilt release binary,
verifies its SHA-256 checksum, and installs it into `~/.local/bin`. Installer
progress streams to your terminal, then the handshake is retried using that path
and the connection proceeds. This applies only to the default server command; it
is skipped when `--server-cmd` is set to something custom. Pass `--no-install` to
opt out, in which case a missing `noisshd` simply fails as before. (The install
step needs either `curl` or `wget` on the remote; if neither is present it fails
with a clear message.)

If the remote `noisshd` is already installed but older than your client, noissh
asks whether to upgrade it — `[y/N]`, defaulting to no. Decline and it connects to
the existing version as usual. Accept and it reinstalls via the same installer;
the new version takes effect on your **next** connection, while the current
session continues on the existing one (reconnecting immediately would collide with
the one-shot still holding the pinned UDP port). The prompt never appears when
stdin is not a terminal (so scripts don't block) or when `--no-install` is set. A
`noisshd` older than v0.4.11 doesn't report its version, so you won't be prompted
for it until it has been upgraded once.

`--server-cmd` sets the remote command if `noisshd` is not on the default `PATH`
(e.g. `--server-cmd /opt/noissh/bin/noisshd`). Everything after `--` is passed
straight to `ssh` (e.g. `-- -p 2222 -i ~/.ssh/id_ed25519`).

By default the bootstrapped server binds an **ephemeral** UDP port. If the host
permits SSH but blocks arbitrary inbound UDP, pin the server to a port you've
opened with `--server-port N` (e.g. `noissh --server-port 51820 user@host`), then
open that UDP port in the firewall.

## During a session: roaming, the status line, and detaching

A noissh session rides out network changes on its own — close the laptop, switch
from Wi-Fi to cellular, walk through a dead spot — and resumes when connectivity
returns, no reconnect needed.

While the link is healthy you see a normal shell. If it goes quiet (you've
moved networks, or the path is down), a status banner appears on the top row so
you know what's happening rather than staring at a frozen screen:

```
[noissh] last contact 6s ago — reconnecting…  (Ctrl-^ . to quit)
```

It only appears after the link has been silent a little longer than the
keepalive interval (so a healthy idle session never shows it), counts up once a
second, and disappears the instant contact resumes. There is nothing to do — the
session reconnects itself.

**The detach key.** `Ctrl-^` (Control-Shift-6) is a local escape prefix:

- `Ctrl-^` then `.` (or `q`) — disconnect now and exit cleanly. Use this to get
  your local prompt back if the server is unreachable and you don't want to wait.
- `Ctrl-^` then `Ctrl-^` — send one literal `Ctrl-^` to the remote shell.

Because the prefix is intercepted locally, you can always quit a wedged session
without killing your terminal window.

## Host aliases (`~/.ssh/config`)

noissh honours your existing `~/.ssh/config`. A `Host` alias's `HostName`,
`User`, and `Port` are applied to **both** legs of a connection — the SSH
bootstrap (handled by `ssh` itself, so `ProxyJump`, `IdentityFile`, and the rest
work too) and the resilient Noise/UDP session (noissh resolves the alias's
`HostName` for the UDP address). So if this is in your `~/.ssh/config`:

```
Host prod
    HostName 203.0.113.10
    User deploy
    Port 2222
```

then `noissh prod` connects to `deploy@203.0.113.10` just like `ssh prod` would.
Run with `-v` to see the resolved host.

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

### Running noisshd under systemd

A ready-to-use unit ships in [`contrib/noisshd.service`](../contrib/noisshd.service).
It runs `noisshd --listen 0.0.0.0:51820` as a dedicated unprivileged user with
sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `Restart=on-failure`,
and friends).

```sh
cargo build --release
sudo install -m 0755 target/release/noisshd /usr/local/bin/noisshd
sudo useradd --system --create-home --shell /bin/bash noissh
sudo install -m 0644 contrib/noisshd.service /etc/systemd/system/noisshd.service
sudo systemctl daemon-reload
sudo systemctl enable --now noisshd
```

The daemon serves the login shell of the user it runs as, so set `User=` to the
account you intend to expose (never root). See
[`contrib/README.md`](../contrib/README.md) for full notes plus
Homebrew/deb packaging placeholders.

## Keys & trust

- **Your identity (client):** `~/.config/noissh/id` — a static X25519 keypair,
  generated on first run, stored `0600`.
- **Server identity:** `~/.config/noissh/noisshd_key` on the server.
- **Server trust (client side):** `~/.config/noissh/known_hosts`, TOFU-pinned.
- **Client authorization (server side):** `~user/.config/noissh/authorized_keys`.

This mirrors SSH's `known_hosts` / `authorized_keys` model, but with Noise static
keys.

### Authorizing your key with `--copy-id`

For a standing-daemon **direct** connection the server must have your public key
in its `authorized_keys`. Instead of copying it by hand, push it over your
existing SSH access (the equivalent of `ssh-copy-id`):

```sh
noissh --copy-id user@server
```

This appends your public key to `~/.config/noissh/authorized_keys` on the server
(creating the file `0600` and its directory `0700` if needed), skipping it if
it's already there, then exits. Afterwards `noissh user@server` can connect
directly. (The SSH bootstrap path authorizes your key automatically per session,
so `--copy-id` is only needed for direct mode.)

### Re-keyed a server? `--forget-host`

If you intentionally reinstall or re-key a server, its pinned key no longer
matches and the next connect aborts with `HOST KEY MISMATCH`. Drop the stale pin
(the equivalent of `ssh-keygen -R`) and reconnect:

```sh
noissh --forget-host server      # removes every pinned label for "server"
```

### Generating your key with noissh-keygen

`noissh-keygen` ensures your static keypair exists and prints its public key line
so you can paste it into a server's `authorized_keys`:

```sh
noissh-keygen
# -> noissh-x25519 <base64-public-key>
```

On first run it creates the keypair (default `~/.config/noissh/id`, stored
`0600`); on later runs it just prints the existing public key without
regenerating. Use `--key PATH` for a non-default location, or `--help` for usage:

```sh
noissh-keygen --key /etc/noissh/id
```

(The client also generates `id` automatically on first connect; `noissh-keygen`
just lets you obtain the public key ahead of time.)

## Configuration & file layout

Files live under `$XDG_CONFIG_HOME/noissh` (or `~/.config/noissh`):

| File | Side | Purpose |
|---|---|---|
| `id` | client | your static keypair |
| `known_hosts` | client | pinned server public keys |
| `noisshd_key` | server | server static keypair |
| `authorized_keys` | server | allowed client public keys |
| `config` | both | optional settings file (see below) |

### Config file

An optional `config` file in the config directory holds simple defaults. Each
line is a setting written as `key = value` or `key value`. Blank lines and lines
starting with `#` are ignored, as are unknown keys and malformed lines (so a
typo never prevents startup). A missing file just means "all defaults".

```
# ~/.config/noissh/config
port = 51820
```

Recognized keys:

| Key | Type | Meaning |
|---|---|---|
| `port` | number | default UDP port for direct connections (a `--port` flag overrides it) |

The terminal type advertised to the remote shell is taken from your `$TERM`
environment variable (falling back to `xterm-256color` if it is unset), so it
does not need a config entry.

## Port forwarding

Local (`-L`) and remote (`-R`) port forwarding ride the same resilient session
and work like SSH's equivalents. Adding any forward makes the session
forward-only (no shell), like a `-N`-style session.

```sh
# Local: localhost:8080 (your machine) -> 10.0.0.5:80 (reachable from the server)
noissh --ssh -L 8080:10.0.0.5:80 user@server

# Remote: server:9000 -> localhost:3000 (on your machine)
noissh --ssh -R 9000:localhost:3000 user@server
```

`-R` listeners bind to loopback on the server, so forwarded ports are not
exposed to the network.

### Dynamic (SOCKS) forwarding

`-D [BIND:]PORT` runs a local SOCKS proxy whose connections tunnel dynamically
to whatever host:port each client requests, resolved via the server:

```sh
# SOCKS proxy on localhost:1080
noissh --ssh -D 1080 user@server

# bind a specific address
noissh --ssh -D 127.0.0.1:1080 user@server
```

Point a SOCKS-aware application at the proxy and its connections exit from the
server. The proxy speaks SOCKS5 (no authentication) and SOCKS4/4a, CONNECT only.
It binds loopback by default. Like `-L`/`-R`, `-D` makes the session
forward-only (no shell), and all forwards may be combined.

## Remote command execution

Anything you put after the host is run as a single command non-interactively on
the server (ssh-style) instead of opening a shell:

```sh
noissh --ssh user@server uname -a
```

The command's stdout and stderr are streamed separately to yours, your stdin is
forwarded until EOF, and noissh exits with the command's exit code. Output is
byte-for-byte (no PTY/terminal mangling), so it is safe to redirect into a file
or use in a pipeline:

```sh
noissh --ssh user@server tar czf - /etc > etc.tar.gz
```

The trailing words are joined and run by the remote shell, so quoting, globs,
pipes, and redirections are interpreted there — quote them to protect them from
your local shell when needed:

```sh
noissh --ssh user@server 'echo $HOME && uname -a'
```

Like file transfer and agent forwarding, a remote command is refused by a standalone
daemon configured with a `--user` privilege drop (see
[Security](SECURITY.md)); use the SSH-bootstrap model or run the daemon as the
target user.

## File transfer

You can copy a single file over the resilient session without opening a shell.
A transfer is forward-only (like a `-N`-style session) and cannot be combined
with an interactive shell or with `-L`/`-R`.

```sh
# upload: local file -> remote path
noissh --ssh --put ./report.pdf:/home/user/report.pdf user@server

# download: remote file -> local path
noissh --ssh --get /var/log/app.log:./app.log user@server
```

The spec is split on the **first** colon. For `--put` the order is
`LOCAL:REMOTE`; for `--get` it is `REMOTE:LOCAL`. Files on the server are read
and written as the user you log in as, exactly like a normal login.

On a terminal, a live progress line shows how the transfer is going (a
percentage and byte counts when uploading, where the size is known up front; a
running byte count when downloading). It is suppressed when output is redirected,
so scripts and pipelines stay clean.

A transfer moves a **single file**. For a whole directory, stream a tar over a
remote command, which rides the same resilient session:

```sh
# download a directory tree
noissh --ssh user@server tar czf - /etc > etc.tar.gz

# upload a directory tree
tar czf - ./src | noissh --ssh user@server 'tar xzf - -C /target'
```

Integrity is guaranteed by the reliable, authenticated (AEAD) stream the bytes
ride on, so there is no separate checksum step. If the source cannot be read
(for `--get`) or the destination cannot be created (for `--put`), the transfer
aborts and noissh reports `remote rejected the transfer (no such file or
permission denied)`.

## Agent forwarding

For an interactive session you can forward your local authentication agent so
that remote `git`/`ssh` can use the keys on your machine without copying them to
the server:

```sh
noissh --ssh -A user@server          # long form: --forward-agent
```

The server exposes an `SSH_AUTH_SOCK` in the shell's environment; connections to
it tunnel back over a dedicated session stream to your local agent. Forwarding
applies only to an interactive shell and requires `SSH_AUTH_SOCK` to be set
locally — if `-A` is given but it is unset, noissh prints a warning and
continues without agent forwarding.

The server-side agent socket lives in a per-user directory created `0700`
(noissh refuses a pre-existing path not owned by you) and the socket file itself
is `0600`, so other local users on the server cannot reach your forwarded agent.

## Command reference

### `noissh`

```
noissh [OPTIONS] [user@]host [command ...] [-- <ssh args>]
  --ssh           force the SSH bootstrap (skip the direct probe)
  --direct        direct connection only; never fall back to SSH
  --port N        UDP port for direct connection (default 51820)
  --server-port N pin the bootstrapped server's UDP port (firewall-friendly)
  --server-cmd C  remote server command for --ssh (default "noisshd")
  --no-install    do not auto-install noisshd on the remote if it is missing
  -L LPORT:HOST:PORT   local forward (repeatable); implies forward-only
  -R RPORT:HOST:PORT   remote forward (repeatable); implies forward-only
  -D [BIND:]PORT       dynamic SOCKS forward (repeatable); implies forward-only
  --put LOCAL:REMOTE   upload LOCAL to REMOTE, then exit (no shell)
  --get REMOTE:LOCAL   download REMOTE to LOCAL, then exit (no shell)
  -A, --forward-agent  forward your local auth agent to the shell session
  --copy-id       install your public key into the remote authorized_keys over
                  SSH (like ssh-copy-id), then exit
  --forget-host H remove the pinned server key(s) for host H, then exit
  -v, --verbose   narrate the connection sequence (diagnose connect hangs)
  -h, --help      print usage and exit
  -V, --version   print the version and exit
  command ...     run this command on the server non-interactively (ssh-style),
                  then exit with its status; omit it for an interactive shell
  -- <args>       pass remaining args to ssh (only with --ssh)
```

All options must come before the host.

Everything after `[user@]host` is treated as the remote command, verbatim — its
own flags are not parsed by noissh. Use `--` before the host's trailing position
only to pass arguments to `ssh` during the bootstrap.

Port forwarding rides the same resilient session. `-R` listeners bind to
loopback on the server (forwarded ports are not exposed to the network); `-D`
binds loopback locally by default and speaks SOCKS5 (no auth) and SOCKS4/4a,
CONNECT only.

### `noisshd`

```
noisshd [--listen ADDR] [--key PATH] [--authorized-keys PATH] [--user NAME] [--command CMD ...] [-v]
noisshd --one-shot --authorize <b64pub> [--bind ADDR] [--command CMD ...]
  --listen ADDR        bind address (default 0.0.0.0:51820)
  -v, --verbose        log session lifecycle (established/ended, active count)
                       and fatal socket errors
  --key PATH           static key file (default <config>/noisshd_key)
  --authorized-keys P  authorized_keys file (default <config>/authorized_keys)
  --user NAME          drop sessions to this user (requires root); file transfer,
                       agent forwarding, and exec are refused in this mode
  --command CMD ...    run this command instead of the login shell
  --one-shot           ephemeral key, serve one session, then exit (SSH bootstrap)
  --authorize <b64>    the single client key to trust in one-shot mode
  --bind ADDR          bind address in one-shot mode (default 0.0.0.0:0)
  -h, --help           print usage and exit
  -V, --version        print the version and exit
```

### `noissh-keygen`

```
noissh-keygen [--key PATH]
  --key PATH      keypair file to ensure/print (default <config>/id)
  -h, --help      print usage
  -V, --version   print the version
```

Ensures the keypair exists (creating it `0600` if missing) and prints its public
key line `noissh-x25519 <base64>` to stdout.

## Scrollback and long output

noissh shows a *live picture* of the remote screen (this is what lets it shrug
off packet loss — only the latest screen matters). The trade-off, shared with
Mosh, is that your terminal's native scrollback does not capture lines that
scroll off the top: scrolling up in your terminal shows your local history, not
the remote session's.

For real scrollback, run a terminal multiplexer on the server and use its copy
mode:

```sh
noissh user@server
tmux new -A -s main     # or: screen
# tmux: Ctrl-b [ then PgUp to scroll; q to exit copy mode
```

This also gives you server-side session persistence that survives even a client
reinstall, complementing noissh's network resilience.

## Windows

The noissh **client** is Unix-only today (Linux and macOS): it relies on a PTY
and POSIX terminal handling that the Windows console does not provide directly.
Windows support (e.g. via ConPTY, or through WSL) is tracked as future work. In
the meantime, the client runs well under **WSL**, and the **server** (`noisshd`)
targets Unix hosts. If Windows support matters to you, please open or 👍 an
issue so it can be prioritised.

## Troubleshooting

- **It hangs at connect.** The Noise/UDP session needs the server's UDP port to
  be reachable. Open the port in the firewall (standalone: your `--listen` port;
  SSH bootstrap: the ephemeral port range). TCP-only reachability (SSH works but
  noissh hangs) is the classic symptom of a blocked UDP path.
- **`HOST KEY MISMATCH`.** The server's key changed since you first connected.
  If this is expected (server reinstall), drop the stale pin with
  `noissh --forget-host <host>` (or remove the host's line from
  `~/.config/noissh/known_hosts`) and reconnect; otherwise treat it as a
  potential man-in-the-middle and investigate.
- **It hangs at connect and you're not sure why.** Re-run with `-v`: it narrates
  each step (direct probe, DNS resolution, handshake, SSH bootstrap) so you can
  see where it stalls. A stall right after the handshake starts is the classic
  blocked-UDP symptom above.
- **`--ssh` fails with "no connect line".** The remote `noisshd` could not be
  launched. Normally noissh auto-installs it on first connect; if you passed
  `--no-install`, or the install step could not run (e.g. the remote has neither
  `curl` nor `wget`), install `noisshd` on the server or pass
  `--server-cmd /full/path/to/noisshd` to point at an existing binary.
- **The session freezes after changing networks.** It should recover
  automatically within a second; if not, check that the new network allows
  outbound UDP to the server.
- **Garbled display.** Ensure your local terminal is UTF-8 and that `$TERM` is
  sane; noissh advertises `xterm-256color` to the remote shell by default.
