# noissh-bench

Compares noissh with OpenSSH over a simulated network path, on one Linux or
macOS machine.

For each tool it starts a server on `127.0.0.1` behind a userspace link that
adds one-way delay, jitter and (UDP only) loss, opens a `-L` port forward
through it to a local data server, and measures through the forward:

| column | what |
|---|---|
| bulk MB/s | download of `--size` MB (10⁶ bytes) |
| echo p50/p95 | round trip of 1 byte, 50 samples, 20 ms apart |
| echo loaded p50/95 | the same while bulk downloads run on another connection of the same session |
| idle pkts/s | datagrams per second up/down, idle, over 5 s (noissh only) |

## Running

Needs release builds of `noissh`, `noisshd` and `noissh-keygen`, and for the
`ssh` tool `ssh`, `ssh-keygen` and `sshd` (`openssh-server`). `sshd` runs as
the current user with a generated host key and config in a temporary
directory; as root it needs `/run/sshd`, which the harness creates.

```sh
cargo build --release --bins
./target/release/noissh-bench --rtt 40 --size 20
./target/release/noissh-bench --rtt 40 --loss 1 --tools noissh
```

Options:

```
--rtt MS        round-trip delay added by the link (default 40)
--jitter MS     extra per-packet delay, uniform in [0, MS] (default 0)
--loss PCT      UDP datagrams dropped, each way (default 0)
--size MB       bulk transfer size (default 20)
--tools LIST    comma-separated: noissh, ssh (default both)
--bin-dir DIR   where the noissh binaries are (default target/release)
```

Each transfer gives up after 120 s and reports `timeout`.

## Loss for OpenSSH

The userspace TCP link can delay but not drop: TCP retransmits underneath it.
To compare under loss, impair loopback with `netem` (Linux, root) and set the
harness's own delay to zero:

```sh
sudo tc qdisc add dev lo root netem delay 20ms loss 1%
./target/release/noissh-bench --rtt 0
sudo tc qdisc del dev lo root
```

`netem` applies on each pass through `lo`, so `delay 20ms` gives a 40 ms RTT.

The baseline numbers for 0.6 are in `docs/design/quic-transport.md`, section 9.
