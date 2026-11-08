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
--rtt MS          round-trip delay added by the link (default 40)
--jitter MS       extra per-packet delay, uniform in [0, MS] (default 0)
--loss PCT        UDP datagrams dropped, each way (default 0)
--size MB         bulk transfer size (default 20)
--tools LIST      comma-separated: noissh, ssh (default both)
--bin-dir DIR     where the noissh binaries are (default target/release)
--timeout S       give up on a transfer after S seconds (default 120)
--no-link         connect directly, without the userspace link
--noissh-port N   UDP port for noisshd (default: random)
--ssh-port N      TCP port for sshd (default: random)
```

A transfer that takes longer than `--timeout` reports `timeout`.

## Loss for OpenSSH

The userspace TCP link can delay but not drop: TCP retransmits underneath it.
To compare under loss, `bench/netem.sh` impairs loopback with the kernel's
`netem` instead (Linux, sudo; the CI *Benchmark* workflow runs it on every
pull request that touches the code and puts the table in the job summary):

```sh
cargo build --release --bins
bench/netem.sh 20
```

It runs the servers on fixed ports (`--no-link --noissh-port 41001
--ssh-port 41002`), impairs only traffic to and from those ports (so the
local legs of the forwards stay clean), and sets loopback to a 1500-byte MTU
with segmentation offloads off for the run, so TCP and UDP lose packets of
comparable size. Scenarios: RTT 40 ms with 0, 1 and 5 % loss, and 150 ms.

The baseline numbers for 0.6 are in `docs/design/quic-transport.md`, section 9.
