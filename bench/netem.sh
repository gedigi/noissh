#!/usr/bin/env bash
# Compare noissh with OpenSSH over loopback impaired by the kernel's netem
# (Linux, needs sudo for tc/ip/ethtool). Used by the CI benchmark job; see
# bench/README.md. Prints a Markdown table.
#
#   bench/netem.sh [SIZE_MB]
#
# Only traffic to and from the two server ports is impaired (a prio qdisc
# with u32 filters), so the local legs of the forwards stay clean. Loopback
# is set to a 1500-byte MTU with segmentation offloads off for the run, so
# TCP and UDP lose packets of comparable size.
set -euo pipefail

SIZE=${1:-20}
NOISSH_PORT=41001
SSH_PORT=41002
BIN=target/release
if [ ! -x "$BIN/noissh-bench" ]; then
    echo "missing $BIN/noissh-bench: run cargo build --release --workspace --bins" >&2
    exit 1
fi

restore() {
    sudo tc qdisc del dev lo root 2>/dev/null || true
    sudo ip link set lo mtu 65536 || true
    sudo ethtool -K lo gso on tso on gro on 2>/dev/null || true
}
trap restore EXIT

sudo ip link set lo mtu 1500
sudo ethtool -K lo gso off tso off gro off 2>/dev/null || true

impair() { # one-way delay (ms), loss (%)
    sudo tc qdisc del dev lo root 2>/dev/null || true
    sudo tc qdisc add dev lo root handle 1: prio bands 3 \
        priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    sudo tc qdisc add dev lo parent 1:3 handle 30: \
        netem delay "${1}ms" loss "${2}%" limit 100000
    for p in $NOISSH_PORT $SSH_PORT; do
        sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 \
            match ip dport "$p" 0xffff flowid 1:3
        sudo tc filter add dev lo parent 1: protocol ip prio 1 u32 \
            match ip sport "$p" 0xffff flowid 1:3
    done
}

echo "| RTT | loss | tool | bulk MB/s | echo p50/p95 ms | echo under load p50/p95 ms |"
echo "|---|---|---|---|---|---|"
for scenario in "20 0" "20 1" "75 0" "20 5"; do
    set -- $scenario
    impair "$1" "$2"
    out=$("$BIN/noissh-bench" --no-link --noissh-port $NOISSH_PORT --ssh-port $SSH_PORT \
        --size "$SIZE" --timeout 300 --bin-dir "$BIN")
    echo "$out" >&2
    echo "$out" | awk -v rtt="$(( $1 * 2 )) ms" -v loss="$2 %" \
            '$1 == "noissh" || $1 == "ssh" {
                printf "| %s | %s | %s | %s | %s | %s |\n", rtt, loss, $1, $2, $3, $4
            }'
done
