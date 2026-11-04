#!/usr/bin/env bash
# From the Mac: build in the Lima VM, make sure the gate daemon is up, then run
# fuzz_containerd.sh (containerd -> shim -> runc startup) for <seeds> seeds.
#
#   vm_containerd.sh <seeds>        env: VM [sched-ext], TARGET [/tmp/crfuzz-target]
#
# The repo mount is read-only in the VM, so the build goes to $TARGET there.
# Results stay in the VM under /tmp/crfuzz-containerd.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <seeds>" >&2; exit 2; }
VM=${VM:-sched-ext}
TARGET=${TARGET:-/tmp/crfuzz-target}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

limactl shell --workdir "$repo" "$VM" -- bash -euc '
seeds=$1 target=$2
cargo build --release --target-dir "$target"
gated=$target/release/scx_crfuzz_gated
if ! grep -qx enabled /sys/kernel/sched_ext/state; then
	sudo nohup "$gated" >/tmp/crfuzz-gated.log 2>&1 &
	for _ in $(seq 50); do grep -qx enabled /sys/kernel/sched_ext/state && break; sleep 0.1; done
	grep -qx enabled /sys/kernel/sched_ext/state || { echo "gated did not start; see /tmp/crfuzz-gated.log" >&2; exit 1; }
fi
sudo env CRFUZZ_BIN="$target/release/scx_crfuzz" CRFUZZ_GATED="$gated" \
	scx_crfuzz/scripts/fuzz_containerd.sh "$seeds" || rc=$?
f=/tmp/crfuzz-containerd/campaign/findings
echo "findings: $(ls "$f" 2>/dev/null | wc -l) in $f (VM $HOSTNAME)"
exit ${rc:-0}
' _ "$1" "$TARGET"
