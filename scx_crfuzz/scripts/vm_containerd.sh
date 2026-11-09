#!/usr/bin/env bash
# From the Mac: build in the Lima VM, then run fuzz_containerd.sh
# (containerd -> shim -> runc startup) for <seeds> seeds.
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
sudo env CRFUZZ_BIN="$target/release/scx_crfuzz" scx_crfuzz/scripts/fuzz_containerd.sh "$seeds" || rc=$?
f=/tmp/crfuzz-containerd/campaign/findings
echo "findings: $(ls "$f" 2>/dev/null | wc -l) in $f (VM $HOSTNAME)"
exit ${rc:-0}
' _ "$1" "$TARGET"
