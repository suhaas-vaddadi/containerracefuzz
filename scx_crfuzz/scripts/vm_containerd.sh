#!/usr/bin/env bash
# From the Mac: build release in the Lima VM, then run the built-in containerd
# target (containerd -> shim -> runc startup) for <seeds> seeds.
#
#   vm_containerd.sh <seeds>        env: VM [sched-ext], TARGET [/var/tmp/crfuzz-target]
#
# The repo mount is read-only in the VM, so the build goes to $TARGET there
# (on disk: the VM's /tmp is a small tmpfs).
# Results stay in the VM under /tmp/crfuzz-containerd.
set -eu
[ $# -eq 1 ] || { echo "usage: $0 <seeds>" >&2; exit 2; }
VM=${VM:-sched-ext}
TARGET=${TARGET:-/var/tmp/crfuzz-target}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

limactl shell --workdir "$repo" "$VM" -- bash -euc '
seeds=$1 target=$2
cargo build --release --target-dir "$target"
sudo "$target/release/scx_crfuzz" containerd --seeds "$seeds" || rc=$?
f=/tmp/crfuzz-containerd/campaign/findings
echo "findings: $(ls "$f" 2>/dev/null | wc -l) in $f (VM $HOSTNAME)"
exit ${rc:-0}
' _ "$1" "$TARGET"
