#!/bin/sh
# The SUT: a private containerd (a child of the SUT, so the shim and runc
# inherit the hold), a busy busybox container, then teardown.
set -eu
d="$CRFUZZ_DIR/run"
find "$d" -mindepth 1 -delete  # a mount point: emptied, never removed
mkdir -p "$d/root" "$d/state"
exec 4>>"$CRFUZZ_DIR/logs/containerd.log"
echo "== $(date)" >&4
# Ready once it logs its boot (its socket is listening by then). Read off a
# FIFO, not polled: a poll loop's syscall count varies run to run, and every
# stat it makes is a held event, so a replay could never match it.
# Unbounded here (sh has no `read -t`, and `timeout` would fork held events):
# a containerd that exits closes the FIFO, one that hangs meets the run's --timeout.
mkfifo "$d/log"
"$CRFUZZ_CONTAINERD" --root "$d/root" --state "$d/state" --address "$d/sock" >"$d/log" 2>&1 &
cpid=$!
trap 'kill "$cpid" 2>/dev/null || true' EXIT
exec 3<"$d/log"
up=
while IFS= read -r l <&3; do
	printf '%s\n' "$l" >&4
	case $l in *"containerd successfully booted"*) up=1 && break ;; esac
done
[ -n "$up" ] || { echo "containerd exited before booting" >&2; exit 1; }
cat <&3 >&4 &
# A cgroup of this worker's own (the mount namespace is the worker's): one
# name for all would be shared at --jobs > 1, one per run would pile up.
ns=$(readlink /proc/self/ns/mnt) # mnt:[4026531841]
ns=${ns#mnt:?}
"$CRFUZZ_CTR" --address "$d/sock" run --rm --cgroup "/crfuzz-busy-${ns%?}" --runc-root "$d/runc" --rootfs "$CRFUZZ_ROOTFS" busy \
	/bin/busybox sh -c '/bin/busybox echo busy; /bin/busybox sleep 0.5'
