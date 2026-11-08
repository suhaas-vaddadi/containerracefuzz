#!/bin/sh
# The SUT: a private containerd (a child of the SUT, so the shim and runc
# inherit the hold), a busy busybox container, then teardown.
set -eu
d="$CRFUZZ_DIR/run"
find "$d" -mindepth 1 -delete  # a mount point: emptied, never removed
mkdir -p "$d/root" "$d/state"
echo "== $(date)" >>"$CRFUZZ_DIR/logs/containerd.log"
"$CRFUZZ_CONTAINERD" --root "$d/root" --state "$d/state" --address "$d/sock" \
	>>"$CRFUZZ_DIR/logs/containerd.log" 2>&1 &
cpid=$!
trap 'kill "$cpid" 2>/dev/null || true' EXIT
i=0
while [ ! -S "$d/sock" ]; do
	i=$((i + 1))
	[ "$i" -gt 400 ] && { echo "containerd socket never appeared" >&2; exit 1; }
	sleep 0.05
done
# --cgroup: beside ours (run-<pid>-<epoch>/sut) under the run cgroup, so runc init stays tracked.
cg=$(cut -d: -f3 /proc/self/cgroup)
"$CRFUZZ_CTR" --address "$d/sock" run --rm --cgroup "${cg%/*}/busy" --runc-root "$d/runc" --rootfs "$CRFUZZ_ROOTFS" busy \
	/bin/busybox sh -c '/bin/busybox echo busy; /bin/busybox sleep 0.5'
