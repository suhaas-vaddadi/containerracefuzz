#!/usr/bin/env bash
# Fuzz a containerd -> shim -> runc container startup with the mutator in
# tests/fixtures/mutator_all.c. Needs root and a running scx_crfuzz_gated.
#
#   fuzz_containerd.sh <seeds>
#
# The SUT starts a private containerd as its own child, so the shim and runc
# inherit the hold, then runs a busybox container from an attacker-owned rootfs.
#
# Env (optional):
#   CRFUZZ_BIN       scx_crfuzz binary      [<repo>/target-linux/debug/scx_crfuzz]
#   CRFUZZ_GATED     scx_crfuzz_gated bin   [<repo>/target-linux/debug/scx_crfuzz_gated]
#   CRFUZZ_ATTACKER  attacker UID:GID       [65534:65534]
#   CRFUZZ_DIR       scratch directory      [/tmp/crfuzz-containerd]
#   CRFUZZ_IMAGE     static busybox to use  [/usr/bin/busybox]
#   CRFUZZ_CC        C compiler             [cc]
# CRFUZZ_SCOPE defaults to the rootfs. Other CRFUZZ_* are inherited by the
# mutator; crfuzz sets CRFUZZ_CANARY itself.
#
# Logs, under $CRFUZZ_DIR/logs/: scx_crfuzz.log (campaign output), mutator.log
# and containerd.log (appended, one "==" header per SUT run). Results are in
# $CRFUZZ_DIR/campaign (runs.tsv, runs/, findings/).
#
# The container's cgroup is placed under the run cgroup (ctr --cgroup), so runc
# init and the container are tracked. Known limit (spec L:Engine): a hold inside
# the container's root, after pivot_root, cannot see the canary.
set -eu

usage() { echo "usage: $0 <seeds>" >&2; exit 2; }
[ $# -eq 1 ] || usage
SEEDS=$1
case "$SEEDS" in ''|*[!0-9]*) usage ;; esac
[ "$SEEDS" -ge 1 ] || usage

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)

CRFUZZ_BIN=${CRFUZZ_BIN:-$repo/target-linux/debug/scx_crfuzz}
CRFUZZ_GATED=${CRFUZZ_GATED:-$repo/target-linux/debug/scx_crfuzz_gated}
CRFUZZ_ATTACKER=${CRFUZZ_ATTACKER:-65534:65534}
CRFUZZ_DIR=${CRFUZZ_DIR:-/tmp/crfuzz-containerd}
CRFUZZ_IMAGE=${CRFUZZ_IMAGE:-/usr/bin/busybox}
CRFUZZ_CC=${CRFUZZ_CC:-cc}

[ "$(id -u)" -eq 0 ] || { echo "$0: needs root" >&2; exit 1; }
[ -x "$CRFUZZ_BIN" ] || { echo "$0: no scx_crfuzz at $CRFUZZ_BIN (build it in the VM)" >&2; exit 1; }
[ -r "$CRFUZZ_IMAGE" ] || { echo "$0: no busybox at $CRFUZZ_IMAGE" >&2; exit 1; }
case "$CRFUZZ_ATTACKER" in *:*) ;; *) echo "$0: CRFUZZ_ATTACKER must be UID:GID" >&2; exit 1 ;; esac
auid=${CRFUZZ_ATTACKER%%:*}
agid=${CRFUZZ_ATTACKER##*:}

CONTAINERD=$(command -v containerd) || { echo "$0: containerd not on PATH" >&2; exit 1; }
CTR=$(command -v ctr) || { echo "$0: ctr not on PATH" >&2; exit 1; }

if [ -x "$CRFUZZ_GATED" ]; then
	"$CRFUZZ_GATED" --status 2>/dev/null | grep -q '^state: *enabled' ||
		echo "warning: sched_ext not enabled; start $CRFUZZ_GATED first" >&2
fi

# Fresh scratch: rootfs, static mutator (also mirrored at the same absolute path
# inside the rootfs, so it exists in the held task's view), SUT and layout.
case "$CRFUZZ_DIR" in ""|/) echo "$0: bad CRFUZZ_DIR" >&2; exit 1 ;; esac
rm -rf "$CRFUZZ_DIR"
mkdir -p "$CRFUZZ_DIR/rootfs/bin" "$CRFUZZ_DIR/rootfs/proc" "$CRFUZZ_DIR/rootfs/dev" \
	"$CRFUZZ_DIR/rootfs/tmp" "$CRFUZZ_DIR/mut" "$CRFUZZ_DIR/logs"
# The mutator runs as the attacker, so her log file is writable by her. The
# directory stays root-only: otherwise the SUT's own log path would be
# attacker-writable and the mutator would redirect the SUT's log into the canary.
: > "$CRFUZZ_DIR/logs/mutator.log"
chmod 666 "$CRFUZZ_DIR/logs/mutator.log"
cp "$CRFUZZ_IMAGE" "$CRFUZZ_DIR/rootfs/bin/busybox"
"$CRFUZZ_CC" -O2 -static -o "$CRFUZZ_DIR/mut/mutator_all" \
	"$repo/scx_crfuzz/tests/fixtures/mutator_all.c"
mkdir -p "$CRFUZZ_DIR/rootfs$(dirname "$CRFUZZ_DIR/mut/mutator_all")"
cp "$CRFUZZ_DIR/mut/mutator_all" "$CRFUZZ_DIR/rootfs$CRFUZZ_DIR/mut/mutator_all"
chown -R "$auid:$agid" "$CRFUZZ_DIR/rootfs"
# Pristine copy; layout.sh restores the rootfs from it before each run.
cp -a "$CRFUZZ_DIR/rootfs" "$CRFUZZ_DIR/rootfs.orig"

# The SUT: a private containerd (a child of the SUT, so the shim and runc
# inherit the hold), a busy busybox container, then teardown.
cat > "$CRFUZZ_DIR/sut.sh" <<'EOF'
#!/bin/sh
set -eu
d="$CRFUZZ_DIR/run"
rm -rf "$d"
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
EOF

# Reset between runs: daemon state and the rootfs the mutator rearranged.
cat > "$CRFUZZ_DIR/layout.sh" <<'EOF'
#!/bin/sh
rm -rf "$CRFUZZ_DIR/run"
rm -rf "$CRFUZZ_DIR/rootfs" && cp -a "$CRFUZZ_DIR/rootfs.orig" "$CRFUZZ_DIR/rootfs"
EOF
chmod +x "$CRFUZZ_DIR/sut.sh" "$CRFUZZ_DIR/layout.sh"

CRFUZZ_LOG=${CRFUZZ_LOG:-$CRFUZZ_DIR/logs/mutator.log}
# The mutator may only rearrange the attacker-owned rootfs; without this the
# SUT's own cwd or a /tmp path could pass the mutator's default scope.
CRFUZZ_SCOPE=${CRFUZZ_SCOPE:-$CRFUZZ_DIR/rootfs}
export CRFUZZ_DIR CRFUZZ_ROOTFS="$CRFUZZ_DIR/rootfs" CRFUZZ_SCOPE \
	CRFUZZ_CONTAINERD="$CONTAINERD" CRFUZZ_CTR="$CTR" CRFUZZ_LOG

log="$CRFUZZ_DIR/logs/scx_crfuzz.log"
echo "scenario: containerd -> shim -> runc startup; busy busybox rootfs owned by $CRFUZZ_ATTACKER" | tee "$log"
echo "campaign: $CRFUZZ_DIR/campaign ($SEEDS seeds)" | tee -a "$log"
echo | tee -a "$log"

# The SUT inherits this cwd: keep relative paths out of the repo.
cd "$CRFUZZ_DIR"
set +e
"$CRFUZZ_BIN" --campaign "$CRFUZZ_DIR/campaign" --seeds "$SEEDS" \
	--attacker "$CRFUZZ_ATTACKER" \
	--mutator "$CRFUZZ_DIR/mut/mutator_all" \
	--layout "$CRFUZZ_DIR/layout.sh" \
	--scope "$CRFUZZ_SCOPE" \
	-- "$CRFUZZ_DIR/sut.sh" | tee -a "$log"  # stderr stays a tty: progress bar
rc=${PIPESTATUS[0]}
set -e

exit "$rc"
