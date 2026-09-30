#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# One `auto_attack` run against a runc bundle: the swap attacker substitutes the
# path at every held `mount`/`symlinkat` checkpoint and the oracle reports any
# path whose object type changed under runc. This is the simple entry point --
# the cgroup, gate, bundle preflight and spawn are assembled here so the
# command line stays one word.
#
#   ./attack_run.sh [bundle] [container-id]
#
# Defaults: bundle /tmp/bundle, a fresh container id. The bundle is copied to a
# scratch directory first, because the attacker moves paths aside and runc
# then fails; the original is left untouched so the run is repeatable.
#
# Root is required (seccomp user-notify), and scx_crfuzz_gated must be running
# (the sched_ext gate holds runc's whole thread group). The attacker
# substitutes an object of the target's own type; point CRFUZZ_EVIL_DIR at a
# real tree (e.g. a rootfs copy) to see whether runc follows it.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
RUNC="${CRFUZZ_RUNC:-/usr/local/bin/runc}"
BUNDLE="${1:-${CRFUZZ_BUNDLE:-/tmp/bundle}}"
ID="${2:-crfuzz-attack-$$}"
EVIL_TARGET="${CRFUZZ_EVIL_TARGET:-/tmp/crfuzz-evil-target}"
EVIL_DIR="${CRFUZZ_EVIL_DIR:-/tmp/crfuzz-evil-dir}"
EVIL_FILE="${CRFUZZ_EVIL_FILE:-/tmp/crfuzz-evil-file}"

if [ ! -f "$BUNDLE/config.json" ]; then
    echo "attack_run.sh: no OCI bundle at $BUNDLE (need config.json)" >&2
    exit 1
fi

# A throwaway copy, so the attacker's swaps do not poison the bundle for the
# next run.
WORK=$(mktemp -d /tmp/crfuzz-attack.XXXXXX)
trap 'sudo rm -rf "$WORK"' EXIT INT TERM
sudo cp -a "$BUNDLE/." "$WORK/"

# runc 1.5+ refuses to create a container when its own process is in a
# non-empty cgroup and the spec names no `linux.cgroupsPath`: it derives the
# container's cgroup from its own and finds itself in it ("container's cgroup
# is not empty"). The engine places runc in /crfuzz/<id> for role matching, so
# give the container a dedicated child cgroup. Left alone when the bundle
# already sets one, and the `<id>/ctr` path still matches the role's `/crfuzz`
# prefix.
if ! sudo grep -q '"cgroupsPath"' "$WORK/config.json"; then
    sudo sed -i "s#\"linux\": {#\"linux\": {\n    \"cgroupsPath\": \"/crfuzz/$ID/ctr\",#" \
        "$WORK/config.json"
fi

# sudo env: pass the payload and the swap scope through sudo's environment
# scrubbing. The scope is the throwaway bundle copy, so the attacker can only
# substitute paths inside the tree runc is setting up.
sudo env \
    CRFUZZ_EVIL_TARGET="$EVIL_TARGET" \
    CRFUZZ_EVIL_DIR="$EVIL_DIR" \
    CRFUZZ_EVIL_FILE="$EVIL_FILE" \
    CRFUZZ_ATTACK_ROOT="$WORK" \
    "$BIN" \
    --config "$HERE/runc_attack.json" \
    --cgroup-path "/crfuzz/$ID" \
    --gate \
    --oci-bundle "$WORK" \
    --spawn "$RUNC run -b $WORK $ID"
