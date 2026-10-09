#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# One run of the sweep against a runc bundle: with a window, the swap attacker
# substitutes the path runc's syscall resolves at that one window, and the
# oracle reports any escape; without one, a dry run that lists the windows.
# The cgroup, gate, bundle preflight and spawn are assembled here so the
# command line stays short.
#
#   ./attack_run.sh [window] [bundle] [container-id]
#
# Defaults: a dry run, bundle /tmp/bundle, a fresh container id. The bundle is
# copied to a scratch directory first, because the attacker moves paths aside
# and runc then fails; the original is left untouched so the run is repeatable.
#
# With a long-lived entrypoint `runc run` never exits, so the engine ends on
# its idle timeout (exit 2) with the container still running; that is what
# lets the oracle inspect it. The container is deleted on exit.
#
# Root is required (seccomp user-notify), and scx_crfuzz_gated must be running
# (the sched_ext gate holds runc's whole thread group). The attacker
# substitutes an object of the target's own type; point CRFUZZ_EVIL_DIR at a
# real tree (e.g. a rootfs copy) to see whether runc follows it.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
RUNC="${CRFUZZ_RUNC:-/usr/local/bin/runc}"
AT="${1:-}"
BUNDLE="${2:-${CRFUZZ_BUNDLE:-/tmp/bundle}}"
ID="${3:-crfuzz-attack-$$}"
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
# Delete the container before its rootfs: a long-lived one is still running.
trap 'sudo "$RUNC" delete -f "$ID" >/dev/null 2>&1 || true; sudo rm -rf "$WORK"' EXIT INT TERM
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
# CRFUZZ_CONFIG selects the scenario (default runc_attack.json).
sudo env \
    PATH="$HERE:$PATH" \
    CRFUZZ_EVIL_TARGET="$EVIL_TARGET" \
    CRFUZZ_EVIL_DIR="$EVIL_DIR" \
    CRFUZZ_EVIL_FILE="$EVIL_FILE" \
    CRFUZZ_ATTACK_ROOT="$WORK" \
    CRFUZZ_CVE="${CRFUZZ_CVE:-}" \
    CRFUZZ_ATTACK_FAMILY="${CRFUZZ_ATTACK_FAMILY:-}" \
    CRFUZZ_ATTACK_KIND="${CRFUZZ_ATTACK_KIND:-}" \
    CRFUZZ_ATTACK_CROSS_MAP="${CRFUZZ_ATTACK_CROSS_MAP:-}" \
    CRFUZZ_ATTACK_VERBS="${CRFUZZ_ATTACK_VERBS:-}" \
    CRFUZZ_ATTACK_SEED="${CRFUZZ_ATTACK_SEED:-}" \
    CRFUZZ_ATTACK_MAX_STEPS="${CRFUZZ_ATTACK_MAX_STEPS:-}" \
    CRFUZZ_ATTACK_EXCLUDE_KNOWN="${CRFUZZ_ATTACK_EXCLUDE_KNOWN:-}" \
    CRFUZZ_ATTACK_LOG="${CRFUZZ_ATTACK_LOG:-}" \
    CRFUZZ_ATTACK_PLAN_LOG="${CRFUZZ_ATTACK_PLAN_LOG:-}" \
    CRFUZZ_ATTACK_ALLOW_MOUNT="${CRFUZZ_ATTACK_ALLOW_MOUNT:-0}" \
    CRFUZZ_REDIR_TARGET="${CRFUZZ_REDIR_TARGET:-}" \
    CRFUZZ_REDIR_ANCHOR="${CRFUZZ_REDIR_ANCHOR:-}" \
    CRFUZZ_EVIL_MODE="${CRFUZZ_EVIL_MODE:-}" \
    "$BIN" \
    --config "${CRFUZZ_CONFIG:-$HERE/runc_attack.json}" \
    --cgroup-path "/crfuzz/$ID" \
    --gate \
    --oci-bundle "$WORK" \
    ${AT:+--at "$AT"} \
    --spawn "$RUNC run -b $WORK $ID"
