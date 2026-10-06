#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Scenario 3 -- a full container startup driven by containerd, with two
# multithreaded attackers interleaved against the instrumented `runc create`,
# scheduled by POS with thread-level actors.
#
#     make run-03                 # from scenarios/
#     ./run.sh [container-id]
#
# `runc_wrapper_attackers.sh` replaces the leaf `runc` binary containerd's shim
# execs, so containerd and the shim are untouched. The wrapper spawns three
# thread groups under the engine: `runc` and two `mt_attacker` pool members,
# each parked and released one thread at a time by the `pos` policy.
#
# Root is required (seccomp user-notify) and scx_crfuzz_gated must be running.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
IMAGE="${CRFUZZ_IMAGE:-docker.io/library/busybox:latest}"
ID="${1:-crfuzz-ctr-$$}"
OUTDIR="${CRFUZZ_OUTDIR:-/tmp/crfuzz-runc}"

# A leftover container from a failed run would make `ctr run` refuse the id.
sudo ctr -n default container rm "$ID" >/dev/null 2>&1 || true

echo "image:   $IMAGE"
echo "id:      $ID"
echo "wrapper: $HERE/runc_wrapper_attackers.sh"
echo "logs:    $OUTDIR/$ID/"

sudo ctr -n default run --rm \
    --runc-binary "$HERE/runc_wrapper_attackers.sh" \
    "$IMAGE" "$ID" /bin/echo "container started"

echo "--- canonical log ($OUTDIR/$ID/log): roles released ---"
if [ -f "$OUTDIR/$ID/log" ]; then
    # Skip the `# scenario` header so the line count and per-role tally are exact.
    grep -v '^#' "$OUTDIR/$ID/log" | wc -l
    grep -v '^#' "$OUTDIR/$ID/log" | cut -f2 | cut -d/ -f1 | sort | uniq -c
else
    echo "(no log written)"
fi
