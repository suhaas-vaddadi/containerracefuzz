#!/bin/sh
# Scenario 2 -- multithreaded victim against a multithreaded attacker, scheduled
# by POS, where every thread is its own actor. No runc here: both sides are
# sample processes. `threaded_victim` runs a checking main thread plus a sibling
# worker; `mt_attacker` runs several worker threads each hammering `renameat`.
#
# Every thread that reaches a checkpoint is its own POS actor, and a hit holds
# only that thread (the per-tid gate), so siblings keep running and
# reach checkpoints of their own -- which whole-group holding cannot express.
# The decision trace (debug log) names threads as `role/t<n>`.
#
# Needs root and scx_crfuzz_gated running.
#
#   make run-02        # from scenarios/
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
DIR=/tmp/crfuzz-mt
OUT="${CRFUZZ_OUTDIR:-$DIR}"

rm -rf "$DIR"; mkdir -p "$DIR/scratch"
printf 'BENIGN\n' > "$DIR/target"

exec sudo "$BIN" \
    --config "$HERE/race.json" \
    --out "$OUT" \
    --spawn "$HERE/threaded_victim $DIR/target $DIR/progress" \
    --spawn "$HERE/mt_attacker $DIR/scratch 3 1" \
    "$@"
