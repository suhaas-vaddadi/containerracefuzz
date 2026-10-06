#!/bin/sh
# Scenario 2 -- multithreaded victim against a multithreaded attacker, scheduled
# by POS, where every thread is its own actor. No runc here: both sides are
# sample processes. `threaded_victim` runs a checking main thread plus a sibling
# worker; `mt_attacker` runs several worker threads each hammering `renameat`.
#
# Every thread that reaches a checkpoint is its own POS actor, and a hit parks
# only that thread. A decision is taken only when every thread is at rest, so
# each ready set holds every thread parked at a checkpoint. The decision trace
# (debug log) names threads by clone path, `role/t0.1`. The victim's sibling
# sleeps on a 1 ms timer, so most decisions count as timed-sleep decisions.
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
