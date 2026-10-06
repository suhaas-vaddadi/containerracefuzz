#!/bin/sh
# Scenario 1 -- the most basic proof of concept: one single-threaded victim
# against one single-threaded attacker, scheduled by the partial-order policy
# (POS). The victim checks a path then uses it; the racer renames a symlink over
# that path. POS samples the orderings of their path-touching syscalls.
#
# Needs root (seccomp user-notify) and scx_crfuzz_gated running: every run
# reads thread state from its sensor.
#
#   make run-01        # from scenarios/
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
DIR=/tmp/crfuzz

# Single-use fixture: the racer consumes the symlink by renaming it.
"$HERE/setup.sh" "$DIR"

exec sudo "$BIN" \
    --config "$HERE/race.json" \
    --spawn "$HERE/victim $DIR/target" \
    --spawn "$HERE/racer $DIR/evil $DIR/target" \
    "$@"
