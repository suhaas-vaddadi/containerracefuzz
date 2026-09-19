#!/bin/sh
# One run of the Go scenario. Same shape as run.sh, but the victim is a Go
# binary, so this is the first scenario where --freezer is load-bearing rather
# than merely available: go_victim runs on ~11 OS threads, and seccomp alone
# holds exactly one of them.
#
# Discovery, not replay. A hand-written schedule would have to name the six
# openat calls the Go runtime makes before main() ever runs -- which is the
# same startup noise that will dominate a runc scenario, and the reason the
# generator's contention filter exists.
set -eu
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
HERE=$(cd "$(dirname "$0")" && pwd)
"$HERE/setup.sh" /tmp/crfuzz
exec sudo "$BIN" \
    --config "$HERE/go_race.json" \
    --cgroup-path /crfuzz/run0 \
    --freezer \
    --spawn "$HERE/go_victim /tmp/crfuzz/target /tmp/crfuzz/goprog" \
    --spawn "$HERE/racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
    "$@"
