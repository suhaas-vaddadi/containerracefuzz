#!/bin/sh
# One scenario run. The fixture is single-use (the racer consumes the symlink
# by renaming it), so it is rebuilt every time.
set -eu
# Guest-side build dir: a host-side `cargo build` writes macOS binaries into
# ./target over the shared mount, which silently breaks runs in the VM.
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
HERE=$(cd "$(dirname "$0")" && pwd)
CONFIG="$1"; shift
"$HERE/setup.sh" /tmp/crfuzz
exec sudo "$BIN" \
    --config "$HERE/$CONFIG" \
    --cgroup-path /crfuzz/run0 \
    --spawn "$HERE/victim /tmp/crfuzz/target" \
    --spawn "$HERE/racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
    "$@"
