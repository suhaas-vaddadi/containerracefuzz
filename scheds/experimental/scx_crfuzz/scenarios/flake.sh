#!/bin/sh
# Section 14-A, measured directly: hold the seed fixed, vary nothing, and see
# whether the ready-set arrival order -- and the canonical log that follows
# from it -- is reproducible across many runs of real processes.
set -eu
# Guest-side build dir: a host-side `cargo build` writes macOS binaries into
# ./target over the shared mount, which silently breaks runs in the VM.
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
HERE=$(cd "$(dirname "$0")" && pwd)
SEED="${1:-3}"; N="${2:-200}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
sed 's|"policy":.*|"policy": { "type": "random_walk", "seed": '"$SEED"' }|' \
    "$HERE/discovery.json" > "$W/cfg.json"
i=0
while [ $i -lt "$N" ]; do
    "$HERE/setup.sh" /tmp/crfuzz
    sudo "$BIN" --config "$W/cfg.json" \
        --cgroup-path /crfuzz/run0 \
        --spawn "$HERE/victim /tmp/crfuzz/target" \
        --spawn "$HERE/racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
        --canonical-log "$W/log.$i" >"$W/out.$i" 2>"$W/err.$i" || true
    printf '%s\t%s\t%s\t%s\n' \
        "$(md5sum "$W/log.$i" | cut -c1-8)" \
        "$(sed -n 's/.*arrival: //p' "$W/err.$i")" \
        "$(sed -n 's/.*ready-sets: //p' "$W/err.$i")" \
        "$(grep -o 'VERDICT:[a-zA-Z=-]*' "$W/out.$i" || echo none)|$(sed -n 's/.*outcome: \([A-Za-z]*\).*/\1/p' "$W/err.$i")" >> "$W/rows"
    i=$((i+1))
done
echo "seed=$SEED runs=$N   columns: count | log-hash | arrival | ready-sets at each decision | verdict"
sort "$W/rows" | uniq -c | sort -rn | sed 's/^/  /'
