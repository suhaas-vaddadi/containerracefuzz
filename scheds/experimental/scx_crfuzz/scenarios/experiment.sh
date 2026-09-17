#!/bin/sh
# Run one discovery config N times at a fixed seed and report, separately:
#   - how many DISTINCT canonical logs came back   (design doc section 10.1)
#   - how many DISTINCT ready-set arrival orders   (design doc section 14-A)
# These are different questions. 10.1 can pass while 14-A fails, if the
# arrival order varies in ways that happen not to change any decision.
set -eu
# Guest-side build dir: a host-side `cargo build` writes macOS binaries into
# ./target over the shared mount, which silently breaks runs in the VM.
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
HERE=$(cd "$(dirname "$0")" && pwd)
SEED="${1:-1}"
N="${2:-20}"
POLICY="${3:-random_walk}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ "$POLICY" = pct ]; then
    BLOCK='"policy": { "type": "pct", "seed": '"$SEED"', "params": { "d": 3, "k": 6 } }'
else
    BLOCK='"policy": { "type": "random_walk", "seed": '"$SEED"' }'
fi
sed 's|"policy":.*|'"$BLOCK"'|' "$HERE/discovery.json" > "$WORK/cfg.json"

i=0
while [ $i -lt "$N" ]; do
    "$HERE/setup.sh" /tmp/crfuzz
    sudo "$BIN" \
        --config "$WORK/cfg.json" --cgroup-path /crfuzz/run0 \
        --spawn "$HERE/victim /tmp/crfuzz/target" \
        --spawn "$HERE/racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
        --canonical-log "$WORK/log.$i" >"$WORK/out.$i" 2>"$WORK/err.$i" || true
    grep -o 'VERDICT:[a-zA-Z=-]*' "$WORK/out.$i" >> "$WORK/verdicts" || echo "VERDICT:none" >> "$WORK/verdicts"
    sed -n "s/.*arrival: //p" "$WORK/err.$i" >> "$WORK/arrivals"
    i=$((i+1))
done

LOGS=$(md5sum "$WORK"/log.* | awk '{print $1}' | sort -u | wc -l)
ARR=$(sort -u "$WORK/arrivals" | wc -l)
echo "policy=$POLICY seed=$SEED runs=$N"
echo "  distinct canonical logs (10.1):   $LOGS"
echo "  distinct arrival orders  (14-A):  $ARR"
echo "  verdicts: $(sort "$WORK/verdicts" | uniq -c | tr -s ' ' | tr '\n' ' ')"
if [ "$ARR" -gt 1 ]; then
    echo "  --- the distinct arrival orders ---"
    sort "$WORK/arrivals" | uniq -c | sed 's/^/  /'
fi
