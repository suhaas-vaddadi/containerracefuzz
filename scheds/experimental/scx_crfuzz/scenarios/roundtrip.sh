#!/bin/sh
# Design doc sections 3.5 and 10.3, end to end against real processes:
#   1. run discovery until the oracle says the victim read the secret
#   2. project that run's canonical log into a replay schedule (drop step_idx)
#   3. replay the projection against a fresh instance of the same scenario
#   4. check it reproduces the same violation, and the same log
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
SEED="${1:-1}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

sed 's|"policy":.*|"policy": { "type": "random_walk", "seed": '"$SEED"' }|' \
    "$HERE/discovery.json" > "$W/discovery.json"

"$HERE/setup.sh" /tmp/crfuzz
DISC_VERDICT=$(sudo "$BIN" --config "$W/discovery.json" --cgroup-path /crfuzz/run0 \
    --spawn "$HERE/victim /tmp/crfuzz/target" \
    --spawn "$HERE/racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
    --canonical-log "$W/disc.log" --project-schedule "$W/steps.json" 2>/dev/null \
    | grep -o 'VERDICT:[a-zA-Z=-]*')

echo "1. discovery (seed $SEED) -> $DISC_VERDICT"
sed 's/^/     /' "$W/disc.log"

# Build the replay config: same scenario, steps instead of policy, and the
# checkpoints those steps name declared explicitly (replay mode gets no default
# set -- a hand-authored schedule names what it cares about).
python3 - "$W/discovery.json" "$W/steps.json" "$W/replay.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
steps = json.load(open(sys.argv[2]))
cfg.pop("policy", None)
cfg["steps"] = steps
used = sorted({s["until"] for s in steps} - {"exit"})
cfg["checkpoints"] = [{"id": c, "kind": "syscall", "target": c} for c in used]
json.dump(cfg, open(sys.argv[3], "w"), indent=2)
PY
echo "2. projected $(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' "$W/steps.json") steps"

"$HERE/setup.sh" /tmp/crfuzz
REPLAY_VERDICT=$(sudo "$BIN" --config "$W/replay.json" --cgroup-path /crfuzz/run0 \
    --spawn "$HERE/victim /tmp/crfuzz/target" \
    --spawn "$HERE/racer /tmp/crfuzz/evil /tmp/crfuzz/target" \
    --canonical-log "$W/replay.log" 2>/dev/null \
    | grep -o 'VERDICT:[a-zA-Z=-]*')

echo "3. replay of the projection -> $REPLAY_VERDICT"
sed 's/^/     /' "$W/replay.log"

echo "4. verdicts match: $([ "$DISC_VERDICT" = "$REPLAY_VERDICT" ] && echo YES || echo NO)"
echo "   logs match:     $(cmp -s "$W/disc.log" "$W/replay.log" && echo YES || echo NO)"
