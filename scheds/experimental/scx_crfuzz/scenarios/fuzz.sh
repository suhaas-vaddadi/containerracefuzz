#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# The fuzzer: a dry run lists the victim's windows, a reachability pass finds
# the ones `attacker.sh` can actually touch, then each reachable window
# is run once per seed. The attacker is a seeded sampler over the mutation
# grammar, so (scenario, window, seed) is a reproducer and the plan log records
# exactly what each run tried.
#
#   ./fuzz.sh [bundle] [outdir]
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
BUNDLE="${1:-${CRFUZZ_BUNDLE:-/tmp/bundle}}"
OUT="${2:-/tmp/crfuzz-fuzz}"
SEEDS="${CRFUZZ_FUZZ_SEEDS:-16}"
CONFIG="${CRFUZZ_CONFIG:-$HERE/runc_attack.json}"
export CRFUZZ_CONFIG
mkdir -p "$OUT"

run() { # $1=window ("" dry)  $2=seed  $3=tag
    CRFUZZ_ATTACK_SEED="$2" \
    CRFUZZ_ATTACK_LOG="$OUT/attack.$3" \
    CRFUZZ_ATTACK_PLAN_LOG="$OUT/plan.$3" \
        "$HERE/attack_run.sh" "$1" "$BUNDLE" >"$OUT/report.$3" 2>"$OUT/engine.$3"
}

tag_of() { printf '%s' "$1" | tr '#/' '__'; }

# 1. dry run lists the windows.
run "" 0 dry
WINDOWS=$(awk -F'\t' '$1 == "window" { print $2 }' "$OUT/report.dry" 2>/dev/null)
echo "windows: $(printf '%s\n' $WINDOWS | grep -c .)"

# 2. reachability: a window is live only if the attacker found an in-scope path
#    (a hit or a failed primitive), not `unreachable`.
reach=""
for w in $WINDOWS; do
    t="probe-$(tag_of "$w")"
    run "$w" "probe-$w" "$t"
    if awk -F'\t' '$3 == "hit" || $3 == "fail" { f=1 } END { exit !f }' "$OUT/plan.$t" 2>/dev/null; then
        reach="$reach $w"
        echo "reachable: $w"
    fi
done
echo "reachable windows:$(printf ' %s' $reach)"

# 3. fuzz each reachable window across seeds.
for w in $reach; do
    for s in $(seq 1 "$SEEDS"); do
        id="$(tag_of "$w").s$s"
        run "$w" "$s-$w" "$id"
        if grep -q '^finding' "$OUT/report.$id" 2>/dev/null; then
            echo "FINDING window=$w seed=$s"
            grep '^finding' "$OUT/report.$id" | sed 's/^/  /'
            printf '  plan: '; tail -n 1 "$OUT/plan.$id"
        fi
    done
done

echo "=== findings over all runs ==="
grep -h '^finding' "$OUT"/report.* 2>/dev/null | sort | uniq -c
echo "=== plan outcomes (reachable runs) ==="
cat "$OUT"/plan.* 2>/dev/null | awk -F'\t' '{print $3"\t"$6"\t"$9}' | sort | uniq -c | sort -rn | head -30
