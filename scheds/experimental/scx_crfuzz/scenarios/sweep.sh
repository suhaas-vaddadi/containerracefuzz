#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# The sweep: a dry run lists runc's windows, then one run attacks each.
#
#   ./sweep.sh [bundle] [outdir]
#
# A dry-run finding is a false positive (nothing was attacked) and is printed
# as such. Each run's full report lands in <outdir>/<window>.report; a window
# with a finding is the reproducer: `./attack_run.sh <window> <bundle>`. A
# window the run never reached, or whose key moved, is flagged instead.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
BUNDLE="${1:-${CRFUZZ_BUNDLE:-/tmp/bundle}}"
OUT="${2:-/tmp/crfuzz-sweep}"
mkdir -p "$OUT"

"$HERE/attack_run.sh" "" "$BUNDLE" >"$OUT/dry.report"
grep '^finding' "$OUT/dry.report" | sed 's/^/false positive (dry run): /'

# The path a report lists for window $w.
path() { awk -F'\t' -v w="$w" '$1 == "window" && $2 == w { print $3 }' "$1"; }

for w in $(awk -F'\t' '$1 == "window" { print $2 }' "$OUT/dry.report"); do
    "$HERE/attack_run.sh" "$w" "$BUNDLE" >"$OUT/$w.report"
    grep '^finding' "$OUT/$w.report" | sed "s/^/$w: /"
    # A key names the victim's nth hit of a checkpoint; if two thread groups
    # hit it concurrently the numbering can shift, and this run attacked a
    # different syscall than the dry run listed under the same key.
    if grep -q '^unreached' "$OUT/$w.report"; then
        echo "$w: never reached, nothing attacked"
    elif [ "$(path "$OUT/dry.report")" != "$(path "$OUT/$w.report")" ]; then
        echo "$w: key moved (dry run $(path "$OUT/dry.report"), this run $(path "$OUT/$w.report"))"
    fi
done
