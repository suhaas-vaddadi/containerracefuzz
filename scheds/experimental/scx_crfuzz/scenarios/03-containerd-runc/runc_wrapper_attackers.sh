#!/bin/sh
# A stand-in for `runc`, for use as `ctr run --runc-binary <this>`, that also
# launches two multithreaded attackers alongside the instrumented `runc create`.
#
# This is `runc_wrapper.sh` plus a second kind of actor. The shim protocol is
# identical (see runc_wrapper.sh for the full explanation):
#
#     containerd (daemon)
#       └─ containerd-shim-runc-v2
#            └─ runc create/start/delete   <- exec'd by path; this replaces it
#
# Only `create` is instrumented. Unlike runc_wrapper.sh, this wrapper spawns the
# attacker role too, so the engine runs three thread groups at once: `runc` and
# two `mt_attacker` instances, the latter a pool. Because the shim reads the
# exit status to decide whether the container was created, the engine must still
# answer for `runc` specifically -- hence `--exit-with-spawn 0` (runc is the
# first `--spawn`).
#
# Requires scx_crfuzz_gated running and root. Under `pos` the gate holds one
# thread at a time; the engine puts each run in its own cgroup.
set -eu

RUNC="${CRFUZZ_RUNC:-/usr/local/bin/runc}"
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
HERE=$(cd "$(dirname "$0")" && pwd)
CONFIG="${CRFUZZ_CONFIG:-$HERE/containerd_two_attackers.json}"
OUTDIR="${CRFUZZ_OUTDIR:-/tmp/crfuzz-runc}"
ATTACKER_BIN="${CRFUZZ_ATTACKER_BIN:-$HERE/mt_attacker}"
ATTACKER_THREADS="${CRFUZZ_ATTACKER_THREADS:-3}"
ATTACKER_SECONDS="${CRFUZZ_ATTACKER_SECONDS:-3}"

# Find the subcommand: the first argument that is not a global flag and not a
# global flag's value.
sub=""
skip=0
for a in "$@"; do
    if [ "$skip" = 1 ]; then skip=0; continue; fi
    case "$a" in
        --root|--log|--log-format|--criu|--rootless)  skip=1 ;;
        -*)                                            ;;
        *)  sub="$a"; break ;;
    esac
done

bundle=""
take=0
for a in "$@"; do
    if [ "$take" = 1 ]; then bundle="$a"; break; fi
    case "$a" in --bundle) take=1 ;; --bundle=*) bundle="${a#--bundle=}"; break ;; esac
done

id=""
for a in "$@"; do id="$a"; done
case "$id" in -*|"") id="unknown" ;; esac

if [ "$sub" != "create" ]; then
    exec "$RUNC" "$@"
fi

mkdir -p "$OUTDIR"
ARGS="$*"

# A private scratch tree for the attackers. They cannot reach into runc's mount
# namespace, so this is deliberately self-contained: the point here is the
# *scheduling* of two multithreaded thread groups against runc, not the paths
# they attack (that is the mutator's job, out of scope).
SCRATCH="$OUTDIR/atk-$id"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

# runc is spawn 0, so `--exit-with-spawn 0` answers the shim for exactly the
# process it asked about. The two attackers are pool members `attacker#0` and
# `attacker#1`.
set -- \
    --config "$CONFIG" \
    --out "$OUTDIR/$id" \
    --exit-with-spawn 0 \
    --spawn "$RUNC $ARGS" \
    --spawn "$ATTACKER_BIN $SCRATCH $ATTACKER_THREADS $ATTACKER_SECONDS" \
    --spawn "$ATTACKER_BIN $SCRATCH $ATTACKER_THREADS $ATTACKER_SECONDS"

[ -n "$bundle" ] && set -- "$@" --oci-bundle "$bundle"

# Keep the engine's own stderr next to its logs: the shim does not forward it,
# so a startup failure would otherwise be invisible.
exec "$BIN" "$@" 2>"$OUTDIR/$id.engine.err"
