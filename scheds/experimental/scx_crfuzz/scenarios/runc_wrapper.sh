#!/bin/sh
# A stand-in for `runc`, for use as `ctr run --runc-binary <this>`.
#
# containerd never executes a container itself. It delegates:
#
#     containerd (daemon)                  <- untouched
#       └─ containerd-shim-runc-v2         <- untouched
#            └─ runc create/start/delete   <- exec'd by path; this replaces it
#
# So nothing about containerd or the shim changes. Only the leaf moves, the
# same way `CC=my-wrapper` intercepts a compiler without touching the build
# system.
#
# The shim makes four separate invocations per container, measured:
#
#     runc --root R --log L --log-format json create --bundle B --pid-file P ID
#     runc --root R --log L --log-format json start ID
#     runc --root R --log L --log-format json delete ID
#     runc --root R --log L --log-format json delete --force ID
#
# Only `create` is instrumented. It is the invocation that does the container
# setup -- of the 279 structural syscalls in a full `runc run`, the mounts,
# symlinkats and the bulk of the readlinkats happen here. `start` merely signals
# an init that `create` already built, and the deletes are teardown. Holding
# those would add latency and interleavings with nothing behind them.
#
# Everything else is exec'd straight through, so the shim sees ordinary runc.
set -eu

RUNC="${CRFUZZ_RUNC:-/usr/bin/runc}"
BIN="${CRFUZZ_BIN:-/workspace/scx/target-linux/debug/scx_crfuzz}"
CONFIG="${CRFUZZ_CONFIG:-$(cd "$(dirname "$0")" && pwd)/runc.json}"
OUTDIR="${CRFUZZ_OUTDIR:-/tmp/crfuzz-runc}"
CGROUP_ROOT="${CRFUZZ_CGROUP:-/crfuzz}"

# Find the subcommand: the first argument that is not a global flag and not a
# global flag's value. Scanning for the literal string "create" would misfire on
# `--bundle /var/lib/.../create`.
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

# The bundle, so the engine can check the container's own seccomp profile before
# running. runc passes it as `--bundle <dir>` on create.
bundle=""
take=0
for a in "$@"; do
    if [ "$take" = 1 ]; then bundle="$a"; break; fi
    case "$a" in --bundle) take=1 ;; --bundle=*) bundle="${a#--bundle=}"; break ;; esac
done

# The container id is the last argument for every invocation the shim makes.
# Used only to keep concurrent containers in separate cgroups and log files.
id=""
for a in "$@"; do id="$a"; done
case "$id" in -*|"") id="unknown" ;; esac

if [ "$sub" != "create" ]; then
    exec "$RUNC" "$@"
fi

mkdir -p "$OUTDIR"

# Captured before `set --` rewrites the positional parameters below.
ARGS="$*"

# --exit-with-child is what makes this safe to put in the shim's path: the shim
# reads the status to decide whether the container was created, so it has to be
# runc's answer, not the engine's verdict on the scheduling run.
# A profile that denies a syscall a checkpoint sits on would erase that
# checkpoint silently, so let the engine refuse rather than report a run that
# quietly explored less than it claims.
set -- \
    --config "$CONFIG" \
    --cgroup-path "$CGROUP_ROOT/$id" \
    --freezer \
    --exit-with-child \
    --canonical-log "$OUTDIR/$id.log" \
    --debug-log "$OUTDIR/$id.debug" \
    --spawn "$RUNC $ARGS"

[ -n "$bundle" ] && set -- "$@" --oci-bundle "$bundle"

exec "$BIN" "$@"
