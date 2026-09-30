#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# The swapping attacker. For each window it is handed, it substitutes an
# attacker-controlled object for the path the victim's use-syscall resolved --
# with the SAME type as the original:
#
#   directory     -> an attacker directory   (Family B: directory exchange)
#   regular file  -> an attacker file        (Family D: content substitution)
#   symlink       -> an attacker symlink     (Family A: leaf substitution)
#
# Type-preserving is the whole point. Replacing a directory with a file makes
# the victim's `open(path, O_DIRECTORY)` fail ENOTDIR -- a crash that proves
# nothing. Replacing it with another directory is an exchange the victim can
# follow, and the race is then visible only if the oracle notices the object
# changed, which is exactly the case worth testing.
#
# The victim is frozen at the use-syscall's entry for the whole window, so the
# verbs need not be atomic to win; only the state the victim wakes into matters.
#
# Inputs, all set by the engine except the payloads:
#   CRFUZZ_CHECKPOINT     the use syscall this window brackets
#   CRFUZZ_TARGET_PATH    the path that syscall resolved (also argv $1)
#   CRFUZZ_ATTACK_ROOT    the only tree the attacker may modify. Required: only
#                         paths strictly beneath it are eligible.
#   CRFUZZ_EVIL_DIR       what a directory target becomes; default an empty
#                         marker dir. Seed it with a real tree (a rootfs copy)
#                         to see whether the victim follows it.
#   CRFUZZ_EVIL_FILE      what a regular-file target becomes; default a marker.
#   CRFUZZ_EVIL_TARGET    what a symlink target becomes.
#   CRFUZZ_ATTACK_LOG     where each window + verb outcome is appended.
set -u

LOG="${CRFUZZ_ATTACK_LOG:-/tmp/crfuzz-attack.log}"
TARGET="${CRFUZZ_TARGET_PATH:-${1:-}}"
CHECKPOINT="${CRFUZZ_CHECKPOINT:-unknown}"
EVIL_DIR="${CRFUZZ_EVIL_DIR:-/tmp/crfuzz-evil-dir}"
EVIL_FILE="${CRFUZZ_EVIL_FILE:-/tmp/crfuzz-evil-file}"
EVIL_LINK="${CRFUZZ_EVIL_TARGET:-/tmp/crfuzz-evil-target}"

log() { printf '%s %s %s\n' "$CHECKPOINT" "${TARGET:--}" "$1" >>"$LOG"; }

# The default payloads, made once. A directory payload defaults to empty; a
# non-empty one (e.g. a copied rootfs) must be supplied by the caller.
[ -d "$EVIL_DIR" ] || mkdir -p -- "$EVIL_DIR" 2>/dev/null
[ -e "$EVIL_FILE" ] || printf 'CRFUZZ-EVIL\n' >"$EVIL_FILE" 2>/dev/null

if [ -z "$TARGET" ]; then
    log "verb=none result=no-path"
    exit 0
fi

# Scope the attack to an explicit root. Without CRFUZZ_ATTACK_ROOT the attacker
# refuses to act: swapping arbitrary system paths is both meaningless and
# destructive -- an earlier version handed `/tmp` and bind-mounted over the
# whole scratch tree.
ROOT="${CRFUZZ_ATTACK_ROOT:-}"
ROOT="${ROOT%/}"
if [ -z "$ROOT" ]; then
    log "verb=none result=no-root"
    exit 0
fi
case "$TARGET" in
    "$ROOT"/*) ;;
    *)
        log "verb=none result=outside-root"
        exit 0
        ;;
esac

# The type to preserve. Check the symlink first: -d/-f follow it.
if [ -L "$TARGET" ]; then
    KIND=symlink
elif [ -d "$TARGET" ]; then
    KIND=dir
elif [ -e "$TARGET" ]; then
    KIND=file
else
    # Nothing is there to replace; a create is not a substitution.
    log "verb=none kind=missing result=no-target"
    exit 0
fi

DIR=$(dirname -- "$TARGET")
SCRATCH="$DIR/.crfuzz-evil.$$"
BACKUP="$DIR/.crfuzz-orig.$$"

# Build an attacker object of the target's type at $SCRATCH.
plant() {
    rm -rf -- "$SCRATCH" 2>/dev/null
    case "$KIND" in
        dir)
            mkdir -- "$SCRATCH" 2>/dev/null || return 1
            if [ -n "$(ls -A "$EVIL_DIR" 2>/dev/null)" ]; then
                cp -a -- "$EVIL_DIR/." "$SCRATCH/" 2>/dev/null || return 1
            fi
            ;;
        symlink)
            ln -s -- "$EVIL_LINK" "$SCRATCH" 2>/dev/null || return 1
            ;;
        *)
            cp -- "$EVIL_FILE" "$SCRATCH" 2>/dev/null || return 1
            ;;
    esac
    return 0
}

# Exchange the target with the planted object, preserving the original at
# $BACKUP. Two renames, not renameat2(RENAME_EXCHANGE): the victim is frozen
# for the whole window, so the intermediate state is never observed, and this
# needs no compiled helper. $SCRATCH and $BACKUP live in the target's own
# directory, so both objects stay on one filesystem (no EXDEV) and a directory
# target moves as a whole. The original is kept so a later window still has a
# sane tree to act on.
exchange() {
    rm -rf -- "$SCRATCH" "$BACKUP" 2>/dev/null
    plant || return 1
    mv -f -- "$TARGET" "$BACKUP" 2>/dev/null || return 1
    if mv -f -- "$SCRATCH" "$TARGET" 2>/dev/null; then
        return 0
    fi
    mv -f -- "$BACKUP" "$TARGET" 2>/dev/null
    return 1
}

# A real absence window: remove the target, then move the planted object in.
# Non-directories only -- never `rm -rf` a directory.
unlink_recreate() {
    [ "$KIND" = dir ] && return 1
    rm -rf -- "$SCRATCH" 2>/dev/null
    plant || return 1
    rm -f -- "$TARGET" 2>/dev/null || return 1
    mv -f -- "$SCRATCH" "$TARGET" 2>/dev/null || return 1
    return 0
}

# Ancestor redirection (Family B): bind-mount the attacker directory over a
# directory target, so everything the victim resolves beneath it lands in our
# tree instead of the intended one.
bind_mount() {
    [ "$KIND" = dir ] || return 1
    [ -d "$EVIL_DIR" ] || return 1
    mount --bind -- "$EVIL_DIR" "$TARGET" 2>/dev/null || return 1
}

# First verb that leaves the object in place wins. A verb that cannot act
# (EPERM, EROFS, EXDEV, a busy mount) is an ACTION-FAILED setup result, not a
# finding -- exactly how the engine treats a non-zero attacker exit. The victim
# is released regardless.
if exchange; then
    log "verb=exchange kind=$KIND result=ok"
elif unlink_recreate; then
    log "verb=unlink-recreate kind=$KIND result=ok"
elif bind_mount; then
    log "verb=bind-mount kind=$KIND result=ok"
else
    log "verb=all kind=$KIND result=action-failed"
fi
exit 0
