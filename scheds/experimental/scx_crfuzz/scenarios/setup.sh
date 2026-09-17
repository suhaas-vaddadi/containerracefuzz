#!/bin/sh
# Lay out the fixture the victim and racer operate on. Run before each run:
# the racer consumes the symlink by renaming it, so the state is single-use.
set -eu
DIR="${1:-/tmp/crfuzz}"
rm -rf "$DIR"
mkdir -p "$DIR"
printf 'BENIGN\n' > "$DIR/target"   # what the victim expects to read
printf 'SECRET\n' > "$DIR/secret"   # what it must never read
ln -s "$DIR/secret" "$DIR/evil"     # the racer renames this over target
