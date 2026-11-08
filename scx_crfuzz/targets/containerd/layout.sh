#!/bin/sh
# Reset between runs: daemon state and the rootfs the mutator rearranged, in
# place (mount points). `cp -a orig/.` restores the rootfs directory's own mode too.
set -eu
find "$CRFUZZ_DIR/run" "$CRFUZZ_DIR/rootfs" -mindepth 1 -delete
cp -a "$CRFUZZ_DIR/rootfs.orig/." "$CRFUZZ_DIR/rootfs/"
