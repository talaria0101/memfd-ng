#!/bin/sh
# Build the memfd-ng-ffi cdylib, link a real C driver against it, run it.
# Proves the exported ABI is consumable from actual C, not just from Rust.
set -e
cd "$(dirname "$0")/.."

command -v cc >/dev/null || { echo "cc not found; skipping FFI smoke"; exit 0; }

echo "== building cdylib =="
cargo build -p memfd-ng-ffi

echo "== compiling C driver =="
LIBDIR="target/debug"
cc -Wall -Wextra -o "$LIBDIR/ffi-smoke" \
    ffi/smoke/main.c \
    -I ffi/include \
    -L "$LIBDIR" -l memfd_ng_ffi

echo "== running (LD_LIBRARY_PATH=$LIBDIR) =="
LD_LIBRARY_PATH="$LIBDIR" "$LIBDIR/ffi-smoke"
