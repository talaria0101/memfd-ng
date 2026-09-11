#!/bin/sh
# Full verification: unit + integration + feature-gated ladder tests, CLI,
# FFI (Rust + a real C driver), doctests, clippy, and the release profile.
set -e
cd "$(dirname "$0")/.."

echo "== clippy (workspace) =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== tests (default features) =="
cargo test

echo "== tests (test-hooks: forced exec-ladder rungs) =="
cargo test --features test-hooks

echo "== tests (cli feature) =="
cargo test --features cli

echo "== FFI tests (Rust side) =="
cargo test -p memfd-ng-ffi

echo "== FFI smoke (real C driver against the cdylib) =="
./scripts/ffi-smoke.sh

echo "== release build =="
cargo build --release --features cli

echo "== bench (spawn latency) =="
cargo bench

echo "all green"
