#!/bin/sh
# Full verification: unit + integration + feature-gated ladder tests,
# doctests, clippy, and the release profile.
set -e
cd "$(dirname "$0")/.."

echo "== clippy =="
cargo clippy --all-targets -- -D warnings

echo "== tests (default features) =="
cargo test

echo "== tests (test-hooks: forced exec-ladder rungs) =="
cargo test --features test-hooks

echo "== release build =="
cargo build --release

echo "== bench (spawn latency) =="
cargo bench

echo "all green"
