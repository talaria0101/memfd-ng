# Review 10 — FFI and CLI surface audit

Pass: the FFI ABI re-read boundary-by-boundary (null handling, ownership,
panics, errno mapping), the C header diffed against the implementation, the
CLI re-read for exit-code semantics. Verified from Rust (`ffi/tests/ffi.rs`,
6 tests) and from a real C driver (`scripts/ffi-smoke.sh`).

## Findings and dispositions

| # | finding | disposition |
| --- | --- | --- |
| R10-1 | panic containment: every exported call that can touch Rust panics (spawn, kill, wait) is wrapped in `catch_unwind(AssertUnwindSafe(..))` mapping to `-EIO` | verified by reading; `memfd_ng_pid` cannot panic (field read only); `memfd_ng_free`/`memfd_ng_abi_version`/`memfd_ng_version` are panic-free by construction |
| R10-2 | ownership contract spelled out for `code` (must outlive the child — the memfd path stages immediately but the no-memfd ladder re-reads the buffer), `argv`/`envp`/`name` (copied before spawn returns), and handle release (exactly once) | documented in `ffi/src/lib.rs` header, the per-function docs, and `ffi/include/memfd-ng.h`; the header and the implementation were linked against each other by the C smoke build (`cc -Wall -Wextra` over `ffi/smoke/main.c` with `-I ffi/include -lmemfd_ng_ffi`) — any signature drift fails the build |
| R10-3 | C `execve` semantics: non-NULL `envp` is a *complete* environment, not an overlay | implemented as `env_clear()` + explicit sets (C callers expect execve semantics); NULL `envp` inherits, matching C convention; `argv == NULL` means `[name]`; all locked by `null_argv_and_envp_use_defaults` |
| R10-4 | C strings can carry arbitrary non-NUL bytes | arguments flow through `OsStr::from_bytes` — lossless, no UTF-8 coercion; empty env keys skipped (C forbids them anyway) |
| R10-5 | error reporting: negated errno, `0` = success | verified live from C: corrupt image surfaces `-ENOEXEC` through `err_out` (`smoke: corrupt image surfaced ENOEXEC`); Rust-side `errors_are_negated_errnos` asserts `-8` |
| R10-6 | wait-status crossing the boundary is the raw `wait(2)` encoding | verified from C: `WIFEXITED`/`WEXITSTATUS` on the C side read exit 5 correctly; from Rust: `7 << 8` and raw `9` for SIGKILL |
| R10-7 | double release is UB (like `free`) — cannot be defended against without handle validation machinery | accepted and documented; `free_without_wait_releases_the_handle` proves single release from both `wait` and `free` paths leaves the process healthy |
| R10-8 | CLI exit-code contract | verified: child exit code propagates (`exit 42` → 42), signal death maps to 128+signal (`crash` stub mode, SIGSEGV → 139), unreadable file → 126 with a message on the *CLI's own* stderr (the library stays silent), corrupt image → 126 with `os error 8` in the message |
| R10-9 | `--argv0` must reach `$0` | verified end-to-end through `sh -c 'echo $0'` (`argv0_and_name_flags_work`) |
| R10-10 | `usage()` returns `!` and `unwrap_or_else(|| usage())` closures — re-checked after a compile error forced the closure form | fine; the `--name`/`--argv0` missing-value path still exits 2 with the usage text |
| R10-11 | workspace wiring: the FFI crate is a workspace member sharing one lock/target dir | verified: `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` both cover it; `required-features = ["cli"]` keeps the binary out of default builds |

## Verdict

The boundary is total: no panic escapes, every failure is an errno, the C
header and the implementation are compile-locked together, and the CLI's
observable contract (exit codes, signal mapping, silence rules) is test-locked.
Re-test: `ffi-smoke.sh` all-ok; FFI 6/6; CLI 5/5.
