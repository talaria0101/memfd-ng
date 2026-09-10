# Review 1 — API surface and std parity

Pass: every public item re-read against the `std::process::Command` contract
and the documented drop-in API contract. Build+tests
green after fixes.

## Findings and dispositions

| # | finding | disposition |
| --- | --- | --- |
| R1-1 | `#[derive(Debug)]` on `MemFdExecutable` prints the entire payload — a prepared 9 MiB image lands in logs verbatim | fixed: manual `Debug` redacts `code` to `[N bytes]`; regression-proofed by keeping the struct non-derive |
| R1-2 | non-UTF-8 program name became `""` via `to_str().unwrap_or_default()` — silent loss, empty memfd name | fixed: `to_string_lossy()` preserves information; lossy text is what `/proc` consumers want anyway |
| R1-3 | `unsafe impl Send/Sync for Argv` redundant — `Vec<CString>` is already `Send + Sync` | removed |
| R1-4 | README did not state the NUL-rejection discipline | fixed: properties section now names it |
| R1-5 | `set_program` updated `argv[0]`/`args[0]` but left `program` stale (incoherent with `get_program_cstr`) | fixed in code during test bring-up: `program` now tracks; covered by `argv0_is_settable` |
| R1-6 | `ExitStatus::exit_ok` was the known always-Err defect in the inherited API | fixed: `success()` is `WIFEXITED && WEXITSTATUS == 0`, `exit_ok` produces a descriptive error; covered by `parity_success_is_std_success` |
| R1-7 | `Stdio::Null` opened `/dev/null` read-only (`File::open` ignoring the configured options) and dropped the handle while stealing its fd | fixed in code during test bring-up: `OpenOptions::open` + `into_raw_fd`; covered by `null_stdio_discards` |
| R1-8 | `Child` gained `named_fallback` cleanup — a `spawn()` caller who drops the `Child` without `wait()` leaks one 0700 file in the tmp dir (no-procfs corner only) | accepted, documented here: identical to leaking a zombie (the child PID), and only reachable with procfs absent; all wait paths (`wait`, `try_wait`-completed, `wait_with_output`, failure branches) unlink |

## Verdict

Surface is a drop-in for the documented API plus the documented extensions
(`prepare`/`is_prepared`/`is_sealed`/`sealed`/`memfd_path`, `From<File>` for
`Stdio`). Every deviation from the inherited behavior is a defect fix listed
above. Re-test: `cargo test` 32/32 + 5 doctests, clippy clean.
