# memfd-ng vs the alternatives — comparison

All ng rows verified against the shipped tree at
the reviewed commit; fork rows against `VHSgunzo__memfd-exec/tree` at
`2decf7d1` (built and run this session); novafacing rows against
`0a15efe` + tracker; memfd-rs rows against `34f0581` + tracker.
Bench/sizes measured 2026-09-10 on x86_64, Linux 6.18, rustc 1.98.

## Scope

| | memfd-ng | novafacing/memfd-exec | VHSgunzo/memfd-exec | lucab/memfd-rs | std Command |
| --- | --- | --- | --- | --- | --- |
| What it is | exec-from-memory crate | exec-from-memory crate (original) | exec-from-memory crate (maintained fork) | memfd *creation* library (no exec API) | filesystem-path exec (control) |
| License | 0BSD | MIT | MIT | Apache-2.0 | MIT/Apache-2.0 |
| Status | new | abandoned (defect reports unanswered) | active | active | — |
| Dependencies | `libc` only | `libc`, `nix` (+ dev: reqwest) | `libc`, `nix`, `bitflags` (+ dev: reqwest) | `libc`, `rustix` | — |

## Execution path

| | memfd-ng | novafacing | VHSgunzo fork | memfd-rs | std |
| --- | --- | --- | --- | --- | --- |
| fd-based exec | `execveat` `AT_EMPTY_PATH` (raw syscall) | glibc `fexecve` | glibc `fexecve` | n/a | n/a |
| `/proc/self/fd` rung | yes (3.17/3.18) | no | no | n/a | n/a |
| disk fallback at all | yes — quiet tmpfs ladder (never writes to stderr), 4 dirs | no | yes — tmp, /dev/shm, ~/.cache | n/a | n/a |
| noexec-mount awareness | yes (`ST_NOEXEC` via raw statfs) | no | no (is_exe can't see mounts) | n/a | std checks at exec |
| fails when procfs absent | yes (fstat + fd rungs, no `/proc` reads) | no (would misreport) | no (is_exe needs `/proc`) | n/a | needs real path |
| ETXTBSY handling | read-only fd swap (measured kernel asymmetry) | n/a | n/a (single write-fd fexecve only works because memfd is exempt) | n/a | n/a |
| fallback cleanup | write phase anonymous (`O_TMPFILE`); name linked only while a rung may need it, unlinked by the parent the moment the exec outcome arrives — no race | n/a | forked helper sleeps 2 ms then `rm -rf` — race vs the execing process | n/a | n/a |
| fallback noise | none, ever | n/a | writes `" Trying tmpfile in ..."` to stderr unconditionally | n/a | none |

## Correctness

| | memfd-ng | novafacing | VHSgunzo fork | memfd-rs | std |
| --- | --- | --- | --- | --- | --- |
| `ExitStatus::success` on exit 0 | **true** (`WIFEXITED`+`WEXITSTATUS`) | **false** (bug #23: `c_int::try_from` infallible) | **false** (same bug, still open) | n/a | true |
| real errno from failed exec | yes (CLOEXEC-pipe protocol) | no — child panics, parent sees exit 101 | no — same panic shape | n/a | yes |
| image fd closed on exec (`MFD_CLOEXEC`) | always | yes | **never** — `is_running_in_qemu()` hardcoded true → flags empty | n/a (creation option) | n/a |
| fd leak into grandchildren | none (measured: child sees fds 0–3) | n/a | **yes** (measured: child sees extra fd) | n/a | none |
| `MFD_EXEC` / `vm.memfd_noexec` awareness | yes, probed once, graceful pre-6.3 | no | no | yes (options + probe) | n/a |
| image sealing | default on (`SHRINK\|GROW\|WRITE`), granular `seals()` incl. `F_SEAL_FUTURE_WRITE`, opt-out | no | no | yes (option, default on) | n/a |
| fallback filename source | library-generated (`uid-pid-128 bit rand`) — no user input in paths | n/a | **program name joined into path** — a `/` in the name writes outside the intended directory | n/a | n/a |
| partial-write safe image write | loop with `WriteZero` guard | single `write` | single `write` | n/a | n/a |
| fallback errno fidelity | real errno per directory | n/a | everything mapped to `PermissionDenied` | n/a | yes |

## API

| | memfd-ng | novafacing | VHSgunzo fork | memfd-rs |
| --- | --- | --- | --- | --- |
| Command-shaped builder | yes | yes | yes | n/a |
| NUL-byte rejection (std discipline) | yes (`InvalidInput`) | no (TODO comment) | no | n/a |
| `prepare()` sealed-image reuse (repeat-spawn fast path) | **yes** | no | no | n/a |
| `memfd_path()` accessor | yes | no | no | yes (`as_path_*`, #69) |
| `Stdio` from `File`/fd | yes (`From<File>`, `From<FileDesc>`, type exported) | Fd variant unreachable | Fd variant unreachable | n/a |
| redacted `Debug` (no image dump) | yes | no (derives) | no (derives) | n/a |
| `exec()` replace-self API | yes | yes | yes | n/a |
| pidfd spawn (`CLONE_PIDFD\|CLONE_VFORK`) | **yes** (5.3+; fork fallback) + `Child::pidfd()` poll-able | no | no | n/a |
| PID-reuse-immune kill/wait | **yes** (`pidfd_send_signal` / `waitid(P_PIDFD)`) | no | no | n/a |
| process groups (`setsid`/`process_group`) | **yes** | no | no | n/a |
| `MFD_HUGETLB` staging (graceful degrade) | **yes** | no | no | yes (creation option, no exec API) |
| granular sealing verified via `F_GET_SEALS` | **yes** (in-suite) | n/a | n/a | no |

## Engineering

| | memfd-ng | novafacing | VHSgunzo fork | memfd-rs |
| --- | --- | --- | --- | --- |
| binary size (minimal driver, stripped release) | **409 KB** | n/m | 465 KB | n/m |
| spawn, cold image (300-iter, static exit-0 fixture) | **~552 µs** | n/m | ~606 µs | n/m |
| spawn, re-used image | **~275 µs** (fork has no equivalent) | n/m | ~580 µs | n/m |
| std control | ~188 µs | | | |
| tests | 80+ tests: std-as-oracle differential suite, pidfd/poll, process groups, granular seals, hugetlb, O_TMPFILE A/B, protocol fuzzer (10 000+ deterministic cases), CLI end-to-end, C FFI from Rust and real C; cc-built real static+dynamic fixtures; 136-byte hand-assembled ELF; feature-gated forced-rung tests | clang-dependent tests | clang-dependent tests (skip without clang) | unit tests |
| build without clang | yes | lib yes / tests no | lib yes / tests no | yes |
| platforms verified | x86_64 gnu (runtime), aarch64 gnu under qemu-user + binfmt (CI), musl compile-checked, FreeBSD 14.2 VM (CI, full suite) | x86_64 | x86_64 | linux/freebsd/android via rustix (upstream CI) |
| FreeBSD | **CI-verified**: full suite in a FreeBSD 14.2 VM (`fexecve` rung included) | no | no | yes (CI) |
| MSRV | 1.64 | old | ≥1.69 (nix 0.31) | 1.85 |
| stderr discipline | never writes | n/a | writes on fallback/disabled paths | n/a |

n/m = not measured this session (abandoned original was not benchmarked; its
maintained fork represents the lineage).

## Verdict

memfd-ng is strictly ahead on correctness (all four measured fork defects
fixed and regression-locked), strictly ahead on environment coverage (three
extraction rungs + noexec-aware, race-free, quiet fallback), faster on every
measured workload (2× on repeat spawns via the prepared path), smaller, and
leaner in dependencies — with the one honest open front being non-Linux
runtime verification.
