# Roadmap

Feature requests and future work, with priorities and dispositions. An item
lands here only with a reason; refused items keep theirs so no future session
re-derives the decision.

## Landed

| # | request | disposition |
| --- | --- | --- |
| 1 | **pidfd spawn**: `clone3(CLONE_PIDFD\|CLONE_VFORK)`, plain `fork()` fallback | **landed** — `sys::clone3_vfork_pidfd`; parent suspended until the child execs (no CLONE_VM, so the child keeps a private COW address space — kernel behavior verified live: a child's pre-exec writes never reach the parent); cached ENOSYS/EINVAL probe falls back to `fork()`. PID-reuse-immune `kill`/`wait`/`try_wait` via `pidfd_send_signal`/`waitid(P_PIDFD)` with classic fallbacks. Evidence: `tests/pidfd.rs` (8 tests), REVIEW-8 |
| 2 | **`Child::pidfd()` + poll-able child** | **landed** — `Child::pidfd()` returns `BorrowedFd`; `POLLIN`-on-exit proven by `pidfd_polls_before_and_after_exit`; fd-leak sweep over 30 spawn cycles |
| 3 | **O_TMPFILE staging** for the fallback ladder | **landed** — write phase anonymous (`O_TMPFILE` on supporting filesystems; verified live on tmpfs); a name is linked only for rungs that need one — unprivileged `linkat` via `/proc/self/fd` with procfs, CAP_DAC_READ_SEARCH `linkat(fd,"",AT_EMPTY_PATH)` dance without; parent unlinks as soon as the exec outcome arrives. `MEMFD_NG_TEST_NO_OTMPFILE` / `MEMFD_NG_TEST_NO_NAMED_STAGE` hooks A/B-lock both mechanisms. Evidence: `tests/ladder.rs` (7 tests), REVIEW-9 |
| 4 | **Granular sealing API** — `seals()` builder + `F_SEAL_FUTURE_WRITE` | **landed** — `SealFlags` (`SHRINK/GROW/WRITE/FUTURE_WRITE`, `BitOr`/`Not`), default stays `SHRINK\|GROW\|WRITE`; every claim read back from the kernel via `F_GET_SEALS`. Quirk documented: F_GET_SEALS on a memfd created *without* MFD_ALLOW_SEALING returns `1` (not the documented error) on 6.18. Evidence: `tests/seals.rs` (7 tests), REVIEW-8 |
| 5 | **Process-group options** — `setsid()`/`setpgid()` builder knobs | **landed** — applied in the forked child before exec; failures surface as real errnos (the kernel refuses `setpgid` on a session leader: composing both fails with `EPERM`, locked by test). std `process_group(0)` parity proven against the oracle. Evidence: `tests/groups.rs` (7 tests), REVIEW-8 |
| 6 | **qemu-user CI job** | **landed** — `.github/workflows/qemu-user.yml` runs the full suite under `qemu-aarch64` + binfmt on GitHub runners. Local (binfmt-less sandbox) verification went as far as physics allows: full aarch64 cross-build, guest fixtures built via `MEMFD_NG_TEST_CC`, ladder traced live with `qemu -strace`; the remaining leg requires binfmt because a binfmt-less kernel answers `ENOEXEC` for every guest-arch exec — qemu 7.2 has no self-exec fallback and `QEMU_EXECVE` is absent. Two real defects found and fixed by this work: cross-process fixture race, and rung-2 ENOEXEC misclassified as an image verdict (see REVIEW-9). Also: rung-1 ENOSYS (qemu does not implement `execveat`) was already correct |
| 7 | **FreeBSD runtime verification** | **landed** — `.github/workflows/freebsd.yml` runs the full suite in a FreeBSD 14.2 VM (the `fexecve` rung was compile-reviewed only before). Local: rustup cannot download the freebsd std in this sandbox, so compile-check rides on CI alongside the runtime pass |
| 8 | **Pipe-protocol fuzzing** | **landed** — `tests/fuzz_pipe.rs`: deterministic structure-aware fuzzer over real OS pipes; exact round-trips (errno sweep incl. `i32::MIN/MAX`; PATH boundary lengths 0…65535), truncation matrix, 10 000 junk cases + 1000 bitflip cases (any outcome except panic/hang/wrong-kind is legal), the real NamedPath→Failure sequence, and byte-by-byte reassembly. Protocol exposed via `memfd_ng::protocol` under `test-hooks`. REVIEW-9 |
| 9 | **`MFD_HUGETLB` option** | **landed** — `.hugetlb(true)` prefers hugetlbfs; everything degrades to an ordinary memfd (alignment enforced by zero-padding to `fstatfs().f_bsize`; verified live: create OK, aligned write OK, unaligned write EINVAL, and — with zero preallocated huge pages — write ENOMEM ⇒ degrade). Engagement proven by fstatfs magic, never assumed. Kernels refuse to seal hugetlb memfds (EPERM, observed); `is_sealed()` reports honestly. Evidence: `tests/hugetlb.rs` (4 tests), REVIEW-8 |
| 10 | **`memfd-run` CLI** | **landed** — `[[bin]]` behind the `cli` feature; `--name`/`--argv0`/`--`, exit-code and 128+signal propagation, 126 on failure with the kernel errno named. Evidence: `tests/cli.rs` (5 tests), REVIEW-10 |
| 11 | **C FFI layer** | **landed** — workspace member `memfd-ng-ffi` (`cdylib`+`rlib`): `memfd_ng_spawn/pid/kill/wait/free`, negated-errno errors, panics caught to `-EIO`, C `execve`-style argv/envp semantics, hand-written `memfd-ng.h`, ABI version 1. Verified from Rust (`ffi/tests/ffi.rs`, 6 tests) AND from real C (`ffi/smoke/main.c` via `scripts/ffi-smoke.sh`). REVIEW-10 |

## Not planned

| request | reason |
| --- | --- |
| `no_std` support | the crate is defined by `fork`/`exec` process machinery and std error/io types; a `no_std` core would be a different, thinner crate with no shared code |
| WASI target | no `memfd_create`/`fexecve` substrate; the concept does not transfer |
| async/tokio child | an adapter crate wrapping this one can add it; embedding a runtime dependency here would tax every user for one feature |
| raw `envp` pointer API | unsafe surface with no demonstrated caller; the BTreeMap capture covers the real cases |
| upstreaming anything, anywhere | standing repo rule; fixes land here, now, in this tree |
