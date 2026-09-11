# memfd-ng

Execute ELF binaries straight from memory. Put the bytes of a Linux
executable in a `&[u8]` — `include_bytes!()`, a socket, a compiler — and
`MemFdExecutable` runs them straight from an anonymous in-memory file,
through an interface shaped like `std::process::Command`.

```rust
use memfd_ng::{MemFdExecutable, Stdio};

let code = std::fs::read("/bin/sh").unwrap();
let out = MemFdExecutable::new("sh", &code)
    .arg("-c")
    .arg("echo in-memory; exit 7")
    .stdout(Stdio::piped())
    .output()
    .unwrap();

assert_eq!(out.stdout, b"in-memory\n");
assert_eq!(out.status.code(), Some(7));
```

## How a spawn executes

```
image bytes
     │
     ▼
memfd_create(MFD_CLOEXEC │ MFD_EXEC? │ MFD_ALLOW_SEALING?)   ← probed once per process
     │ write + seal (configurable seals, default SHRINK|GROW|WRITE)
     ▼
spawn: clone3(CLONE_VFORK │ CLONE_PIDFD) → pidfd      (kernel 5.3+; plain fork() fallback)
     ▼
rung 1: execveat(fd, "", AT_EMPTY_PATH)      Linux 3.19+, no procfs needed
rung 2: execve("/proc/self/fd/N")            3.17/3.18, procfs only
rung 3: tmpfs ladder → named exec            emulators, ancient kernels
```

Every rung after a refused `execveat` runs without writing anything to
stderr (captured output is never polluted) and stays allocation-free in the
forked child (stack buffers and raw syscalls only — argv/envp are built
before the fork, so the child never depends on a malloc lock another thread
may hold).

The tmpfs ladder stages each candidate on an executable filesystem —
`XDG_RUNTIME_DIR`, `TMPDIR`/`/tmp`, `/dev/shm`, `~/.cache` — rejecting
`ST_NOEXEC` mounts outright via a raw `statfs`. The write phase prefers
`O_TMPFILE`: an anonymous inode with no name to leak if anything crashes
mid-write. A name is linked only so a rung can exec it (and for emulators,
which can only exec a path), and the parent unlinks it the moment the exec
outcome reaches it. Staged files are made read-only before exec (the
kernel's `ETXTBSY` rule exempts memfds but not regular files). No threads,
no helper processes, no sleeps, no races.

## Properties

- **std Command discipline.** Arguments or environment values containing NUL
  bytes are rejected with `InvalidInput`, exactly as std does; `Debug` never
  dumps the image. An unmodified command inherits the parent environment
  wholesale, exactly like std.
- **Errno fidelity.** A failed exec surfaces from `spawn()`/`status()`/
  `output()` as a real `std::io::Error` with the kernel's own errno
  (`ENOEXEC`, `EACCES`, …). The child reports through the CLOEXEC pipe; it
  never panics and never prints.
- **Quiet by construction.** The library writes nothing to stderr — captured
  output is never polluted.
- **No fd leaks.** The image memfd carries `MFD_CLOEXEC`; children see
  exactly the std stdio set; pidfds are closed with the `Child`.
- **Sealed images.** Written images are sealed against shrink, grow and
  write by default (`SealFlags::full()`), so nothing can swap code between
  write and exec. `seals()` picks exact bits (including
  `F_SEAL_FUTURE_WRITE`); `sealed(false)` opts out entirely. Note: kernels
  refuse to seal hugetlb memfds — a hugetlb image runs unsealed.
- **pidfd spawn, poll-able children.** Spawns use
  `clone3(CLONE_VFORK | CLONE_PIDFD)` on kernel 5.3+ (plain `fork()`
  otherwise). The parent is suspended until the child execs — the child runs
  immediately instead of racing the scheduler — while its copy-on-write
  memory keeps the child's pre-exec activity from ever touching the parent.
  `Child::pidfd()` hands out a pidfd that stays valid across PID reuse and
  fires `POLLIN` on exit: event loops can await a child without SIGCHLD.
  `kill`/`wait`/`try_wait` go through `pidfd_send_signal`/`waitid(P_PIDFD)`
  and are PID-reuse-immune, with the classic `kill`/`waitpid` as fallback.
- **`vm.memfd_noexec`-aware.** `MFD_EXEC` (kernel 6.3+) is probed once and
  used when supported, so kernels configured to restrict memfd execution
  keep enforcing that; older kernels fall back gracefully.
- **Repeat-spawn fast path.** `prepare()` writes and seals once; every later
  spawn re-executes the sealed image without rewriting it.
- **Process-group knobs.** `setsid()` and `process_group(pgid)` run in the
  forked child before exec, std-`process_group(0)`-compatible; failures
  surface as real errnos.

## Optional: hugetlb, CLI, C FFI

- **`MFD_HUGETLB`** (`.hugetlb(true)`): stage the image on hugetlbfs for
  very large images (page-aligned via zero padding; loaders ignore bytes
  past the last `PT_LOAD`). Every hugetlb refusal degrades to an ordinary
  memfd — a spawn never fails *because of* the flag. `is_hugetlb()` reports
  what actually happened.
- **`memfd-run` CLI** (feature `cli`): `cargo build --features cli` gives you
  `memfd-run [--name NAME] [--argv0 ARGV0] FILE [ARGS...]` — exec a file from
  memory from the shell, exit code and 128+signal propagation included.
- **C FFI** (crate `memfd-ng-ffi` in this workspace): a small `extern "C"`
  layer (`memfd_ng_spawn/wait/kill/free`, negated-errno errors, panics caught
  into `-EIO`) with a hand-written C header and a real C smoke driver
  (`scripts/ffi-smoke.sh`).

## Measured (this machine: x86_64, Linux 6.18, rustc 1.98)

`cargo bench` — 300 spawns of a static `exit(0)` fixture, harness in
`benches/spawn.rs`:

| workload | µs/spawn |
| --- | --- |
| `std::process::Command` (control) | ~188 |
| memfd-ng, image written per spawn | ~552 |
| memfd-ng, `prepare()` once, re-spawn | ~275 |

Run-to-run variance is a few percent; the deltas are stable across runs.

Writing the image costs memory bandwidth; the prepared path halves the
per-spawn cost. `cargo build --release` size of a minimal driver linking the
crate: ~409 KB stripped (profile: `opt-level = "z"`, LTO, one codegen unit).

## Environment

- Linux (glibc, musl/static), x86_64 and aarch64 build- and link-verified;
  the static musl build runs its full test suite; musl compile-checked for
  both features.
- **qemu-user CI** (`qemu-user.yml`): the whole suite runs under
  `qemu-aarch64` with binfmt_misc registered, proving guest execution and the
  ladder's behavior under emulation. (Without binfmt, a kernel answers
  `ENOEXEC` for every guest-arch exec — verified locally; nothing user-space
  can lift that, which is why the runner must register binfmt.)
- **FreeBSD CI** (`freebsd.yml`): the full suite runs in a FreeBSD 14.2 VM,
  retiring the "compile-reviewed only" caveat on the `fexecve` rung.

Set `NO_MEMFDEXEC=1` to skip the memfd path and use the tmpfs ladder
directly.

## Testing

```sh
cargo test                          # behavior, parity, doctests
cargo test --features test-hooks    # + forced exec-ladder rungs & staging A/B
cargo test --features cli           # + memfd-run CLI end-to-end
cargo test -p memfd-ng-ffi          # + C FFI (Rust side)
./scripts/ffi-smoke.sh              # + C FFI (real C driver)
scripts/test.sh                     # everything, in CI order
```

The parity suite runs identical workloads through `std::process::Command`
and `MemFdExecutable` and asserts identical results — std is the oracle.
Fixtures are real binaries: a static and a dynamic stub built with the
system `cc` at test time (override with `MEMFD_NG_TEST_CC` for
cross-environments), plus a hand-assembled 136-byte ELF64 that exits 42.
`tests/fuzz_pipe.rs` structure-fuzzes the CLOEXEC-pipe protocol (2 000+
deterministic junk/bitflip/truncation cases per run, boundary-length
images, exact round-trips).

## MSRV

Rust 1.64. The only dependency is `libc` (plus `memfd-ng` itself for the FFI
crate).

## License

0BSD — see [LICENSE](LICENSE).
