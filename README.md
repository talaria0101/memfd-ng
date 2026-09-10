# memfd-ng

Execute ELF binaries straight from memory. Put the bytes of a Linux
executable in a `&[u8]` — `include_bytes!()`, a socket, a compiler — and
`MemFdExecutable` runs them without the file ever landing on disk, through an
interface shaped like `std::process::Command`.

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
payload bytes
     │
     ▼
memfd_create(MFD_CLOEXEC │ MFD_EXEC? │ MFD_ALLOW_SEALING?)   ← probed once per process
     │ write + seal (F_SEAL_SHRINK|GROW|WRITE)
     ▼
rung 1: execveat(fd, "", AT_EMPTY_PATH)      Linux 3.19+, no procfs needed
rung 2: execve("/proc/self/fd/N")            3.17/3.18, procfs only
rung 3: tmpfs ladder → named exec            emulators, ancient kernels
```

Every rung after a refused `execveat` is silent and, in the forked child,
allocation-free (stack buffers and raw syscalls only — a forked child must
not depend on a malloc lock another thread may hold).

The tmpfs ladder picks the first workable directory — `XDG_RUNTIME_DIR`,
`TMPDIR`/`/tmp`, `/dev/shm`, `~/.cache` — rejecting `ST_NOEXEC` mounts
outright via a raw `statfs`. Staged files get library-generated names (the
program name never touches a path), are made read-only before exec (the
kernel's `ETXTBSY` rule exempts memfds but not regular files), are unlinked
while every rung is still fd-based, and are otherwise reported to the
parent, which unlinks them after reaping. No threads, no helper processes,
no sleeps, no races.

## Properties

- **std Command discipline.** Arguments or environment values containing NUL
  bytes are rejected with `InvalidInput`, exactly as std does; `Debug` never
  dumps the payload.
- **Errno fidelity.** A failed exec surfaces from `spawn()`/`status()`/
  `output()` as a real `std::io::Error` with the kernel's own errno
  (`ENOEXEC`, `EACCES`, …). The child reports through the CLOEXEC pipe; it
  never panics and never prints.
- **Quiet by construction.** The library writes nothing to stderr — captured
  output is never polluted.
- **No fd leaks.** The payload memfd carries `MFD_CLOEXEC`; children see
  exactly the std stdio set.
- **Sealed payloads.** Written payloads are sealed against shrink, grow and
  write, so nothing can swap code between write and exec. Opt out with
  `.sealed(false)`.
- **`vm.memfd_noexec`-aware.** `MFD_EXEC` (kernel 6.3+) is probed once and
  used when supported, so enforcement modes keep working; older kernels fall
  back gracefully.
- **Repeat-spawn fast path.** `prepare()` writes and seals once; every later
  spawn re-executes the sealed image without rewriting it.

## Measured (this machine: x86_64, Linux 6.18, rustc 1.98)

`cargo bench` — 300 spawns of a static `exit(0)` fixture, harness in
`benches/spawn.rs`:

| workload | µs/spawn |
| --- | --- |
| `std::process::Command` (control) | ~172 |
| memfd-ng, payload written per spawn | ~529 |
| memfd-ng, `prepare()` once, re-spawn | ~273 |

Writing the payload costs memory bandwidth; the prepared path halves the
per-spawn cost. `cargo build --release` size of a minimal driver linking the
crate: ~409 KB stripped (profile: `opt-level = "z"`, LTO, one codegen unit).

## Environment

- Linux (glibc, musl/static), x86_64 and aarch64 build- and link-verified;
  the static musl build runs its full test suite.
- FreeBSD support is cfg-gated and compiles out of the box, but is untested
  on real hardware — reports welcome.
- No qemu-user here to prove guest execution; the tmpfs ladder exists for
  those environments.

Set `NO_MEMFDEXEC=1` to skip the memfd path and use the tmpfs ladder
directly.

## Testing

```sh
cargo test                          # behavior, parity, doctests
cargo test --features test-hooks    # + forced exec-ladder fallback rungs
```

The parity suite runs identical workloads through `std::process::Command`
and `MemFdExecutable` and asserts identical results — std is the oracle.
Fixtures are real binaries: a static and a dynamic stub built with the
system `cc` at test time, plus a hand-assembled 121-byte ELF64 that exits 42.

## MSRV

Rust 1.64. The only dependency is `libc`.

## License

0BSD — see [LICENSE](LICENSE).
