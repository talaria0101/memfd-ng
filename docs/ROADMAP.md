# Roadmap

Feature requests and future work, with priorities and dispositions. An item
lands here only with a reason; refused items keep theirs so no future session
re-derives the decision.

## Accepted

| # | request | priority | effort | notes |
| --- | --- | --- | --- | --- |
| 1 | **pidfd spawn**: `clone3(CLONE_PIDFD\|CLONE_VFORK)` where available, plain `fork()` fallback | P1 | medium-high | kills the PID-reuse race in `kill()`/`wait`, makes children pollable; biggest single latency win left (vfork-class spawn) |
| 2 | **`Child::pidfd()` + poll-able child** | P2 | small | depends on 1; lets event loops await exit without SIGCHLD |
| 3 | **O_TMPFILE staging** for the fallback ladder | P2 | medium | removes the named-file window entirely in the no-procfs corner (needs the `/proc`-less linkat dance, else keep the pipe protocol) |
| 4 | **Granular sealing API** — `seals(u32)` builder + `F_SEAL_FUTURE_WRITE` option | P2 | small | current default stays `SHRINK\|GROW\|WRITE` |
| 5 | **Process-group options** — `setsid()`/`setpgid()` builder knobs | P2 | small | requested for supervisor-style users |
| 6 | **qemu-user CI job** — run the suite under `qemu-x86_64`/`qemu-aarch64` to prove the guest-execution claim instead of documenting it | P2 | small | needs a runner with qemu-user + binfmt |
| 7 | **FreeBSD runtime verification** — CI runner or VM pass; the cfg-gated `fexecve` rung is compile-reviewed only | P2 | small | closes the last "untested" row in the docs |
| 8 | **Pipe-protocol fuzzing** — `pipe_read` parser under a small structure-aware fuzzer (6-byte header dispatch, length-bounded payload) | P2 | small | the one place untrusted-shape bytes are parsed |
| 9 | **`MFD_HUGETLB` option** for very large payloads | P3 | small | hugetlb memfd exec has page-size alignment constraints; must degrade to ordinary memfd |
| 10 | **`memfd-run` CLI** — optional `[[bin]]` behind a feature to exec a file from memory from a shell | P3 | small | keeps the library lean by default |
| 11 | **C FFI layer** (`memfd_ng_spawn` C API) for non-Rust embedders | P3 | medium | separate `-ffi` crate; this one stays pure Rust |

## Not planned

| request | reason |
| --- | --- |
| `no_std` support | the crate is defined by `fork`/`exec` process machinery and std error/io types; a `no_std` core would be a different, thinner crate with no shared code |
| WASI target | no `memfd_create`/`fexecve` substrate; the concept does not transfer |
| async/tokio child | an adapter crate wrapping this one can add it; embedding a runtime dependency here would tax every user for one feature |
| raw `envp` pointer API | unsafe surface with no demonstrated caller; the BTreeMap capture covers the real cases |
| upstreaming anything, anywhere | standing repo rule; fixes land here, now, in this tree |
