# Review 2 — unsafe code and syscall audit

Pass: every `unsafe` block, raw syscall, fd lifecycle and errno path in
`src/` re-read end to end. Build + full suite (including `test-hooks`) green
after fixes.

## Findings and dispositions

| # | finding | disposition |
| --- | --- | --- |
| R2-1 | `proc_fd_path` accepted negative fds; a `-1` would render `/proc/self/fd/` and exec a directory path | fixed: returns `None` for `fd < 0` |
| R2-2 | FreeBSD had no fd-based rung: `execveat` is Linux-only in the ladder, and FreeBSD's `fexecve(2)` — a real kernel facility there — was unused | fixed: cfg-gated `fexecve` rung for FreeBSD (untested on hardware; documented) |
| R2-3 | `pipe_write_all` broke out of the write loop on `EINTR` like on any error — a signal mid-write could truncate the errno or named-path message and desynchronize the parent's parser | fixed: `EINTR` retries, true errors break |
| R2-4 | **`NamedPath` shipped the whole 192-byte stack buffer, not the string** — `len` was the array length, so the parent's `remove_file` got a NUL-padded name and silently failed, leaving the tmpfs file behind | fixed: `len` is the string length + NUL; caught live by `named_rung_executes_and_parent_cleans_up_without_procfs`, which now passes |
| R2-5 | `hook_disabled` called `libc::getenv` without an `unsafe` block (compile error once actually exercised) | fixed; getenv only reads `environ` |
| R2-6 | fd lifecycle sweep: every `open` has a close on every path — memfd probe (closes), tmpfs file (close+unlink on every error branch), ro reopen (close of wr fd), pipes (parent drops write end, child drops read end) | verified, no change |
| R2-7 | zombie sweep: every parent error branch (`Failure`, protocol error) reaps via `p.wait()` before returning; success hands the PID to `Child` per std contract | verified, no change |
| R2-8 | allocation-in-child sweep: only `argv`/`envp` pointer arrays and error formatting allocate in the forked child; `tmpfs_payload` and `exec_fd` are allocation-free (stack buffers + raw syscalls) — this is the property that makes the fallback safe under a held malloc lock | verified, no change |
| R2-9 | errno fidelity sweep: `Error::last_os_error()` is read with zero intervening libc calls in every branch; fallback failures never overwrite the reported errno | verified, no change |

## Reproduction for R2-4 (kept as a regression check)

```sh
cargo test --features test-hooks --test ladder \
  named_rung_executes_and_parent_cleans_up_without_procfs
```

Before the fix this failed with `tmpfs ladder left files behind` because the
parent tried to unlink `/tmp/.memfd-ng-…\0\0…`.

## Verdict

All unsafe paths account for their fds, errnos and allocations. Re-test:
default suite 32/32 + doctests, `--features test-hooks` suite green, clippy
clean.
