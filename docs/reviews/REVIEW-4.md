# Review 4 — concurrency and resource-lifecycle audit

Pass: every mutation point, every fd, every child handle re-read under the
question "what happens when this overlaps, exhausts, or is dropped?".
Build + full suite green after fixes.

## Findings and dispositions

| # | finding | disposition |
| --- | --- | --- |
| R4-1 | `sealed(false)` after `prepare()` left the old **sealed** image cached — subsequent spawns silently ran the sealed payload after the caller asked for unsealed | fixed: `sealed()` now invalidates the prepared cache when the setting actually changes; locked by `unsealing_after_prepare_invalidates_the_cache` |
| R4-2 | `std::os::fd` paths in `child.rs` require Rust 1.66, but the crate claims MSRV 1.64 | fixed: `std::os::unix::io` aliases (stable since 1.0); keeps the MSRV claim honest |
| R4-3 | fork-failure path: `do_fork()?` returns with both pipe fds and `StdioPipes` alive | verified: all are locals with `Drop`, nothing leaks; no child exists so nothing to reap |
| R4-4 | fd exhaustion (`EMFILE`) mid-spawn | verified fail-closed: probe/create/open errors propagate, `spawn` returns `Err`, tmpfs ladder walks to the next directory on per-dir `EMFILE` |
| R4-5 | `Child` dropped without `wait()` | accepted, std-parity: zombie persists exactly as `std::process::Child` would; documented here rather than papered over with a background reaper thread |
| R4-6 | `spawn()` blocks on the CLOEXEC pipe; a child wedged pre-exec (e.g. `open` on a dead network mount inside the tmpfs ladder) blocks the caller forever | accepted, std-parity: `std::process::Command::spawn` has the identical property; timeouts belong to the caller |
| R4-7 | prepared memfd lifetime | verified: owned by `Prepared` inside the struct; dropped (closed) with it or replaced by a second `prepare()`; `exec()`-mode success closes it via `MFD_CLOEXEC` |
| R4-8 | concurrent `spawn()` from many threads on *distinct* commands | verified + covered by `concurrent_spawns_are_safe` (8 threads): capability probes are racy-but-idempotent atomics, no shared mutable state |

## Verdict

No lost fds, no un-reaped children beyond the documented std-parity case, no
aliasing (the builder API is `&mut self` throughout). Re-test: full gate
green.
