# Review 6 — failure-mode injection

Pass: stop reading code, start stressing the environment. New committed tests
drive real failure modes end to end (unusable mounts, dead directories, empty
images, NUL arguments, 1000-argument vectors, `=`-bearing env values).
Full suite green after fixes, five consecutive failure-mode runs clean.

## New instruments (committed as `tests/adversarial.rs`, since renamed `tests/failure_modes.rs`)

| # | injection | expected | result |
| --- | --- | --- | --- |
| R6-1 | `TMPDIR=/proc` + fallback forced — `/proc` is a **real noexec mount** on this host | `ST_NOEXEC` skip is exercised against a genuine mount, ladder lands on `/dev/shm`, nothing staged inside `/proc` | **pass** — the noexec-awareness claim is now proven live, not just read from `statfs` docs |
| R6-2 | every env-controlled directory dead (`XDG_RUNTIME_DIR`, `TMPDIR`, `HOME` → `/nonexistent-*`) | ladder walks past them to `/dev/shm`, silent, no leftovers | pass |
| R6-3 | empty image | kernel's `ENOEXEC` from `status()`, no hang, no leftovers | pass |
| R6-4 | NUL byte in an argument | `InvalidInput` before any fork; tmpfs untouched | pass |
| R6-5 | 1000-argument argv (plus sentinel) | verbatim round trip through argv construction and exec | pass |
| R6-6 | environment value `a=b=c=d` | round trips through the `key=value` reconstruction | pass |
| R6-7 | `sealed(false)` after `prepare()` | cache invalidated, fresh unsealed image staged | pass (with the R4-1 fix) |

## Test-suite defect found and fixed during injection

| # | finding | disposition |
| --- | --- | --- |
| R6-8 | the new suite's cleanliness assertions ran **after** dropping the serial lock; the next test's env writes (`TMPDIR` → `/nonexistent-*`) raced the previous test's `env::temp_dir()` read, producing spurious `NotFound`/wrong-directory assertions that appeared only under parallel execution | fixed: all assertions moved inside the lock; suite run 5× consecutively with zero failures (previously failed ~1 in 2 full runs) |

## What was NOT established

- A real read-only **root** or full-tmpfs (`ENOSPC`) injection — the sandbox
  has no privilege to stage those; the per-directory error path they exercise
  is the same `open`-fails branch as the dead-directory test above.
- Injected `EINTR` storms on the exec ladder — `pipe_write_all` retries
  `EINTR` (R2-3) but a signal-storm harness was not built.
- qemu-user execution (no emulator in the sandbox) — remains roadmap item 6.

## Verdict

The library fails closed under every injected failure and stays silent doing
it. The one defect found was in the test suite, not the library, and its fix
made the whole suite deterministic.
