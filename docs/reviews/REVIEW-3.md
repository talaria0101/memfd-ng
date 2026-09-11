# Review 3 — failure-mode, security and edge-case pass

Pass: stress the design — degraded filesystems, awkward names, signal
windows, partial messages, permission edges — and check every failure path
fails closed. Build + full suite green after fixes.

## Findings and dispositions

| # | vector | analysis | disposition |
| --- | --- | --- | --- |
| R3-1 | **Name joins into paths.** The inherited fallback joined the user-supplied name into a filesystem path (`dir.join(name)`); a name containing `/` would write (and exec) outside the intended directory | memfd-ng derives fallback names purely from `uid`, `pid` and 128 bits of randomness — the program name never touches a path | fixed by design; regression-locked by `memfd_name_visible_in_child` (name reaches `/memfd:`, not a path) |
| R3-2 | **Pre-created / symlinked fallback file.** A competing process plants a file at the ladder's next name | `O_EXCL\|O_CREAT` fails closed and the ladder retries with fresh randomness, then moves to the next directory | safe; verified by reading the retry branch |
| R3-3 | **Permission window on the staged file.** Between `open` and `fchmod` the mode is `0700 & ~umask` | a umask can only remove bits from `0700`, never add group/other access, so the file is owner-only at every instant; `fchmod` then restores the execute bit umask may have stripped | safe |
| R3-4 | **A competing process unlinks the named fallback before exec** (only reachable with procfs absent) | fd-based rungs do not need the name; the named rung fails `ENOENT`, the child reports it, the parent fails closed. No exec of foreign content is possible because the inode is ours and owner-only | safe |
| R3-5 | **Image swap between write and exec** | `F_SEAL_SHRINK\|GROW\|WRITE` lands before exec; only the parent's fd exists in the window; children of a prepared image cannot modify a sealed image | safe; asserted by `sealing_is_applied_and_visible` via `F_GET_SEALS` |
| R3-6 | **Truncated pipe protocol** — forked child killed mid-message | parent's `pipe_read` answers a short read with `InvalidData`, reaps the child, returns an error; no hang, no desync into a wrong interpretation (the PATH header `bytes[2..6]` cannot collide with an errno message's `NOEX` footer bytes) | verified |
| R3-7 | **Signal window leaves a tmpfs file** — SIGKILL between create and unlink | microscopic window; residue is owner-only, in the tmp dir, and indistinguishable from any crashed process's tmpfile — tmp-reaper territory | accepted, documented here |
| R3-8 | **`exec()` + procfs-absent + named fallback** — no parent survives to receive the name | the name persists after exec; documented limitation of a triple corner (no procfs, no execveat, `exec()` API); every procfs-present and every `spawn()` path is leak-free | accepted, documented |
| R3-9 | **Rung-exhaustion semantics misfire** — falling to the tmpfs ladder on a verdict that would repeat | matrix verified: `ENOSYS`/`ENOENT` (facility missing) and `EACCES`/`EPERM` (exec refused, e.g. LSM or enforcement mode) fall to the next candidate; `ENOEXEC`, `EINVAL`, `ETXTBSY`… return immediately as the real verdict | verified; locked by `corrupt_payload_reports_real_errno` |
| R3-10 | **`try_wait` returns `Err(Interrupted)` instead of retrying** | matches std's own `try_wait` semantics; callers retry naturally | accepted (std parity) |
| R3-11 | **`ST_NOEXEC` kernel-ABI drift** | raw `statfs` struct matches every 64-bit Linux ABI; non-64-bit-Linux skips the check and fails closed at exec (`EACCES`), never execs from a noexec mount | safe by degradation |
| R3-12 | **Zombie/handle misuse** — `kill` after reap, `wait` after `wait` | guarded (`InvalidInput`), matches std | verified |

## Verdict

Every failure path fails closed; the two accepted residues (R3-7, R3-8) are
documented and unreachable on procfs-present systems. Re-test: default suite
32/32 + 5 doctests, `--features test-hooks` green, clippy `-D warnings`
clean.
