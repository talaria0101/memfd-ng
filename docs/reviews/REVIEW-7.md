# Review 7 — std-parity and API-contract re-derivation

Pass: every new public item re-read against the `std::process::Command`
contract and the documented API contract; every parity claim re-executed
against the std oracle. Build + full suite green after fixes.

## Findings and dispositions

| # | finding | disposition |
| --- | --- | --- |
| R7-1 | **Inherited parity violation (predates this branch):** a command with *no* environment changes passed an empty `envp` to `execve` — `do_exec` did `maybe_envp.unwrap_or_default()`, i.e. an empty slice — so children saw an empty environment where std inherits the parent's `environ`. Demonstrated live on the parent commit: a canary variable visible to `std::process::Command` children reads as absent (`canary=`) in `MemFdExecutable` children | fixed: no-modification commands now pass the `environ` global (std's own approach; the child reads the fork-time copy); locked by `unmodified_env_inherits_the_parent_environment`, which fails on the old tree and passes here |
| R7-2 | The restructure to pre-fork argv/envp initially consumed the captured `Vec<CString>` while keeping raw pointers to its buffers — dangling pointers into freed heap (caught by `environment_values_with_equals_signs_round_trip` during bring-up, child saw `(unset)`) | fixed: `as_ref().map(...)` borrows for the whole spawn; regression is the existing env test suite |
| R7-3 | `setsid(true)` + `process_group(0)` was first documented as composable; the kernel refuses `setpgid(2)` on a session leader, so the spawn fails with `EPERM` — the doc claimed the opposite of reality | fixed: doc states they are alternatives; failure locked by `setsid_then_process_group_fails_with_the_kernel_verdict` (real errno through the exec-failure channel) |
| R7-4 | `waitid(P_PIDFD)` decoding uses a private 128-byte siginfo buffer (`si_signo`@0, `si_code`@8, `_sigchld.si_status`@24) instead of libc struct gymnastics | verified: exit codes 0/1/7/42/127/255 and `SIGTERM`/`SIGKILL` decode identically to the std `waitpid` oracle across `parity_exit_codes_match_std`, `groups`, `pidfd`, and the CLI's 128+signal mapping |
| R7-5 | `process_group(0)` parity with std's `Command::process_group(0)` | verified live: both make the child lead its own group (pgid == child pid) while staying in the parent's session; locked by `process_group_parity_with_std` |
| R7-6 | `is_sealed()`/`is_hugetlb()` could drift from kernel reality (our bookkeeping says X, the kernel did Y) | verified: `tests/seals.rs` reads `F_GET_SEALS` back from the kernel for every claim; `tests/hugetlb.rs` reads `fstatfs` magic off the prepared fd; on 6.18 an unsealed-but-sealable memfd reports seals `=1` (not the documented error) — assertions were adjusted to check only the bits *we* asked for, with the quirk documented in the test |
| R7-7 | argv is append-only across spawns on a prepared image (std semantics); a naive stress test assumed per-spawn argv | fixed the test: 50 prepared spawns with a growing argv must preserve every earlier argument and never rewrite the image (`prepare_then_spawn_stress`) |

## Verdict

The public surface matches the std contract everywhere the two overlap,
including the inherited-environment case that was silently broken since the
original tree. Every new knob reports kernel truth, not builder intent.
Re-test: full gate green.
