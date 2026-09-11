# Review 9 — emulation and ladder-semantics deep dive

Pass: run the whole suite cross-compiled for aarch64 under qemu-user, trace
every exec rung with `qemu -strace`, and re-derive the ladder's rung matrix
from what emulators actually do. Two real defects and one semantic
misclassification found and fixed; the suite gained per-process fixtures and
an A/B staging lock.

## What the traces established (all from live `qemu-aarch64 -strace` runs)

| # | observation | consequence |
| --- | --- | --- |
| R9-1 | qemu 7.2 does not implement `execveat`: the guest's rung-1 call returns `ENOSYS` every time | correct already: rung 1 falls through on `ENOSYS` — no change |
| R9-2 | qemu implements execve by re-executing **itself** with the target path; guest fds marked CLOEXEC are gone in the new process, so `execve("/proc/self/fd/N")` reopens a dead fd and answers `ENOEXEC` for a perfectly valid image | rung-2 `ENOEXEC` under an emulator is an *environmental* verdict, not a payload verdict. Fixed: rung 2 falls through on `ENOENT` **or `ENOEXEC`**; on real kernels rung 1 still returns `ENOEXEC` immediately, so the visible contract (corrupt image ⇒ `ENOEXEC`) is unchanged and locked by 5 tests |
| R9-3 | with rung 2 unable to work under an emulator, the only functional rung is the named one — but the old staging unlinked the staged name whenever procfs was available, so emulators had *no* working rung at all | fixed: staged names are kept until the parent learns the outcome (success EOF, failure errno, or death), and O_TMPFILE staging links the anonymous inode via the unprivileged `/proc/self/fd` linkat form so a name exists as fallback. Trace after the fix: memfd rungs refused → O_TMPFILE + reopen + linkat → fd rungs refused → **named rung execs the guest image successfully** → parent unlinks |
| R9-4 | without binfmt_misc registered, the kernel answers `ENOEXEC` for every guest-arch exec — including the named rung (`execve(path)` → native attempt → `ENOEXEC`); qemu 7.2 has no self-exec fallback and `QEMU_EXECVE` is absent (both tested) | unfixable in user space — this is precisely the roadmap's "needs a runner with qemu-user + binfmt" fine print. `qemu-user.yml` registers binfmt on the runner before running the suite. Locally, everything except the final kernel-level leg was verified: cross-build, guest fixture builds via `MEMFD_NG_TEST_CC`, ladder walk to the named rung, and the exact ENOEXEC verdict |
| R9-5 | **cross-process fixture race (defect):** each test binary built fixtures at a shared path; under parallel runs one binary could exec another's half-written ELF — observed live as `ENOEXEC` under qemu, flaky on the host too | fixed: fixtures are per-process (`name.<pid>`); the previously flaky run now passes 8 concurrent runs in a row |
| R9-6 | cargo does not pre-create `CARGO_TARGET_TMPDIR` for cross-target runs (defect in the harness) | fixed: the fixture builder creates its directory (`create_dir_all`) |
| R9-7 | rung matrix after the changes | verified: rung 1 falls on `ENOSYS`/`ENOENT`; rung 2 falls on `ENOENT`/`ENOEXEC`; `EACCES`/`EPERM` (enforcement modes) fall; real image verdicts (`ENOEXEC` from rung 1, `EINVAL`, `ETXTBSY`) stop immediately; the named rung's verdict is always final. Locked by `corrupt_image_reports_real_errno` + `tests/ladder.rs` |
| R9-8 | tiny-ELF fixture is x86_64 machine code | fixed: gated `#[cfg(target_arch = "x86_64")]` in both suites that used it; aarch64 runs exercise the cc-built fixtures instead |

## What was NOT established

- Guest execution under qemu without binfmt cannot work at the kernel level
  (proven above); the CI runner is where that leg is exercised.
- qemu aarch64 guest execution on the *runner* is CI-verified, not
  verified from this sandbox (no binfmt possible here — `unshare` and
  `binfmt_misc` mounts are both refused).

## Verdict

The ladder now does for emulators what it already did for old kernels: every
refused rung falls to the next candidate, names live only as long as a rung
needs them, and the surfaced errno is always the kernel's own. The suite
gained determinism along the way. Re-test: full gate green on x86_64;
aarch64 under binfmt rides on `qemu-user.yml`.
