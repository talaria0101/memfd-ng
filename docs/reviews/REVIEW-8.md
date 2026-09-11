# Review 8 — unsafe code and syscall audit of the new machinery

Pass: every new `unsafe` block, raw syscall, struct layout and fd lifecycle
in the pidfd/O_TMPFILE/seals/hugetlb work re-read end to end. Build + full
suite green after fixes.

## Findings and dispositions

| # | finding | disposition |
| --- | --- | --- |
| R8-1 | `clone3` `CloneArgs` layout | verified: 8 × `u64` fields, `pidfd` is a pointer-to-int slot, `exit_signal = SIGCHLD`, base 64-byte size accepted by every clone3 kernel (5.3+). `CLONE_VFORK` without `CLONE_VM` verified live: the parent is suspended until exec (~105 µs) while the child's writes land in a private COW copy — a child write to a global never reached the parent |
| R8-2 | probe caching could poison future spawns if a *transient* error were cached | verified: clone3 caches only `ENOSYS`/`EINVAL` (structural); `waitid(P_PIDFD)` caches only `EINVAL`/`ENOSYS`; the hugetlb probe deliberately does **not** cache `ENOMEM` (huge pages can be added at runtime). All probes are idempotent single-syscalls, so probe races between threads are harmless |
| R8-3 | `RawSiginfo` is a private 128-byte `#[repr(C, align(8))]` buffer cast to `*mut siginfo_t` for `waitid` | verified: Linux siginfo is a fixed 128 bytes on every ABI, alignment 8; only `si_signo`@0, `si_code`@8 and `_sigchld.si_status`@24 are read — identical offsets on 32- and 64-bit. Kernel `CLD_EXITED/CLD_KILLED/CLD_DUMPED` decode into waitpid's raw-status encoding, reusing the long-tested `ExitStatus` decoder |
| R8-4 | fd lifecycle sweep of the new code | verified: clone3 pidfd is owned by `Process` and closed on drop (`spawning_does_not_leak_pidfds`, 30 cycles); O_TMPFILE write fd closes on every path (staged/reopened/failed), and the linked name is the parent's to unlink; the hugetlb create path closes on fstatfs failure, write failure and degrade; the reopen-ro fd replaces (never duplicates) the write fd before exec so the named rung cannot hit `ETXTBSY` |
| R8-5 | allocation-in-child claim under the new clone3 path | verified and *strengthened*: argv/envp pointer arrays are now built before the fork (the old code built them inside the child — an allocation the docs pretended didn't exist), and the error paths in the child carry raw errnos (`Error::new` allocations removed from the child-reachable ladder). The child between clone and exec now truly touches no allocator; locked by the deep-stack sentinel test |
| R8-6 | `AT_SYMLINK_FOLLOW` (0x400) / `AT_EMPTY_PATH` (0x1000) values and the two linkat forms | verified live: the procfs form `linkat(AT_FDCWD, "/proc/self/fd/N", …, AT_SYMLINK_FOLLOW)` succeeds unprivileged; the `linkat(fd, "", …, AT_EMPTY_PATH)` form succeeds here (root/CAP_DAC_READ_SEARCH) and is exercised by the no-procfs suite; both leave the inode dead when the fd closes unlinked |
| R8-7 | `waitid` without `WNOHANG` returning `Ok(None)` | impossible per kernel contract; the case is handled as an explicit error rather than a panic (parent-side only) |
| R8-8 | `KernelStatfs` reuse for `fstatfs` (hugetlb page size + magic) | verified live on a real hugetlb memfd: `f_type == 0x958458f6`, `f_bsize == 2 MiB`; unaligned writes refused EINVAL, aligned writes succeed, and with zero preallocated huge pages the write fails ⇒ documented degrade fires (`hugetlb_request_never_breaks_spawning`) |
| R8-9 | errno fidelity of the new ladder tail | verified: the exhaustion marker is a raw `ENOSYS` produced without allocation; rung-1 `ENOEXEC` still surfaces immediately as the payload verdict; corrupt/empty images still report `ENOEXEC` (5 tests assert it) |
| R8-10 | `MEMFD_NG_TEST_NO_OTMPFILE` / `MEMFD_NG_TEST_NO_NAMED_STAGE` hooks | verified as A/B forcing functions: with named staging forbidden, success can only have come from the O_TMPFILE path (`otmpfile_staging_serves_the_whole_ladder`); with O_TMPFILE off, the legacy flow behaves exactly as before |

## Verdict

The new machinery follows the same discipline as the old: probes are cached
idempotently, every fd has an owner and an exit, the forked child is
allocation-free (now truthfully), and every seal/staging claim is read back
from the kernel. Re-test: full gate green.
