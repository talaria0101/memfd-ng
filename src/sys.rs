//! Raw syscall layer: memfd creation (ordinary or hugetlb) with a capability
//! ladder, image sealing, a three-rung exec ladder, pidfd-based child
//! handling, and the CLOEXEC-pipe protocol that carries the real errno (or a
//! fallback-file path) from the forked child back to the parent.
//!
//! Everything the child runs between fork and exec is written without
//! touching the allocator: stack buffers and direct syscalls only, because
//! a forked child must not rely on (or deadlock on) a malloc lock another
//! thread may hold.

use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::cvt::{cvt, cvt_r_ssize, cvt_ssize};

// memfd_create flags (linux/memfd.h). Defined here so targets whose libc
// crate lacks the constants still compile; the values are ABI-stable.
pub const MFD_CLOEXEC: libc::c_uint = 0x0001;
pub const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;
pub const MFD_HUGETLB: libc::c_uint = 0x0004;
pub const MFD_EXEC: libc::c_uint = 0x0010;

pub const F_ADD_SEALS: libc::c_int = 1033;
pub const F_SEAL_SHRINK: libc::c_int = 0x0001;
pub const F_SEAL_GROW: libc::c_int = 0x0002;
pub const F_SEAL_WRITE: libc::c_int = 0x0008;
pub const SEALS_FULL: libc::c_int = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

pub const AT_EMPTY_PATH: libc::c_int = 0x1000;
pub const AT_SYMLINK_FOLLOW: libc::c_int = 0x0400;

// pidfd machinery. Syscall numbers are ABI-stable across every Linux arch;
// CLONE_* flag values likewise (uapi/linux/sched.h).
pub const SYS_CLONE3: libc::c_long = 435;
pub const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
pub const CLONE_VFORK_FLAG: libc::c_long = 0x0000_4000;
pub const CLONE_PIDFD_FLAG: libc::c_long = 0x0000_1000;

// magic for hugetlbfs, from uapi/linux/magic.h
pub const HUGETLBFS_MAGIC: i64 = 0x9584_58f6;

// The parent's (inherited) environment, passed to execve when the command
// carries no explicit environment changes — exactly what std does. libc does
// not declare it for Linux, so declare the POSIX global here.
extern "C" {
    static mut environ: *mut *mut libc::c_char;
}

/// Read the global `environ` pointer for execve. Called in the forked child:
/// the pointer (and the strings it references) are the fork-time copy.
pub fn inherited_environ() -> *const *const libc::c_char {
    unsafe { environ as *const *const libc::c_char }
}

// ---------------------------------------------------------------------------
// Capability probes
// ---------------------------------------------------------------------------

// 0 = unknown, 1 = supported, 2 = unsupported. Races are harmless: the probe
// syscall is idempotent and its only side effect is one closed fd.
static EXEC_BIT: AtomicU8 = AtomicU8::new(0);
static SEAL_BIT: AtomicU8 = AtomicU8::new(0);
static HUGETLB_BIT: AtomicU8 = AtomicU8::new(0);
static CLONE3_BIT: AtomicU8 = AtomicU8::new(0);
static PIDFD_WAIT_BIT: AtomicU8 = AtomicU8::new(0);
static PROC_OK: AtomicU8 = AtomicU8::new(0);

/// The cached verdict of a capability probe: the kernel facility is not
/// available (raw `ENOSYS`, so callers can match on it). Not to be confused
/// with a per-spawn failure, which keeps its own errno.
fn unsupported() -> Error {
    Error::from_raw_os_error(libc::ENOSYS)
}

/// True when `err` is the cached probe verdict, not a real failure.
pub fn is_unsupported(err: &Error) -> bool {
    err.raw_os_error() == Some(libc::ENOSYS)
}

fn probe_flag(flag: libc::c_uint, atom: &AtomicU8) -> bool {
    match atom.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let name = b"memfd-ng-probe\0";
    let supported = unsafe {
        let fd = libc::memfd_create(name.as_ptr() as *const libc::c_char, MFD_CLOEXEC | flag);
        if fd >= 0 {
            libc::close(fd);
            true
        } else {
            false
        }
    };
    atom.store(if supported { 1 } else { 2 }, Ordering::Relaxed);
    supported
}

/// True when `/proc` is mounted and `access(F_OK)` passes, cached per process.
pub fn proc_available() -> bool {
    #[cfg(feature = "test-hooks")]
    if hook_disabled(b"MEMFD_NG_TEST_NO_PROC\0") {
        return false;
    }
    match PROC_OK.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let ok = unsafe {
                libc::access(b"/proc/self\0".as_ptr() as *const libc::c_char, libc::F_OK) == 0
            };
            PROC_OK.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            ok
        }
    }
}

// ---------------------------------------------------------------------------
// memfd
// ---------------------------------------------------------------------------

/// Create an anonymous executable file and return the raw fd.
///
/// `MFD_EXEC` (kernel 6.3+) is probed once and set when supported, so
/// `vm.memfd_noexec` enforcement modes keep working; on older kernels the
/// creation falls back to `MFD_CLOEXEC` and the kernel default. When
/// `allow_sealing` is true and the kernel supports it, `MFD_ALLOW_SEALING`
/// is added so the image can be sealed once fully written.
pub fn memfd_create(name: *const libc::c_char, allow_sealing: bool) -> Result<libc::c_int> {
    let mut flags = MFD_CLOEXEC;
    if probe_flag(MFD_EXEC, &EXEC_BIT) {
        flags |= MFD_EXEC;
    }
    if allow_sealing && probe_flag(MFD_ALLOW_SEALING, &SEAL_BIT) {
        flags |= MFD_ALLOW_SEALING;
    }
    cvt(unsafe { libc::memfd_create(name, flags) })
}

/// Create an anonymous executable file on hugetlbfs (`MFD_HUGETLB`, kernel
/// 4.14+). Probed once; `Err` with raw `ENOSYS` means the kernel refused the
/// facility outright and the caller should stage an ordinary memfd.
pub fn memfd_create_hugetlb(name: *const libc::c_char) -> Result<libc::c_int> {
    if HUGETLB_BIT.load(Ordering::Relaxed) == 2 {
        return Err(unsupported());
    }
    let fd = unsafe { libc::memfd_create(name, MFD_CLOEXEC | MFD_HUGETLB) };
    if fd >= 0 {
        HUGETLB_BIT.store(1, Ordering::Relaxed);
        return Ok(fd);
    }
    let err = Error::last_os_error();
    // ENOSYS/EINVAL: the kernel has no hugetlb memfd support at all.
    // ENOMEM is deliberately NOT cached: huge pages can be added at runtime.
    if matches!(
        err.raw_os_error(),
        Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
    ) {
        HUGETLB_BIT.store(2, Ordering::Relaxed);
        return Err(unsupported());
    }
    Err(err)
}

/// The hugetlb page size of a hugetlbfs memfd (`fstatfs(2).f_bsize`), or
/// `None` when the fd is not on hugetlbfs — the caller's signal to degrade
/// to an ordinary memfd rather than guess alignment.
pub fn hugetlb_page_size(fd: libc::c_int) -> Option<i64> {
    let mut fs: KernelStatfs = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::syscall(libc::SYS_fstatfs, fd, &mut fs as *mut KernelStatfs) == 0 };
    if ok && fs.f_type == HUGETLBFS_MAGIC && fs.f_bsize > 0 {
        Some(fs.f_bsize)
    } else {
        None
    }
}

/// Seal a memfd against the given `F_SEAL_*` bits. Returns false when the
/// kernel has no sealing support (the image still runs, it just stays
/// modifiable through writable fds).
pub fn add_seals(fd: libc::c_int, seals: libc::c_int) -> bool {
    unsafe { libc::fcntl(fd, F_ADD_SEALS, seals) == 0 }
}

/// True when `fd` is a regular file — the only kind the kernel will exec.
pub fn is_regular_file(fd: libc::c_int) -> bool {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFREG
    }
}

/// Write the whole buffer, looping over partial writes.
pub fn write_all(fd: libc::c_int, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = cvt_r_ssize(|| unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) })?;
        if n == 0 {
            return Err(Error::new(ErrorKind::WriteZero, "failed to write image"));
        }
        buf = &buf[n..];
    }
    Ok(())
}

/// Read until the buffer is full or the stream ends.
fn read_fill(fd: libc::c_int, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = cvt_ssize(unsafe {
            libc::read(fd, buf[filled..].as_mut_ptr() as *mut libc::c_void, buf.len() - filled)
        })?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

// ---------------------------------------------------------------------------
// pidfd spawn and race-free child handling (Linux)
// ---------------------------------------------------------------------------

/// `struct clone_args` for the clone3 syscall (uapi/linux/sched.h). The
/// base 64-byte layout is accepted by every kernel that implements clone3;
/// later additions (set_tid, cgroup) are appended by the kernel, not us.
#[cfg(target_os = "linux")]
#[repr(C)]
struct CloneArgs {
    flags: libc::c_ulonglong,
    pidfd: *mut libc::c_int,
    child_tid: libc::c_ulonglong,
    parent_tid: libc::c_ulonglong,
    exit_signal: libc::c_ulonglong,
    stack: libc::c_ulonglong,
    stack_size: libc::c_ulonglong,
    tls: libc::c_ulonglong,
}

/// What `clone3_vfork_pidfd` decided for the caller.
pub enum ForkOutcome {
    /// The calling thread continues as the child (pid would be 0).
    Child,
    /// The calling thread is the parent; the child has `pid` and the parent
    /// holds a `pidfd` that stays valid across PID reuse.
    Parent { pid: libc::pid_t, pidfd: libc::c_int },
}

/// Fork via `clone3(CLONE_VFORK | CLONE_PIDFD, exit_signal = SIGCHLD)`
/// (kernel 5.3+).
///
/// - `CLONE_VFORK` suspends the parent until the child execs or exits, so
///   the freshly forked child runs immediately instead of racing the
///   scheduler — the same latency win posix_spawn buys. Without `CLONE_VM`
///   the child still gets a private copy-on-write address space, so it can
///   never corrupt the suspended parent.
/// - `CLONE_PIDFD` returns a pidfd, which makes `kill`/`wait` immune to PID
///   reuse and lets callers poll(2) the child.
///
/// `Err` with raw `ENOSYS` (cached) means the kernel lacks clone3 or refuses
/// the flag pair; the caller must fall back to plain `fork()`. Any other
/// error is the spawn's real verdict and is propagated.
pub fn clone3_vfork_pidfd() -> Result<ForkOutcome> {
    if CLONE3_BIT.load(Ordering::Relaxed) == 2 {
        return Err(unsupported());
    }
    let mut pidfd: libc::c_int = -1;
    let mut args = CloneArgs {
        flags: (CLONE_VFORK_FLAG | CLONE_PIDFD_FLAG) as libc::c_ulonglong,
        pidfd: &mut pidfd,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as libc::c_ulonglong,
        stack: 0,
        stack_size: 0,
        tls: 0,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_CLONE3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if ret >= 0 {
        CLONE3_BIT.store(1, Ordering::Relaxed);
        return Ok(if ret == 0 {
            ForkOutcome::Child
        } else {
            ForkOutcome::Parent {
                pid: ret as libc::pid_t,
                pidfd,
            }
        });
    }
    let err = Error::last_os_error();
    if matches!(err.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) {
        // no clone3 (< 5.3), or a hardening layer that refuses the call:
        // plain fork() is the ladder's next rung.
        CLONE3_BIT.store(2, Ordering::Relaxed);
        return Err(unsupported());
    }
    Err(err)
}

/// Kernel siginfo layout, fixed size (128 bytes on every Linux ABI), used
/// only to decode what waitid wrote: si_signo @ 0, si_code @ 8, and
/// _sigchld.si_status @ 24 (identical offset on 32- and 64-bit). A private
/// copy keeps the decoding independent of libc crate struct gymnastics.
#[repr(C, align(8))]
struct RawSiginfo([u8; 128]);

impl RawSiginfo {
    fn field(&self, off: usize) -> i32 {
        i32::from_ne_bytes([self.0[off], self.0[off + 1], self.0[off + 2], self.0[off + 3]])
    }
}

/// Decode a filled siginfo into the raw wait-status encoding that
/// `ExitStatus` understands (same encoding waitpid returns).
fn siginfo_to_wait_status(info: &RawSiginfo) -> i32 {
    match info.field(8) {
        libc::CLD_EXITED => (info.field(24) & 0xff) << 8,
        libc::CLD_KILLED => info.field(24),
        libc::CLD_DUMPED => info.field(24) | 0x80, // WCOREDUMP
        _ => 0,
    }
}

/// Wait for a child by pidfd (`waitid(P_PIDFD, WEXITED)`), immune to PID
/// reuse. Returns `Ok(None)` only with `nohang` and a still-running child.
/// `Err` with raw `ENOSYS` (cached) = kernel without P_PIDFD (< 5.4); the
/// caller falls back to waitpid on the cached pid.
pub fn waitid_pidfd(pidfd: libc::c_int, nohang: bool) -> Result<Option<i32>> {
    if PIDFD_WAIT_BIT.load(Ordering::Relaxed) == 2 {
        return Err(unsupported());
    }
    let mut info = RawSiginfo([0u8; 128]);
    let mut options = libc::WEXITED;
    if nohang {
        options |= libc::WNOHANG;
    }
    // The kernel fills a fixed 128-byte siginfo; our RawSiginfo is exactly
    // that buffer with matching alignment.
    let ret = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd as libc::id_t,
            &mut info as *mut RawSiginfo as *mut libc::siginfo_t,
            options,
        )
    };
    if ret != 0 {
        let err = Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS)) {
            // idtype P_PIDFD unrecognized = kernel < 5.4. Our options and id
            // are otherwise always valid, so EINVAL cannot mean anything else
            // here.
            PIDFD_WAIT_BIT.store(2, Ordering::Relaxed);
            return Err(unsupported());
        }
        return Err(err);
    }
    if info.field(0) == 0 {
        // WNOHANG and no state change: siginfo was left zeroed.
        return Ok(None);
    }
    Ok(Some(siginfo_to_wait_status(&info)))
}

/// Deliver SIGKILL by pidfd (`pidfd_send_signal`): hits the exact child even
/// if its PID was recycled. `Err` with raw `ENOSYS` = kernel < 5.1.
pub fn pidfd_send_signal_kill(pidfd: libc::c_int) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pidfd,
            libc::SIGKILL,
            std::ptr::null::<libc::c_void>(),
            0u32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// exec ladder
// ---------------------------------------------------------------------------

/// Render a file descriptor as `/proc/self/fd/N` into a stack buffer and
/// return the NUL-terminated length, or None when it does not fit.
fn proc_fd_path(fd: libc::c_int, buf: &mut [u8; 32]) -> Option<usize> {
    if fd < 0 {
        return None;
    }
    const PREFIX: &[u8] = b"/proc/self/fd/";
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut digits = [0u8; 12];
    let mut n = fd;
    let mut len = 0;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    }
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let total = PREFIX.len() + len;
    if total + 1 > buf.len() {
        return None;
    }
    for (i, d) in digits[..len].iter().rev().enumerate() {
        buf[PREFIX.len() + i] = *d;
    }
    buf[total] = 0;
    Some(total)
}

/// Test hooks for the integration suite: force the ladder past a rung.
/// Compiled only under the `test-hooks` feature.
#[cfg(feature = "test-hooks")]
fn hook_disabled(name: &[u8]) -> bool {
    // libc marks getenv unsafe; it only reads `environ`, never mutates.
    unsafe { libc::getenv(name.as_ptr() as *const libc::c_char) != std::ptr::null_mut() }
}
#[cfg(not(feature = "test-hooks"))]
fn hook_disabled(_name: &[u8]) -> bool {
    false
}

/// Execute `fd` in place of the current process, trying:
///
/// 1. `execveat(fd, "", AT_EMPTY_PATH)` — no filesystem at all (Linux 3.19+),
/// 2. `execve("/proc/self/fd/N")` — works on 3.17/3.18 and odd emulation
///    layers, needs procfs.
///
/// `ENOSYS` (no execveat) and `ENOENT` (seen from emulation layers) fall
/// through to the next rung; every other errno is the real verdict and is
/// returned immediately, because the remaining rungs would only repeat it.
///
/// # Safety
/// On success this function never returns.
pub unsafe fn exec_fd(
    fd: libc::c_int,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    if !hook_disabled(b"MEMFD_NG_TEST_NO_EXECVEAT\0") {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            b"\0".as_ptr(),
            argv,
            envp,
            AT_EMPTY_PATH,
        );
        let err = Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::ENOENT) => {}
            _ => return Err(err),
        }
    }

    // FreeBSD: fexecve(2) is a kernel facility, not a procfs workaround.
    #[cfg(target_os = "freebsd")]
    {
        libc::fexecve(fd, argv, envp);
        let err = Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(err);
        }
    }

    if !hook_disabled(b"MEMFD_NG_TEST_NO_PROC\0") && proc_available() {
        let mut buf = [0u8; 32];
        if let Some(_len) = proc_fd_path(fd, &mut buf) {
            libc::execve(buf.as_ptr() as *const libc::c_char, argv, envp);
            let err = Error::last_os_error();
            // ENOENT: procfs vanished mid-ladder. ENOEXEC: under user-mode
            // emulators (qemu-user) this rung cannot work — the emulator
            // re-executes itself and the CLOEXEC fd is gone by the time it
            // re-opens the path. Both are environmental verdicts: the named
            // rung may still behave differently, so fall through.
            if !matches!(
                err.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::ENOEXEC)
            ) {
                return Err(err);
            }
        }
    }

    // Both fd rungs declined for environmental reasons. Raw ENOSYS is the
    // exhaustion marker (never an image verdict — real ENOEXEC etc. returned
    // above), allocation-free for the forked child.
    Err(Error::from_raw_os_error(libc::ENOSYS))
}

/// Execute a named path in place of the current process.
///
/// # Safety
/// On success this function never returns.
pub unsafe fn exec_path(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> Result<()> {
    libc::execve(path, argv, envp);
    Err(Error::last_os_error())
}

// ---------------------------------------------------------------------------
// tmpfs ladder (allocation-free: runs in the forked child)
// ---------------------------------------------------------------------------

const ST_NOEXEC_FLAG: libc::c_long = 0x0008;

/// Kernel-ABI statfs (what the raw syscall fills). The libc crate's statfs
/// struct has no f_flags on gnu targets, so the noexec check talks to the
/// kernel directly; this layout matches every 64-bit Linux ABI.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[repr(C)]
struct KernelStatfs {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [u32; 2],
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [i64; 4],
}

/// True when the mount holding `dir` forbids execution. Outside 64-bit
/// Linux there is no cheap ABI-stable check and this always answers false;
/// the exec itself then fails with EACCES and the ladder moves on.
fn mount_noexec(dir: *const libc::c_char) -> bool {
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    {
        let mut fs: KernelStatfs = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            libc::syscall(libc::SYS_statfs, dir, &mut fs as *mut KernelStatfs) == 0
        };
        ok && (fs.f_flags & ST_NOEXEC_FLAG) != 0
    }
    #[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
    {
        let _ = dir;
        false
    }
}

/// Append `n` as decimal ASCII. Returns the new length.
fn push_dec(buf: &mut [u8], mut len: usize, mut n: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut d = 0;
    if n == 0 {
        digits[0] = b'0';
        d = 1;
    }
    while n > 0 {
        digits[d] = b'0' + (n % 10) as u8;
        n /= 10;
        d += 1;
    }
    for byte in digits[..d].iter().rev() {
        if len < buf.len() {
            buf[len] = *byte;
            len += 1;
        }
    }
    len
}

/// Fill 16 random bytes without the heap: getrandom(2), /dev/urandom, then a
/// monotonic-clock mix as a last resort.
fn fill_random(out: &mut [u8; 16]) {
    #[cfg(target_os = "linux")]
    unsafe {
        let n = libc::syscall(libc::SYS_getrandom, out.as_mut_ptr(), out.len(), 0);
        if n == out.len() as libc::c_long {
            return;
        }
    }
    unsafe {
        let fd = libc::open(b"/dev/urandom\0".as_ptr() as *const libc::c_char, libc::O_RDONLY);
        if fd >= 0 {
            let ok = matches!(read_fill(fd, out), Ok(n) if n == out.len());
            libc::close(fd);
            if ok {
                return;
            }
        }
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        let mix = (ts.tv_nsec as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ ((libc::getpid() as u64) << 32)
            ^ (libc::getuid() as u64);
        out[..8].copy_from_slice(&mix.to_ne_bytes());
        out[8..].copy_from_slice(&mix.swap_bytes().to_ne_bytes());
    }
}

const FALLBACK_PREFIX: &[u8] = b".memfd-ng-";
const HEX: &[u8] = b"0123456789abcdef";

/// A NUL-terminated fallback-file path built on the stack, reported to the
/// parent so it can unlink the file after reaping the child.
pub struct NamedPath {
    bytes: [u8; 192],
    len: usize, // includes the NUL
}

impl NamedPath {
    pub fn as_ptr(&self) -> *const libc::c_char {
        self.bytes.as_ptr() as *const libc::c_char
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len - 1]
    }
}

/// An image staged on an executable filesystem.
pub struct TmpfsPayload {
    /// Read-only fd to feed the exec ladder, or -1 when only the named rung
    /// exists (no procfs to reopen through). The write fd is always closed
    /// before this is returned: the kernel refuses exec on a file that is
    /// open for writing (ETXTBSY) unless it is a memfd.
    pub fd: libc::c_int,
    /// The file's path, kept whenever a name was linked: the fd rungs get
    /// first try, but user-mode emulators can only exec the named rung.
    /// Reported to the parent, which unlinks it as soon as the exec outcome
    /// is known (success EOF, failure errno, or death).
    pub named: Option<NamedPath>,
}

/// Create and fill an image file on an executable filesystem.
///
/// With procfs available the write fd is swapped for a read-only one. The
/// name (when one was linked) is reported to the parent, which unlinks it as
/// soon as the exec outcome reaches it. Without procfs the write fd is
/// closed (the kernel's ETXTBSY rule) and the name is the named rung.
///
/// The whole function avoids the allocator so it is safe to run in a forked
/// child before exec, where another thread may hold a malloc lock.
pub fn tmpfs_payload(code: &[u8]) -> Result<TmpfsPayload> {
    unsafe {
        let uid = libc::getuid() as u64;
        let pid = libc::getpid() as u64;
        let mut rnd = [0u8; 16];
        fill_random(&mut rnd);
        let env = |name: &[u8]| libc::getenv(name.as_ptr() as *const libc::c_char);

        // XDG_RUNTIME_DIR first (conventionally a private 0700 tmpfs), then
        // TMPDIR or /tmp, /dev/shm, and ~/.cache only when HOME is set.
        let mut candidates: [(*const libc::c_char, bool); 4] = [
            (env(b"XDG_RUNTIME_DIR\0"), false),
            (env(b"TMPDIR\0"), true),
            (b"/dev/shm\0".as_ptr() as *const libc::c_char, false),
            (env(b"HOME\0"), true),
        ];
        candidates[1].1 = true; // fall back to /tmp when TMPDIR is unset
        let mut last_err: Option<Error> = None;

        for (dir, default_tmp) in candidates {
            let dir = if !dir.is_null() {
                dir
            } else if default_tmp {
                b"/tmp\0".as_ptr() as *const libc::c_char
            } else {
                continue; // variable unset: skip rather than guess
            };

            if mount_noexec(dir) {
                last_err.get_or_insert(Error::from_raw_os_error(libc::EACCES));
                continue;
            }

            // "<dir>/.memfd-ng-<uid>-<pid>-<32 hex>" on the stack.
            let mut path = [0u8; 192];
            let mut len = {
                let d = dir as *const u8;
                let mut l = 0usize;
                while *d.add(l) != 0 && l < path.len() - 64 {
                    path[l] = *d.add(l);
                    l += 1;
                }
                l
            };
            if len > 0 && path[len - 1] != b'/' {
                path[len] = b'/';
                len += 1;
            }
            if len + FALLBACK_PREFIX.len() + 1 + 20 + 1 + 20 + 1 + 32 >= path.len() {
                continue;
            }
            path[len..len + FALLBACK_PREFIX.len()].copy_from_slice(FALLBACK_PREFIX);
            len += FALLBACK_PREFIX.len();
            len = push_dec(&mut path, len, uid);
            path[len] = b'-';
            len += 1;
            len = push_dec(&mut path, len, pid);
            path[len] = b'-';
            len += 1;
            for byte in rnd.iter() {
                path[len] = HEX[(*byte >> 4) as usize];
                path[len + 1] = HEX[(*byte & 0xf) as usize];
                len += 2;
            }
            path[len] = 0;
            let cpath = path.as_ptr() as *const libc::c_char;

            // O_TMPFILE first (Linux 3.11+ on supporting filesystems): the
            // image's write phase then happens in an inode with no name at
            // all — a crash mid-write leaves nothing behind.
            if !hook_disabled(b"MEMFD_NG_TEST_NO_OTMPFILE\0") {
                let fd = libc::open(
                    dir,
                    libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                    0o700,
                );
                if fd >= 0 {
                    let staged = libc::fchmod(fd, 0o700) == 0 && write_all(fd, code).is_ok();
                    if !staged {
                        let err = Error::last_os_error();
                        // the inode dies here; there was never a name
                        libc::close(fd);
                        last_err.get_or_insert(err);
                    } else if proc_available() {
                        // Reopen read-only through procfs for the fd rungs,
                        // and link the anonymous inode into place so a named
                        // rung can take over if the fd rungs are refused
                        // (user-mode emulators re-exec themselves and lose
                        // CLOEXEC fds, so /proc/self/fd rungs cannot work
                        // there). The linkat-via-/proc form needs no
                        // privileges. The parent unlinks the name the moment
                        // the exec outcome is known.
                        let mut pbuf = [0u8; 32];
                        let mut ro = -1;
                        if proc_fd_path(fd, &mut pbuf).is_some() {
                            ro = libc::open(
                                pbuf.as_ptr() as *const libc::c_char,
                                libc::O_RDONLY | libc::O_CLOEXEC,
                            );
                        }
                        if ro >= 0 {
                            let linked = libc::linkat(
                                libc::AT_FDCWD,
                                pbuf.as_ptr() as *const libc::c_char,
                                libc::AT_FDCWD,
                                cpath,
                                AT_SYMLINK_FOLLOW,
                            ) == 0;
                            libc::close(fd);
                            if linked {
                                let mut bytes = [0u8; 192];
                                bytes[..path.len()].copy_from_slice(&path);
                                return Ok(TmpfsPayload {
                                    fd: ro,
                                    named: Some(NamedPath { bytes, len: len + 1 }),
                                });
                            }
                            // link refused (odd /proc mount): fd-only, the
                            // fd rungs carry it on real kernels
                            return Ok(TmpfsPayload { fd: ro, named: None });
                        }
                        let err = Error::last_os_error();
                        libc::close(fd);
                        last_err.get_or_insert(err);
                    } else {
                        // No procfs: link the anonymous inode into place so
                        // the named rung can exec it — the /proc-less linkat
                        // dance. Needs CAP_DAC_READ_SEARCH; without it this
                        // fails closed into named staging below. The image
                        // gains a name only at the moment it must be execed
                        // by name, and the write handle is closed first so
                        // the named exec cannot hit ETXTBSY.
                        let linked = libc::linkat(
                            fd,
                            b"\0".as_ptr() as *const libc::c_char,
                            libc::AT_FDCWD,
                            cpath,
                            AT_EMPTY_PATH,
                        ) == 0;
                        if linked {
                            libc::close(fd);
                            let mut bytes = [0u8; 192];
                            bytes[..path.len()].copy_from_slice(&path);
                            return Ok(TmpfsPayload {
                                fd: -1,
                                named: Some(NamedPath { bytes, len: len + 1 }),
                            });
                        }
                        let err = Error::last_os_error();
                        libc::close(fd); // still unnamed: the inode dies here
                        last_err.get_or_insert(err);
                    }
                }
                // O_TMPFILE refused (old kernel, unsupported fs, EMFILE...):
                // fall through to named staging in this same directory.
            }

            // Test hook: forbid the named-staging flow, so a successful
            // staging can only have come from the O_TMPFILE path.
            #[cfg(feature = "test-hooks")]
            if hook_disabled(b"MEMFD_NG_TEST_NO_NAMED_STAGE\0") {
                last_err.get_or_insert(Error::from_raw_os_error(libc::EPERM));
                continue;
            }

            let open_flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;
            let mut fd = libc::open(cpath, open_flags, 0o700);
            if fd < 0 {
                // 128 bits of randomness collide essentially never; one retry
                // covers even a directory someone is throwing garbage into.
                fill_random(&mut rnd);
                let mut hlen = len - 32;
                for byte in rnd.iter() {
                    path[hlen] = HEX[(byte >> 4) as usize];
                    path[hlen + 1] = HEX[(byte & 0xf) as usize];
                    hlen += 2;
                }
                fd = libc::open(cpath, open_flags, 0o700);
            }
            if fd < 0 {
                last_err.get_or_insert(Error::last_os_error());
                continue;
            }

            // open(2)'s mode is filtered by the umask, which may strip the
            // execute bit; fchmod(2) is not, so set it explicitly.
            if libc::fchmod(fd, 0o700) != 0 {
                let err = Error::last_os_error();
                libc::close(fd);
                libc::unlink(cpath);
                last_err.get_or_insert(err);
                continue;
            }
            if let Err(err) = write_all(fd, code) {
                libc::close(fd);
                libc::unlink(cpath);
                last_err.get_or_insert(err);
                continue;
            }

            // Swap the write fd for a read-only one: the kernel refuses to
            // exec a file that is open for writing (ETXTBSY) unless it is a
            // memfd. With procfs this is a plain reopen by /proc/self/fd.
            // The name is KEPT: the fd rungs exec it first, but emulators
            // can only exec the named rung, and the parent unlinks the name
            // as soon as the exec outcome reaches it.
            if proc_available() {
                let mut pbuf = [0u8; 32];
                if proc_fd_path(fd, &mut pbuf).is_some() {
                    let ro = libc::open(
                        pbuf.as_ptr() as *const libc::c_char,
                        libc::O_RDONLY | libc::O_CLOEXEC,
                    );
                    if ro >= 0 {
                        libc::close(fd);
                        let mut bytes = [0u8; 192];
                        bytes[..path.len()].copy_from_slice(&path);
                        return Ok(TmpfsPayload {
                            fd: ro,
                            named: Some(NamedPath { bytes, len: len + 1 }),
                        });
                    }
                }
                let err = Error::last_os_error();
                libc::close(fd);
                libc::unlink(cpath);
                last_err.get_or_insert(err);
                continue;
            }

            // No procfs: no fd-based rung is reachable, so close the write
            // fd (otherwise the named exec gets ETXTBSY) and hand the name
            // to the caller. `len` is the string length; +1 counts the NUL.
            libc::close(fd);
            let mut bytes = [0u8; 192];
            bytes[..path.len()].copy_from_slice(&path);
            return Ok(TmpfsPayload {
                fd: -1,
                named: Some(NamedPath { bytes, len: len + 1 }),
            });
        }

        Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::Unsupported, "no executable tmpfs")))
    }
}

// ---------------------------------------------------------------------------
// CLOEXEC-pipe protocol
// ---------------------------------------------------------------------------

/// A message the forked child sends before exec or exit.
#[derive(Debug)]
pub enum PipeMsg {
    /// Child execed successfully and the pipe closed: EOF.
    Success,
    /// Child failed to exec; carries the real errno.
    Failure(i32),
    /// Child is about to exec a still-named tmpfs file (no-procfs corner);
    /// the parent owns the name now and must unlink it after reaping.
    NamedPath(Vec<u8>),
}

/// Write the errno message: 4 big-endian errno bytes + `NOEX` footer.
pub fn pipe_write_errno(pipe: libc::c_int, err: &Error) {
    let mut msg = [0u8; 8];
    msg[..4].copy_from_slice(&(err.raw_os_error().unwrap_or(libc::EIO) as u32).to_be_bytes());
    msg[4..].copy_from_slice(b"NOEX");
    pipe_write_all(pipe, &msg);
}

/// Write the named-path message: 2 big-endian length bytes + `PATH` footer +
/// the path bytes (no NUL). Only used in the no-procfs corner.
pub fn pipe_write_named_path(pipe: libc::c_int, path: &[u8]) {
    if path.len() > u16::MAX as usize {
        return;
    }
    let mut head = [0u8; 6];
    head[..2].copy_from_slice(&(path.len() as u16).to_be_bytes());
    head[2..].copy_from_slice(b"PATH");
    pipe_write_all(pipe, &head);
    pipe_write_all(pipe, path);
}

fn pipe_write_all(pipe: libc::c_int, mut buf: &[u8]) {
    while !buf.is_empty() {
        let n = unsafe { libc::write(pipe, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue;
            }
            break; // parent died; nothing left to tell
        }
        if n == 0 {
            break;
        }
        buf = &buf[n as usize..];
    }
}

/// Read one message from the CLOEXEC pipe, looping over EINTR.
///
/// Wire shapes (headers are read 6 bytes at a time so the PATH image is
/// never overshot):
/// - failure: `[4B errno BE]["NOEX"]` — 8 bytes
/// - named path: `[2B len BE]["PATH"] + len bytes`
pub fn pipe_read(pipe: libc::c_int) -> Result<PipeMsg> {
    let mut head = [0u8; 8];
    let mut got = 0;
    while got < 6 {
        let n = cvt_ssize(unsafe {
            libc::read(pipe, head[got..].as_mut_ptr() as *mut libc::c_void, 6 - got)
        })?;
        if n == 0 {
            if got == 0 {
                return Ok(PipeMsg::Success);
            }
            return Err(Error::new(ErrorKind::InvalidData, "short read on exec pipe"));
        }
        got += n;
    }

    if &head[2..6] == b"PATH" {
        let len = u16::from_be_bytes([head[0], head[1]]) as usize;
        let mut path = vec![0u8; len];
        let n = read_fill(pipe, &mut path)?;
        path.truncate(n);
        return Ok(PipeMsg::NamedPath(path));
    }

    while got < 8 {
        let n = cvt_ssize(unsafe {
            libc::read(pipe, head[got..].as_mut_ptr() as *mut libc::c_void, 8 - got)
        })?;
        if n == 0 {
            return Err(Error::new(ErrorKind::InvalidData, "short read on exec pipe"));
        }
        got += n;
    }
    if &head[4..8] == b"NOEX" {
        let code = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as i32;
        return Ok(PipeMsg::Failure(code));
    }
    Err(Error::new(ErrorKind::InvalidData, "bad exec pipe message"))
}
