//! Raw syscall layer: memfd creation with a capability ladder, payload
//! sealing, a three-rung exec ladder, and the CLOEXEC-pipe protocol that
//! carries the real errno (or a fallback-file path) from the forked child
//! back to the parent.
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
pub const MFD_EXEC: libc::c_uint = 0x0010;

pub const F_ADD_SEALS: libc::c_int = 1033;
pub const F_SEAL_SHRINK: libc::c_int = 0x0001;
pub const F_SEAL_GROW: libc::c_int = 0x0002;
pub const F_SEAL_WRITE: libc::c_int = 0x0008;
pub const SEALS_FULL: libc::c_int = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

pub const AT_EMPTY_PATH: libc::c_int = 0x1000;

// ---------------------------------------------------------------------------
// Capability probes
// ---------------------------------------------------------------------------

// 0 = unknown, 1 = supported, 2 = unsupported. Races are harmless: the probe
// syscall is idempotent and its only side effect is one closed fd.
static EXEC_BIT: AtomicU8 = AtomicU8::new(0);
static SEAL_BIT: AtomicU8 = AtomicU8::new(0);
static PROC_OK: AtomicU8 = AtomicU8::new(0);

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
/// is added so the payload can be sealed once fully written.
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

/// Seal the memfd against shrinking, growing and writing. Returns false when
/// the kernel has no sealing support (the payload still runs, it just stays
/// modifiable through writable fds).
pub fn add_seals(fd: libc::c_int) -> bool {
    unsafe { libc::fcntl(fd, F_ADD_SEALS, SEALS_FULL) == 0 }
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
            return Err(Error::new(ErrorKind::WriteZero, "failed to write payload"));
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
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(err);
            }
        }
    }

    Err(Error::new(
        ErrorKind::Unsupported,
        "no fd-based exec rung succeeded",
    ))
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

/// A payload staged on an executable filesystem.
pub struct TmpfsPayload {
    /// Read-only fd to feed the exec ladder, or -1 when only the named rung
    /// exists (no procfs to reopen through). The write fd is always closed
    /// before this is returned: the kernel refuses exec on a file that is
    /// open for writing (ETXTBSY) unless it is a memfd.
    pub fd: libc::c_int,
    /// The file's path, kept only when procfs is unavailable and the name is
    /// therefore the final exec rung. The parent unlinks it after reaping.
    pub named: Option<NamedPath>,
}

/// Create and fill a payload file on an executable filesystem.
///
/// With procfs available the write fd is swapped for a read-only one and the
/// name is unlinked immediately: every exec rung is fd-based, so nothing is
/// left to clean up. Without procfs the write fd is closed (the kernel's
/// ETXTBSY rule) and the name is returned for the named rung plus the
/// parent-side unlink after reap.
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
            if proc_available() {
                let mut pbuf = [0u8; 32];
                if proc_fd_path(fd, &mut pbuf).is_some() {
                    let ro = libc::open(
                        pbuf.as_ptr() as *const libc::c_char,
                        libc::O_RDONLY | libc::O_CLOEXEC,
                    );
                    if ro >= 0 {
                        libc::close(fd);
                        // The name is dead weight now: both rungs are
                        // fd-based and both work on an unlinked inode.
                        libc::unlink(cpath);
                        return Ok(TmpfsPayload { fd: ro, named: None });
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
/// Wire shapes (headers are read 6 bytes at a time so the PATH payload is
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
