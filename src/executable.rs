//! The main type: a `std::process::Command`-shaped interface to an in-memory
//! executable.

use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{Error, ErrorKind, Result};
use std::mem::MaybeUninit;
use std::os::unix::prelude::{AsRawFd, OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::os::unix::io::FromRawFd;

use libc::{c_int, sigemptyset, signal};

use crate::{
    anon_pipe::anon_pipe,
    child::Child,
    command_env::CommandEnv,
    cvt::{cvt, cvt_r},
    file_desc::FileDesc,
    output::Output,
    process::{ExitStatus, Process},
    stdio::{ChildPipes, Stdio, StdioPipes},
    sys,
};

/// A set of `F_SEAL_*` bits for [`MemFdExecutable::seals`]. The crate
/// default is `SealFlags::full()` (`SHRINK | GROW | WRITE`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SealFlags(libc::c_int);

impl SealFlags {
    /// The file cannot be reduced in size (`F_SEAL_SHRINK`).
    pub const SHRINK: SealFlags = SealFlags(0x0001);
    /// The file cannot grow (`F_SEAL_GROW`).
    pub const GROW: SealFlags = SealFlags(0x0002);
    /// The contents cannot be modified through any writable handle
    /// (`F_SEAL_WRITE`).
    pub const WRITE: SealFlags = SealFlags(0x0008);
    /// Like `WRITE`, but handles that were already writable keep working
    /// (`F_SEAL_FUTURE_WRITE`, kernel 5.1+).
    pub const FUTURE_WRITE: SealFlags = SealFlags(0x0010);

    /// The default seal set: `SHRINK | GROW | WRITE`.
    pub const fn full() -> SealFlags {
        SealFlags(sys::SEALS_FULL)
    }

    /// The raw `F_SEAL_*` bits.
    pub const fn bits(self) -> libc::c_int {
        self.0
    }

    /// True when every bit of `other` is set in `self`.
    pub const fn contains(self, other: SealFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for SealFlags {
    type Output = SealFlags;
    fn bitor(self, rhs: SealFlags) -> SealFlags {
        SealFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for SealFlags {
    fn bitor_assign(&mut self, rhs: SealFlags) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for SealFlags {
    type Output = SealFlags;
    fn bitand(self, rhs: SealFlags) -> SealFlags {
        SealFlags(self.0 & rhs.0)
    }
}

impl std::ops::Not for SealFlags {
    type Output = SealFlags;
    fn not(self) -> SealFlags {
        SealFlags(!self.0 & sys::SEALS_FULL)
    }
}

/// This is the main struct used to create an in-memory only executable.
/// Wherever possible, it is a drop-in replacement for the standard library's
/// `process::Command` struct; the one difference is that the executable's
/// bytes are supplied by the caller instead of a filesystem path.
///
/// The image lands in a `memfd_create(2)` file, is sealed against
/// modification when the kernel allows, and is executed with
/// `execveat(2)`/`AT_EMPTY_PATH` — no file on disk is needed. Kernels or
/// emulation layers without fd-based exec get an allocation-free tmpfs
/// ladder that never writes to stderr (`XDG_RUNTIME_DIR` → tmp dir →
/// `/dev/shm` → `~/.cache`), each candidate checked against `ST_NOEXEC`
/// first.
///
/// # Examples
///
/// Run a binary entirely from memory, capturing its output:
///
/// ```no_run
/// use memfd_ng::{MemFdExecutable, Stdio};
///
/// let code = std::fs::read("/bin/echo").unwrap();
/// let output = MemFdExecutable::new("echo", &code)
///     .arg("hello from memory")
///     .stdout(Stdio::piped())
///     .output()
///     .expect("failed to execute process");
///
/// assert!(output.status.success());
/// assert_eq!(output.stdout, b"hello from memory\n");
/// ```
pub struct MemFdExecutable<'a> {
    /// The contents of the ELF executable to run. This content can be
    /// included in the file using the `include_bytes!()` macro, or you can do
    /// fancy things like read it in from a socket.
    code: &'a [u8],
    /// The name of the program: used as the memfd name (visible in
    /// `/proc/<pid>/exe` for the child) and as the fallback tmpfs file name.
    name: String,
    /// The name of the program; this value is the argv\[0\] argument to the
    /// binary when executed. If the program expects something specific here,
    /// that value should be used, otherwise any name will do.
    program: CString,
    /// The arguments to the program, excluding the program name
    args: Vec<CString>,
    /// The whole argv array, including the program name
    argv: Argv,
    /// The environment variables to set for the program
    env: CommandEnv,
    /// The current working directory to set for the program
    cwd: Option<CString>,
    /// The program's stdin handle
    pub stdin: Option<Stdio>,
    /// The program's stdout handle
    pub stdout: Option<Stdio>,
    /// The program's stderr handle
    pub stderr: Option<Stdio>,
    /// Holdover from Command: whether there was a NUL in the arguments or not
    saw_nul: bool,
    /// Whether to seal the memfd after writing (default: yes, when supported)
    sealed: bool,
    /// Which seals to apply (default: SHRINK | GROW | WRITE)
    seal_flags: SealFlags,
    /// Stage the image on hugetlbfs instead of an ordinary memfd
    hugetlb: bool,
    /// Run the child in a new session (setsid(2))
    setsid: bool,
    /// Run the child in a specific process group (setpgid(0, pgid))
    process_group: Option<i32>,
    /// Prepared memfd cache: written and sealed once, executed many times
    prepared: Option<Prepared>,
}

#[derive(Debug)]
struct Prepared {
    fd: FileDesc,
    sealed: bool,
    hugetlb: bool,
}

struct Argv(Vec<CString>);

impl std::fmt::Debug for MemFdExecutable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // redact the image: Debug on a prepared 9 MiB image would otherwise
        // dump the whole thing into logs
        f.debug_struct("MemFdExecutable")
            .field("code", &format!("[{} bytes]", self.code.len()))
            .field("name", &self.name)
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env)
            .field("cwd", &self.cwd)
            .field("stdin", &self.stdin)
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("saw_nul", &self.saw_nul)
            .field("sealed", &self.sealed)
            .field("seal_flags", &self.seal_flags)
            .field("hugetlb", &self.hugetlb)
            .field("setsid", &self.setsid)
            .field("process_group", &self.process_group)
            .field("prepared", &self.prepared.is_some())
            .finish()
    }
}

fn os2c(s: &OsStr, saw_nul: &mut bool) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_e| {
        *saw_nul = true;
        CString::new("<string-with-nul>").unwrap_or_default()
    })
}

fn construct_envp(env: std::collections::BTreeMap<OsString, OsString>, saw_nul: &mut bool) -> Vec<CString> {
    let mut result = Vec::with_capacity(env.len());
    for (mut k, v) in env {
        // Reserve additional space for '=' and the null terminator
        k.reserve_exact(v.len() + 2);
        k.push("=");
        k.push(&v);

        // Add the new entry into the array
        if let Ok(item) = CString::new(k.into_vec()) {
            result.push(item);
        } else {
            *saw_nul = true;
        }
    }
    result
}

impl<'a> MemFdExecutable<'a> {
    /// Create a new MemFdExecutable with the given name and code. The name is
    /// the name of the program, and becomes the memfd name (the child's
    /// `/proc/<pid>/exe` shows `/memfd:<name>`); the first argv entry stays
    /// this name too, so use `set_program` if the program needs a specific
    /// argv\[0\] distinct from the image name.
    ///
    /// # Examples
    ///
    /// You can run code that is included directly in your executable with
    /// `include_bytes!()`:
    ///
    /// ```no_run
    /// use memfd_ng::MemFdExecutable;
    ///
    /// let code = include_bytes!("/bin/echo");
    ///
    /// let status = MemFdExecutable::new("echo", code)
    ///     .arg("hi")
    ///     .status()
    ///     .expect("failed to execute process");
    /// ```
    pub fn new<S: AsRef<OsStr>>(name: S, code: &'a [u8]) -> Self {
        let mut saw_nul = false;
        let name_cstr = os2c(name.as_ref(), &mut saw_nul);
        Self {
            code,
            name: name.as_ref().to_string_lossy().into_owned(),
            program: name_cstr.clone(),
            args: vec![name_cstr.clone()],
            argv: Argv(vec![name_cstr]),
            env: Default::default(),
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
            saw_nul,
            sealed: true,
            seal_flags: SealFlags::full(),
            hugetlb: false,
            setsid: false,
            process_group: None,
            prepared: None,
        }
    }

    /// Add an argument to the program. This is equivalent to `Command::arg()`.
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        let arg = os2c(arg.as_ref(), &mut self.saw_nul);
        self.argv.0.push(arg.clone());
        self.args.push(arg);
        self
    }

    /// Add multiple arguments to the program. This is equivalent to `Command::args()`.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg.as_ref());
        }
        self
    }

    /// Add an environment variable to the program. This is equivalent to `Command::env()`.
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.env_mut().set(key.as_ref(), val.as_ref());
        self
    }

    /// Add multiple environment variables to the program. This is equivalent
    /// to `Command::envs()`.
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (ref key, ref val) in vars {
            self.env_mut().set(key.as_ref(), val.as_ref());
        }
        self
    }

    /// Remove an environment variable from the program. This is equivalent to
    /// `Command::env_remove()`.
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Self {
        self.env_mut().remove(key.as_ref());
        self
    }

    /// Clear all environment variables from the program. This is equivalent
    /// to `Command::env_clear()`.
    pub fn env_clear(&mut self) -> &mut Self {
        self.env_mut().clear();
        self
    }

    /// Set the current working directory for the program. This is equivalent
    /// to `Command::current_dir()`.
    pub fn cwd<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.cwd = Some(os2c(dir.as_ref().as_ref(), &mut self.saw_nul));
        self
    }

    /// Set the stdin handle for the program. This is equivalent to
    /// `Command::stdin()`. The default is to inherit the current process's
    /// stdin. Note that this `Stdio` is not exactly the same as
    /// `process::Stdio`, but it is feature-equivalent.
    ///
    /// # Examples
    ///
    /// This example creates a `cat` process that will read in the contents
    /// passed to its stdin handle and write them to a null stdout (i.e. they
    /// will be discarded). The same methodology can be used to read from
    /// stderr/stdout.
    ///
    /// ```no_run
    /// use std::thread::spawn;
    /// use std::io::Write;
    ///
    /// use memfd_ng::{MemFdExecutable, Stdio};
    ///
    /// let code = include_bytes!("/bin/cat");
    /// let mut cat_cmd = MemFdExecutable::new("cat", code)
    ///    .stdin(Stdio::piped())
    ///    .stdout(Stdio::null())
    ///    .spawn()
    ///    .expect("failed to spawn cat");
    ///
    /// let mut cat_stdin = cat_cmd.stdin.take().expect("failed to open stdin");
    /// spawn(move || {
    ///    cat_stdin.write_all(b"hello world").expect("failed to write to stdin");
    /// });
    /// ```
    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdin = Some(cfg.into());
        self
    }

    /// Set the stdout handle for the program. This is equivalent to
    /// `Command::stdout()`.
    ///
    /// # Arguments
    /// * `cfg` - The configuration for the stdout handle. This will usually
    ///   be one of the following:
    ///   * `Stdio::inherit()` - Inherit the current process's stdout handle
    ///   * `Stdio::piped()` - Create a pipe to the child process's stdout.
    ///     This can be read.
    ///   * `Stdio::null()` - Discard all output to stdout
    ///
    /// # Examples
    ///
    /// This example creates a `cat` process that will read from its stdin and
    /// write to its stdout, both piped. The same methodology can be used to
    /// read from stderr/stdout.
    ///
    /// ```
    /// use std::thread::spawn;
    /// use std::fs::read;
    /// use std::io::{Read, Write};
    ///
    /// use memfd_ng::{MemFdExecutable, Stdio};
    ///
    /// let mut cat = MemFdExecutable::new("cat", &read("/bin/cat").unwrap_or_default())
    ///     .stdin(Stdio::piped())
    ///     .stdout(Stdio::piped())
    ///     .spawn()
    ///     .expect("failed to spawn cat");
    ///
    /// let mut cat_stdin = cat.stdin.take().expect("failed to open stdin");
    /// let mut cat_stdout = cat.stdout.take().expect("failed to open stdout");
    ///
    /// spawn(move || {
    ///    cat_stdin.write_all(b"hello world").expect("failed to write to stdin");
    /// });
    ///
    /// let mut output = Vec::new();
    /// cat_stdout.read_to_end(&mut output).expect("failed to read from stdout");
    /// assert_eq!(output, b"hello world");
    /// cat.wait().expect("failed to wait on cat");
    /// ```
    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdout = Some(cfg.into());
        self
    }

    /// Set the stderr handle for the program. This is equivalent to
    /// `Command::stderr()`.
    ///
    /// # Arguments
    /// * `cfg` - The configuration for the stderr handle. This will usually
    ///   be one of the following:
    ///   * `Stdio::inherit()` - Inherit the current process's stderr handle
    ///   * `Stdio::piped()` - Create a pipe to the child process's stderr.
    ///     This can be read.
    ///   * `Stdio::null()` - Discard all output to stderr
    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stderr = Some(cfg.into());
        self
    }

    /// Create the memfd now: write the image and, when the kernel supports
    /// it, seal it against the configured [`SealFlags`] (default: shrink,
    /// grow and write).
    ///
    /// Spawning prepares the image anyway, but calling this once makes
    /// every later `spawn()` skip the write entirely: the sealed image is
    /// executed in place, which is the fast path for programs that spawn the
    /// same image repeatedly. Sealing also means nobody with a writable fd
    /// (including our own children) can swap the code between spawns.
    ///
    /// Preparing again simply replaces the previous image.
    pub fn prepare(&mut self) -> Result<&mut Self> {
        // hugetlb(true) is a preference, never a hard requirement: every
        // hugetlb failure (kernel without MFD_HUGETLB, unalignable size,
        // no preallocated huge pages) degrades to an ordinary memfd.
        if self.hugetlb && self.prepare_hugetlb().is_ok() {
            return Ok(self);
        }
        let name = os2c(OsStr::new(&self.name), &mut self.saw_nul);
        let fd = sys::memfd_create(name.as_ptr(), self.sealed)?;
        if !sys::is_regular_file(fd) {
            let err = Error::from_raw_os_error(libc::EINVAL);
            unsafe { libc::close(fd) };
            return Err(err);
        }
        sys::write_all(fd, self.code)?;
        let sealed =
            self.sealed && self.seal_flags.bits() != 0 && sys::add_seals(fd, self.seal_flags.bits());
        self.prepared = Some(Prepared {
            fd: unsafe { FileDesc::from_raw_fd(fd) },
            sealed,
            hugetlb: false,
        });
        Ok(self)
    }

    /// Prepare the image on hugetlbfs: create with `MFD_HUGETLB`, then pad
    /// the image up to the huge-page size (hugetlbfs refuses unaligned
    /// sizes with `EINVAL`; loaders ignore bytes past the last PT_LOAD, so
    /// zero padding does not change the program). Err means degrade to the
    /// ordinary memfd path.
    fn prepare_hugetlb(&mut self) -> Result<()> {
        let name = os2c(OsStr::new(&self.name), &mut self.saw_nul);
        let fd = sys::memfd_create_hugetlb(name.as_ptr())?;
        let bsize = match sys::hugetlb_page_size(fd) {
            Some(bsize) if bsize > 0 => bsize as usize,
            _ => {
                unsafe { libc::close(fd) };
                return Err(Error::from_raw_os_error(libc::ENOSYS));
            }
        };
        let write_ok = if self.code.len() % bsize == 0 {
            sys::write_all(fd, self.code).is_ok()
        } else {
            let mut padded = Vec::with_capacity(self.code.len() + bsize);
            padded.extend_from_slice(self.code);
            padded.resize(self.code.len() + (bsize - self.code.len() % bsize), 0);
            sys::write_all(fd, &padded).is_ok()
        };
        if !write_ok {
            unsafe { libc::close(fd) };
            return Err(Error::from_raw_os_error(libc::EIO));
        }
        // Sealing is refused on hugetlbfs (EPERM, observed on 6.18); the
        // image runs unsealed, and is_sealed() reports that honestly.
        let sealed =
            self.sealed && self.seal_flags.bits() != 0 && sys::add_seals(fd, self.seal_flags.bits());
        self.prepared = Some(Prepared {
            fd: unsafe { FileDesc::from_raw_fd(fd) },
            sealed,
            hugetlb: true,
        });
        Ok(())
    }

    /// Whether an image is already prepared (see [`prepare`]).
    pub fn is_prepared(&self) -> bool {
        self.prepared.is_some()
    }

    /// Whether the prepared image (if any) ended up sealed.
    pub fn is_sealed(&self) -> bool {
        self.prepared.as_ref().map(|p| p.sealed).unwrap_or(false)
    }

    /// Whether the prepared image (if any) lives on hugetlbfs. Only true
    /// when `hugetlb(true)` was set AND the kernel accepted the facility;
    /// otherwise the image degraded to an ordinary memfd.
    pub fn is_hugetlb(&self) -> bool {
        self.prepared.as_ref().map(|p| p.hugetlb).unwrap_or(false)
    }

    /// Toggle image sealing. Sealing is on by default; kernels without
    /// sealing support skip it without surfacing an error. Changing this invalidates any
    /// prepared image: the next spawn (or `prepare`) stages a fresh image
    /// under the new setting.
    pub fn sealed(&mut self, on: bool) -> &mut Self {
        if self.sealed != on {
            self.sealed = on;
            self.prepared = None;
        }
        self
    }

    /// Choose exactly which seals land on the prepared image. The default
    /// is [`SealFlags::full()`]; pass e.g. `SealFlags::FUTURE_WRITE` to keep
    /// already-open writable handles working while blocking new writes, or
    /// `SealFlags::default()` (no bits) to keep the memfd sealable without
    /// actually sealing anything under `sealed(true)`. Changing this
    /// invalidates any prepared image.
    pub fn seals(&mut self, flags: SealFlags) -> &mut Self {
        if self.seal_flags != flags {
            self.seal_flags = flags;
            self.prepared = None;
        }
        self
    }

    /// Prefer staging the image on hugetlbfs (`MFD_HUGETLB`, kernel 4.14+)
    /// instead of an ordinary memfd. Intended for very large images on
    /// machines with preallocated huge pages. Every hugetlb failure degrades
    /// to an ordinary memfd, so a spawn never fails *because of* this
    /// setting; check [`is_hugetlb`] after `prepare()` to see what actually
    /// happened. Note that kernels refuse to seal hugetlb memfds, so a
    /// hugetlb image is unsealed even under `sealed(true)`. Changing this
    /// invalidates any prepared image.
    pub fn hugetlb(&mut self, on: bool) -> &mut Self {
        if self.hugetlb != on {
            self.hugetlb = on;
            self.prepared = None;
        }
        self
    }

    /// Run the child in a new session (`setsid(2)`), detaching it from the
    /// controlling terminal. The call happens in the forked child before
    /// exec; a failure surfaces as the real errno through the normal
    /// exec-failure channel. Note the kernel refuses `setpgid(2)` on a
    /// session leader, so combining this with [`process_group`] fails the
    /// spawn with `EPERM` — they are alternatives, not layers.
    ///
    /// [`process_group`]: MemFdExecutable::process_group
    pub fn setsid(&mut self, on: bool) -> &mut Self {
        self.setsid = on;
        self
    }

    /// Run the child in process group `pgid` (`setpgid(0, pgid)`). Passing
    /// `0` makes the child a leader of its own new group — the same meaning
    /// as `std::process::Command::process_group(0)`. A failure surfaces as
    /// the real errno through the normal exec-failure channel.
    pub fn process_group(&mut self, pgid: i32) -> &mut Self {
        self.process_group = Some(pgid);
        self
    }

    /// Filesystem path of the prepared memfd (`/proc/self/fd/N`), when one is
    /// prepared and procfs is available. The path is only valid while this
    /// struct (or a running child) keeps the fd open.
    pub fn memfd_path(&self) -> Option<PathBuf> {
        if !sys::proc_available() {
            return None;
        }
        self.prepared
            .as_ref()
            .map(|p| PathBuf::from(format!("/proc/self/fd/{}", p.fd.as_raw_fd())))
    }

    /// Spawn the program as a child process. This is equivalent to
    /// `Command::spawn()`.
    pub fn spawn(&mut self) -> Result<Child> {
        if self.saw_nul() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "nul byte found in provided data",
            ));
        }

        // Everything the forked child needs is built BEFORE the fork: the
        // child runs without touching the allocator, so it cannot deadlock
        // on a malloc lock another thread may hold.
        let captured_env = self.capture_env();
        let argv: Vec<*const libc::c_char> = self
            .get_argv()
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        // borrowed from captured_env, which stays alive for the whole spawn
        let envp: Option<Vec<*const libc::c_char>> = captured_env.as_ref().map(|v| {
            v.iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect()
        });
        let (ours, theirs) = self.setup_io(Stdio::Inherit, true)?;
        let (input, output) = anon_pipe()?;

        // Prepare the image in the parent so the forked child only has to
        // call exec. A kernel without memfd support is not fatal: the child
        // falls back to the tmpfs ladder on its own.
        let memfd_fd = match self.ensure_prepared() {
            Ok(p) => p.fd.as_raw_fd(),
            Err(_) => -1,
        };

        let quiet = env::var_os("NO_MEMFDEXEC").map(|v| v == "1").unwrap_or(false);

        // Whatever happens after the fork is almost for sure going to touch
        // or look at the environment in one way or another. The fork happens
        // here; the child never returns from do_exec on success.
        let (pid, pidfd) = self.do_fork()?;

        if pid == 0 {
            drop(input);
            let err = unsafe {
                match self.do_exec(
                    memfd_fd,
                    quiet,
                    theirs,
                    &argv,
                    envp.as_deref(),
                    output.as_raw_fd(),
                ) {
                    Ok(()) => unreachable!("do_exec either execs or fails"),
                    Err(err) => err,
                }
            };
            sys::pipe_write_errno(output.as_raw_fd(), &err);
            unsafe { libc::_exit(127) };
        }

        drop(output);

        let mut p = unsafe { Process::new(pid, pidfd) };
        let mut named_fallback: Option<PathBuf> = None;

        // loop to handle EINTR and the (no-procfs) named-path message
        loop {
            match sys::pipe_read(input.as_raw_fd()) {
                Ok(sys::PipeMsg::Success) => {
                    // The child execed (or died trying); any still-named
                    // fallback file is ours to remove now.
                    if let Some(path) = &named_fallback {
                        let _ = std::fs::remove_file(path);
                    }
                    let mut child = Child::new(p, ours);
                    child.named_fallback = None;
                    return Ok(child);
                }
                Ok(sys::PipeMsg::NamedPath(path)) => {
                    named_fallback = Some(PathBuf::from(std::ffi::OsString::from_vec(path)));
                }
                Ok(sys::PipeMsg::Failure(code)) => {
                    // A still-named fallback file nobody execed is ours to
                    // remove; the child could not.
                    if let Some(path) = &named_fallback {
                        let _ = std::fs::remove_file(path);
                    }
                    let _ = p.wait();
                    return Err(Error::from_raw_os_error(code));
                }
                Err(e) => {
                    if let Some(path) = &named_fallback {
                        let _ = std::fs::remove_file(path);
                    }
                    let _ = p.wait();
                    return Err(e);
                }
            }
        }
    }

    /// Spawn the program as a child process and wait for it to complete,
    /// obtaining the output and exit status. This is equivalent to
    /// `Command::output()`.
    pub fn output(&mut self) -> Result<Output> {
        self.spawn()?.wait_with_output()
    }

    /// Spawn the program as a child process and wait for it to complete,
    /// obtaining the exit status. This is equivalent to `Command::status()`.
    pub fn status(&mut self) -> Result<ExitStatus> {
        self.spawn()?.wait()
    }

    /// Set the program name (argv\[0\]) to a new value.
    ///
    /// # Arguments
    /// * `program` - The new value for argv\[0\]
    pub fn set_program(&mut self, program: &OsStr) {
        let arg = os2c(program, &mut self.saw_nul);
        self.program = arg.clone();
        self.argv.0[0] = arg.clone();
        self.args[0] = arg;
    }

    fn env_mut(&mut self) -> &mut CommandEnv {
        &mut self.env
    }

    fn setup_io(&self, default: Stdio, needs_stdin: bool) -> Result<(StdioPipes, ChildPipes)> {
        let null = Stdio::Null;
        let default_stdin = if needs_stdin { &default } else { &null };
        let stdin = self.stdin.as_ref().unwrap_or(default_stdin);
        let stdout = self.stdout.as_ref().unwrap_or(&default);
        let stderr = self.stderr.as_ref().unwrap_or(&default);
        let (their_stdin, our_stdin) = stdin.to_child_stdio(true)?;
        let (their_stdout, our_stdout) = stdout.to_child_stdio(false)?;
        let (their_stderr, our_stderr) = stderr.to_child_stdio(false)?;
        let ours = StdioPipes {
            stdin: our_stdin,
            stdout: our_stdout,
            stderr: our_stderr,
        };
        let theirs = ChildPipes {
            stdin: their_stdin,
            stdout: their_stdout,
            stderr: their_stderr,
        };
        Ok((ours, theirs))
    }

    fn saw_nul(&self) -> bool {
        self.saw_nul
    }

    /// Get the current working directory for the child process.
    pub fn get_cwd(&self) -> &Option<CString> {
        &self.cwd
    }

    /// Fork: clone3(CLONE_VFORK | CLONE_PIDFD) when the kernel has it (the
    /// parent is suspended until the child execs, and the parent gets a
    /// pidfd that is immune to PID reuse), plain fork() otherwise. Returns
    /// (pid, pidfd) where pid == 0 in the child and pidfd is None there.
    fn do_fork(&mut self) -> Result<(libc::pid_t, Option<libc::c_int>)> {
        #[cfg(target_os = "linux")]
        {
            match sys::clone3_vfork_pidfd() {
                Ok(sys::ForkOutcome::Child) => return Ok((0, None)),
                Ok(sys::ForkOutcome::Parent { pid, pidfd }) => return Ok((pid, Some(pidfd))),
                // probe verdict: no clone3 (< 5.3) or a policy refusing it
                Err(ref e) if sys::is_unsupported(e) => {}
                Err(e) => return Err(e),
            }
        }
        let pid = cvt(unsafe { libc::fork() })?;
        Ok((pid, None))
    }

    fn capture_env(&mut self) -> Option<Vec<CString>> {
        let maybe_env = self.env.capture_if_changed();
        maybe_env.map(|env| construct_envp(env, &mut self.saw_nul))
    }

    /// Execute the command as a new process image, replacing the current
    /// process. On success this function never returns; the error it yields
    /// on failure is the operating system's own verdict.
    ///
    /// # Arguments
    /// * `default` - The default stdio to use if the child process does not
    ///   specify one.
    pub fn exec(&mut self, default: Stdio) -> Error {
        if self.saw_nul() {
            return Error::new(ErrorKind::InvalidInput, "nul byte found in provided data");
        }

        let captured_env = self.capture_env();
        let argv: Vec<*const libc::c_char> = self
            .get_argv()
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        // borrowed from captured_env, which stays alive through the exec
        let envp: Option<Vec<*const libc::c_char>> = captured_env.as_ref().map(|v| {
            v.iter()
                .map(|s| s.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect()
        });
        let memfd_fd = match self.ensure_prepared() {
            Ok(p) => p.fd.as_raw_fd(),
            Err(_) => -1, // kernel without memfd: the tmpfs ladder takes over
        };
        let quiet = env::var_os("NO_MEMFDEXEC").map(|v| v == "1").unwrap_or(false);

        match self.setup_io(default, true) {
            Ok((_, theirs)) => unsafe {
                // pipe fd -1: no parent survives to read a named-path report,
                // so a named fallback file in a no-procfs environment stays
                // behind (documented).
                match self.do_exec(memfd_fd, quiet, theirs, &argv, envp.as_deref(), -1) {
                    Ok(()) => Error::new(ErrorKind::Other, "exec returned without replacing"),
                    Err(err) => err,
                }
            },
            Err(e) => e,
        }
    }

    /// Get the program name to use for the child process as a C string.
    pub fn get_program_cstr(&self) -> &CStr {
        &self.program
    }

    /// Get the program argv to use for the child process.
    pub fn get_argv(&self) -> &Vec<CString> {
        &self.argv.0
    }

    /// Get whether PATH has been affected by changes to the environment
    /// variables of this command.
    pub fn env_saw_path(&self) -> bool {
        self.env.have_changed_path()
    }

    /// Get whether the program (argv\[0\]) is a path, as opposed to a name.
    pub fn program_is_path(&self) -> bool {
        self.program.to_bytes().contains(&b'/')
    }

    fn ensure_prepared(&mut self) -> Result<&Prepared> {
        if self.prepared.is_none() {
            self.prepare()?;
        }
        Ok(self.prepared.as_ref().unwrap())
    }

    /// The child half of spawn: wire up stdio, reset signals, apply the
    /// session/process-group knobs, then exec. Runs in the forked child; on
    /// success it never returns.
    ///
    /// The body must stay allocation-free: `argv`/`envp` were built by the
    /// caller before the fork, and every error carries a raw errno (a forked
    /// child must not depend on a malloc lock another thread may hold).
    ///
    /// # Safety
    /// Must only run in a freshly forked child (or a process that is about to
    /// exec and does not care about its own survival).
    unsafe fn do_exec(
        &mut self,
        memfd_fd: c_int,
        quiet: bool,
        stdio: ChildPipes,
        argv: &[*const libc::c_char],
        maybe_envp: Option<&[*const libc::c_char]>,
        pipe_fd: c_int,
    ) -> Result<()> {
        if let Some(fd) = stdio.stdin.fd() {
            cvt_r(|| libc::dup2(fd, libc::STDIN_FILENO))?;
        }
        if let Some(fd) = stdio.stdout.fd() {
            cvt_r(|| libc::dup2(fd, libc::STDOUT_FILENO))?;
        }
        if let Some(fd) = stdio.stderr.fd() {
            cvt_r(|| libc::dup2(fd, libc::STDERR_FILENO))?;
        }

        if let Some(ref cwd) = *self.get_cwd() {
            cvt(libc::chdir(cwd.as_ptr()))?;
        }

        {
            // Reset signal handling so the child process starts in a
            // standardized state. libstd ignores SIGPIPE, and signal-handling
            // libraries often set a mask. Child processes inherit ignored
            // signals and the signal mask from their parent, but most UNIX
            // programs do not reset these things on their own, so we need to
            // clean things up now to avoid confusing the program we're about
            // to run.
            let mut set = MaybeUninit::<libc::sigset_t>::uninit();
            cvt(sigemptyset(set.as_mut_ptr()))?;
            cvt_nz(libc::pthread_sigmask(
                libc::SIG_SETMASK,
                set.as_ptr(),
                null_mut(),
            ))?;

            let ret = signal(libc::SIGPIPE, libc::SIG_DFL);
            if ret == libc::SIG_ERR {
                return Err(Error::last_os_error());
            }
        }

        if self.setsid {
            cvt(libc::setsid())?;
        }
        if let Some(pgid) = self.process_group {
            cvt(libc::setpgid(0, pgid as libc::pid_t))?;
        }

        let envp: *const *const libc::c_char = match maybe_envp {
            Some(v) => v.as_ptr(),
            // No explicit environment: hand the exec the inherited environ
            // global — std's own semantics (a real env snapshot lives in the
            // fork-time copy of memory the child sees).
            None => sys::inherited_environ(),
        };

        if memfd_fd >= 0 && !quiet {
            match sys::exec_fd(memfd_fd, argv.as_ptr(), envp) {
                Err(err) if fd_rung_exhausted(&err) => {
                    // memfd lives but fd-based exec is off the table (no
                    // execveat, or procfs disappeared, or a hardening layer
                    // refuses memfd exec): try the tmpfs ladder.
                    return self.tmpfs_fallback(argv.as_ptr(), envp, pipe_fd);
                }
                other => return other.map(|()| unreachable!()),
            }
        }
        self.tmpfs_fallback(argv.as_ptr(), envp, pipe_fd)
    }

    /// Write the image to an executable tmpfs file and exec it. Runs in the
    /// forked child; never writes to stderr — failures travel back to the
    /// parent through the CLOEXEC pipe as real errnos.
    fn tmpfs_fallback(
        &self,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
        pipe_fd: c_int,
    ) -> Result<()> {
        let image = sys::tmpfs_payload(self.code)?;

        // No-procfs corner: the name is the final rung and the parent owns
        // the cleanup, so hand it over before execing.
        if let Some(path) = &image.named {
            if pipe_fd >= 0 {
                sys::pipe_write_named_path(pipe_fd, path.as_bytes());
            }
        }

        if image.fd >= 0 {
            match unsafe { sys::exec_fd(image.fd, argv, envp) } {
                Err(err) if fd_rung_exhausted(&err) => {
                    // Both fd rungs refused; without procfs there is no
                    // named rung left, so surface the real verdict.
                    if image.named.is_none() {
                        return Err(err);
                    }
                }
                other => return other,
            }
        }

        match &image.named {
            Some(path) => unsafe { sys::exec_path(path.as_ptr(), argv, envp) },
            None => Err(Error::from_raw_os_error(libc::ENOSYS)),
        }
    }
}

/// True when both fd rungs declined for environmental reasons (no execveat /
/// no procfs / exec forbidden), meaning a different backing file might still
/// work. Real image verdicts (ENOEXEC, EINVAL, ETXTBSY...) do not qualify.
/// ENOSYS doubles as the allocation-free "rungs exhausted" marker produced
/// by `sys::exec_fd` itself.
fn fd_rung_exhausted(err: &Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::ENOSYS)
    )
}

fn cvt_nz(ret: libc::c_int) -> Result<()> {
    if ret != 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}
