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

use libc::{c_int, pid_t, sigemptyset, signal};

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

/// This is the main struct used to create an in-memory only executable.
/// Wherever possible, it is a drop-in replacement for the standard library's
/// `process::Command` struct; the one difference is that the executable's
/// bytes are supplied by the caller instead of a filesystem path.
///
/// The payload lands in a `memfd_create(2)` file, is sealed against
/// modification when the kernel allows, and is executed with
/// `execveat(2)`/`AT_EMPTY_PATH` — never touching disk. Kernels or emulation
/// layers without fd-based exec get a silent, allocation-free tmpfs ladder
/// (`XDG_RUNTIME_DIR` → tmp dir → `/dev/shm` → `~/.cache`), each candidate
/// checked against `ST_NOEXEC` first.
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
    /// Prepared memfd cache: written and sealed once, executed many times
    prepared: Option<Prepared>,
}

#[derive(Debug)]
struct Prepared {
    fd: FileDesc,
    sealed: bool,
}

struct Argv(Vec<CString>);

impl std::fmt::Debug for MemFdExecutable<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // redact the payload: Debug on a prepared 9 MiB image would otherwise
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
    /// argv\[0\] distinct from the payload name.
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

    /// Create the memfd now: write the payload and, when the kernel supports
    /// it, seal it against shrinking, growing and writing.
    ///
    /// Spawning prepares the payload anyway, but calling this once makes
    /// every later `spawn()` skip the write entirely: the sealed image is
    /// executed in place, which is the fast path for programs that spawn the
    /// same payload repeatedly. Sealing also means nobody with a writable fd
    /// (including our own children) can swap the code between spawns.
    ///
    /// Preparing again simply replaces the previous image.
    pub fn prepare(&mut self) -> Result<&mut Self> {
        let name = os2c(OsStr::new(&self.name), &mut self.saw_nul);
        let fd = sys::memfd_create(name.as_ptr(), self.sealed)?;
        if !sys::is_regular_file(fd) {
            let err = Error::from_raw_os_error(libc::EINVAL);
            unsafe { libc::close(fd) };
            return Err(err);
        }
        sys::write_all(fd, self.code)?;
        let sealed = self.sealed && sys::add_seals(fd);
        self.prepared = Some(Prepared {
            fd: unsafe { FileDesc::from_raw_fd(fd) },
            sealed,
        });
        Ok(self)
    }

    /// Whether a payload is already prepared (see [`prepare`]).
    pub fn is_prepared(&self) -> bool {
        self.prepared.is_some()
    }

    /// Whether the prepared payload (if any) ended up sealed.
    pub fn is_sealed(&self) -> bool {
        self.prepared.as_ref().map(|p| p.sealed).unwrap_or(false)
    }

    /// Toggle payload sealing. Sealing is on by default; kernels without
    /// sealing support silently skip it. Changing this invalidates any
    /// prepared image: the next spawn (or `prepare`) stages a fresh payload
    /// under the new setting.
    pub fn sealed(&mut self, on: bool) -> &mut Self {
        if self.sealed != on {
            self.sealed = on;
            self.prepared = None;
        }
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

        let envp = self.capture_env();
        let (ours, theirs) = self.setup_io(Stdio::Inherit, true)?;
        let (input, output) = anon_pipe()?;

        // Prepare the payload in the parent so the forked child only has to
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
        let pid = unsafe { self.do_fork()? };

        if pid == 0 {
            drop(input);
            let err = unsafe {
                match self.do_exec(memfd_fd, quiet, theirs, envp.as_deref(), output.as_raw_fd()) {
                    Ok(()) => unreachable!("do_exec either execs or fails"),
                    Err(err) => err,
                }
            };
            sys::pipe_write_errno(output.as_raw_fd(), &err);
            unsafe { libc::_exit(127) };
        }

        drop(output);

        let mut p = unsafe { Process::new(pid) };
        let mut named_fallback: Option<PathBuf> = None;

        // loop to handle EINTR and the (no-procfs) named-path message
        loop {
            match sys::pipe_read(input.as_raw_fd()) {
                Ok(sys::PipeMsg::Success) => {
                    let mut child = Child::new(p, ours);
                    child.named_fallback = named_fallback;
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

    unsafe fn do_fork(&mut self) -> Result<pid_t> {
        cvt(libc::fork())
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

        let envp = self.capture_env();
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
                match self.do_exec(memfd_fd, quiet, theirs, envp.as_deref(), -1) {
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

    /// The child half of spawn: wire up stdio, reset signals, then exec.
    /// Runs in the forked child; on success it never returns.
    ///
    /// # Safety
    /// Must only run in a freshly forked child (or a process that is about to
    /// exec and does not care about its own survival).
    unsafe fn do_exec(
        &mut self,
        memfd_fd: c_int,
        quiet: bool,
        stdio: ChildPipes,
        maybe_envp: Option<&[CString]>,
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

        let argv = self
            .get_argv()
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<*const libc::c_char>>();

        let envp_owned = maybe_envp.unwrap_or_default();
        let envp = envp_owned
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<*const libc::c_char>>();

        if memfd_fd >= 0 && !quiet {
            match sys::exec_fd(memfd_fd, argv.as_ptr(), envp.as_ptr()) {
                Err(err) if fd_rung_exhausted(&err) => {
                    // memfd lives but fd-based exec is off the table (no
                    // execveat, or procfs disappeared, or a hardening layer
                    // refuses memfd exec): try the tmpfs ladder.
                    return self.tmpfs_fallback(&argv, &envp, pipe_fd);
                }
                other => return other.map(|()| unreachable!()),
            }
        }
        self.tmpfs_fallback(&argv, &envp, pipe_fd)
    }

    /// Write the payload to an executable tmpfs file and exec it. Runs in the
    /// forked child; never writes to stderr — failures travel back to the
    /// parent through the CLOEXEC pipe as real errnos.
    fn tmpfs_fallback(
        &self,
        argv: &[*const libc::c_char],
        envp: &[*const libc::c_char],
        pipe_fd: c_int,
    ) -> Result<()> {
        let payload = sys::tmpfs_payload(self.code)?;

        // No-procfs corner: the name is the final rung and the parent owns
        // the cleanup, so hand it over before execing.
        if let Some(path) = &payload.named {
            if pipe_fd >= 0 {
                sys::pipe_write_named_path(pipe_fd, path.as_bytes());
            }
        }

        if payload.fd >= 0 {
            match unsafe { sys::exec_fd(payload.fd, argv.as_ptr(), envp.as_ptr()) } {
                Err(err) if fd_rung_exhausted(&err) => {
                    // Both fd rungs refused; without procfs there is no
                    // named rung left, so surface the real verdict.
                    if payload.named.is_none() {
                        return Err(err);
                    }
                }
                other => return other,
            }
        }

        match &payload.named {
            Some(path) => unsafe { sys::exec_path(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) },
            None => Err(Error::new(
                ErrorKind::Unsupported,
                "fd rungs exhausted and no named fallback available",
            )),
        }
    }
}

/// True when both fd rungs declined for environmental reasons (no execveat /
/// no procfs / exec forbidden), meaning a different backing file might still
/// work. Real payload verdicts (ENOEXEC, EINVAL, ETXTBSY...) do not qualify.
fn fd_rung_exhausted(err: &Error) -> bool {
    match err.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => true,
        _ => err.kind() == ErrorKind::Unsupported,
    }
}

fn cvt_nz(ret: libc::c_int) -> Result<()> {
    if ret != 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}
