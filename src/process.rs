//! Child process handle (waitpid/waitid) and exit-status decoding.
//!
//! When the child was spawned via clone3(CLONE_PIDFD), the handle carries a
//! pidfd: kill and wait then go through pidfd_send_signal / waitid(P_PIDFD),
//! which stay correct even if the child's PID was recycled in the meantime.
//! On kernels without that machinery the classic waitpid/kill path is used
//! against the cached PID, exactly as std does.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{Error, ErrorKind, Result};

use crate::cvt::{cvt, cvt_r};
use crate::sys;

pub struct Process {
    pid: libc::pid_t,
    /// pidfd from clone3(CLONE_PIDFD); None on the plain-fork fallback.
    pidfd: Option<libc::c_int>,
    status: Option<ExitStatus>,
}

impl Process {
    pub unsafe fn new(pid: libc::pid_t, pidfd: Option<libc::c_int>) -> Self {
        Process {
            pid,
            pidfd,
            status: None,
        }
    }

    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    /// The pidfd of the child, if the kernel provided one. Pollable: poll(2)
    /// reports POLLIN once the child has exited, even before it is reaped.
    /// Valid across PID reuse; owned by this Process.
    pub fn pidfd(&self) -> Option<libc::c_int> {
        self.pidfd
    }

    pub fn kill(&mut self) -> Result<()> {
        // Once reaped the pid can be recycled; refuse to kill whoever wears
        // it next.
        if self.status.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid argument: can't kill an exited process",
            ));
        }
        if let Some(pidfd) = self.pidfd {
            match sys::pidfd_send_signal_kill(pidfd) {
                Ok(()) => return Ok(()),
                Err(ref e) if sys::is_unsupported(e) => {} // kernel < 5.1: fall through
                Err(e) => return Err(e),
            }
        }
        cvt(unsafe { libc::kill(self.pid, libc::SIGKILL) }).map(drop)
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        if let Some(pidfd) = self.pidfd {
            match sys::waitid_pidfd(pidfd, false) {
                Ok(Some(raw)) => {
                    let decoded = ExitStatus(raw);
                    self.status = Some(decoded);
                    return Ok(decoded);
                }
                // blocking waitid always yields a status
                Ok(None) => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "waitid(P_PIDFD) returned no status",
                    ))
                }
                Err(ref e) if sys::is_unsupported(e) => {} // kernel < 5.4: fall through
                Err(e) => return Err(e),
            }
        }
        let mut status = 0 as libc::c_int;
        cvt_r(|| unsafe { libc::waitpid(self.pid, &mut status, 0) })?;
        let decoded = ExitStatus(status);
        self.status = Some(decoded);
        Ok(decoded)
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        if let Some(pidfd) = self.pidfd {
            match sys::waitid_pidfd(pidfd, true) {
                Ok(Some(raw)) => {
                    let decoded = ExitStatus(raw);
                    self.status = Some(decoded);
                    return Ok(Some(decoded));
                }
                Ok(None) => return Ok(None),
                Err(ref e) if sys::is_unsupported(e) => {} // kernel < 5.4: fall through
                Err(e) => return Err(e),
            }
        }
        let mut status = 0 as libc::c_int;
        let pid = cvt(unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) })?;
        if pid == 0 {
            Ok(None)
        } else {
            let decoded = ExitStatus(status);
            self.status = Some(decoded);
            Ok(Some(decoded))
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(pidfd) = self.pidfd {
            unsafe { libc::close(pidfd) };
        }
    }
}

/// Describes the result of a process after it has terminated.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ExitStatus(libc::c_int);

impl Debug for ExitStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_tuple("unix_wait_status").field(&self.0).finish()
    }
}

impl ExitStatus {
    fn exited(&self) -> bool {
        libc::WIFEXITED(self.0)
    }

    /// Was termination successful? Signal termination is not a success.
    ///
    /// Success means the child exited normally with status 0.
    pub fn success(&self) -> bool {
        self.exited() && libc::WEXITSTATUS(self.0) == 0
    }

    /// Was termination successful? Returns an error describing the failure.
    pub fn exit_ok(&self) -> Result<()> {
        if let Some(code) = self.code() {
            if code == 0 {
                return Ok(());
            }
            return Err(Error::new(
                ErrorKind::Other,
                format!("process exited with status {code}"),
            ));
        }
        if let Some(sig) = self.signal() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("process terminated by signal {sig}"),
            ));
        }
        Err(Error::new(ErrorKind::Other, "process exited abnormally"))
    }

    /// The exit code of the process, if it exited normally. None when the
    /// process was terminated by a signal.
    pub fn code(&self) -> Option<i32> {
        self.exited().then(|| libc::WEXITSTATUS(self.0))
    }

    /// If the process was terminated by a signal, returns that signal.
    pub fn signal(&self) -> Option<i32> {
        libc::WIFSIGNALED(self.0).then(|| libc::WTERMSIG(self.0))
    }

    /// If the process was terminated by a signal, says whether it dumped core.
    pub fn core_dumped(&self) -> bool {
        libc::WIFSIGNALED(self.0) && libc::WCOREDUMP(self.0)
    }

    /// If the process was stopped by a signal, returns that signal.
    pub fn stopped_signal(&self) -> Option<i32> {
        libc::WIFSTOPPED(self.0).then(|| libc::WSTOPSIG(self.0))
    }

    /// Whether the process was continued from a stopped status.
    pub fn continued(&self) -> bool {
        libc::WIFCONTINUED(self.0)
    }

    /// The underlying raw wait status (a wait status, not an exit status).
    #[allow(clippy::wrong_self_convention)]
    pub fn into_raw(&self) -> libc::c_int {
        self.0
    }
}

impl From<libc::c_int> for ExitStatus {
    fn from(a: libc::c_int) -> ExitStatus {
        ExitStatus(a)
    }
}
