//! Child process handle (waitpid) and exit-status decoding.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{Error, ErrorKind, Result};

use crate::cvt::{cvt, cvt_r};

pub struct Process {
    pid: libc::pid_t,
    status: Option<ExitStatus>,
}

impl Process {
    pub unsafe fn new(pid: libc::pid_t) -> Self {
        Process { pid, status: None }
    }

    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn kill(&mut self) -> Result<()> {
        // Once reaped the pid can be recycled; refuse to kill whoever wears
        // it next.
        if self.status.is_some() {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid argument: can't kill an exited process",
            ))
        } else {
            cvt(unsafe { libc::kill(self.pid, libc::SIGKILL) }).map(drop)
        }
    }

    pub fn wait(&mut self) -> Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
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
