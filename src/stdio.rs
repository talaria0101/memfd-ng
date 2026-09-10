//! Child stdio configuration: inherit, null, pipe, or an explicit fd.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::Result;
use std::os::raw::c_int;
use std::os::unix::prelude::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;

use crate::anon_pipe::{anon_pipe, AnonPipe};
use crate::file_desc::FileDesc;

pub struct StdioPipes {
    pub stdin: Option<AnonPipe>,
    pub stdout: Option<AnonPipe>,
    pub stderr: Option<AnonPipe>,
}

pub struct ChildPipes {
    pub stdin: ChildStdio,
    pub stdout: ChildStdio,
    pub stderr: ChildStdio,
}

pub enum ChildStdio {
    Inherit,
    Explicit(c_int),
    Owned(FileDesc),
}

/// Description of a stdio stream for a child process
#[derive(Debug)]
pub enum Stdio {
    /// Inherit the parent's stdio stream
    Inherit,
    /// Use a null stream, like /dev/null
    Null,
    /// Use a pipe to the input or output of the child process
    MakePipe,
    /// Use an existing file descriptor as the stdio stream
    Fd(FileDesc),
}

impl Stdio {
    pub fn to_child_stdio(&self, readable: bool) -> Result<(ChildStdio, Option<AnonPipe>)> {
        match *self {
            Stdio::Inherit => Ok((ChildStdio::Inherit, None)),

            // Make sure that the source descriptors are not an stdio
            // descriptor, otherwise the order in which we set the child's
            // descriptors may blow away a descriptor we were hoping to save.
            // For example, suppose we want the child's stderr to be the
            // parent's stdout, and the child's stdout to be the parent's
            // stderr. No matter which we dup first, the second overwrites it.
            Stdio::Fd(ref fd) => {
                let raw = fd.as_raw_fd();
                if (0..=libc::STDERR_FILENO).contains(&raw) {
                    Ok((ChildStdio::Owned(fd.duplicate()?), None))
                } else {
                    Ok((ChildStdio::Explicit(raw), None))
                }
            }

            Stdio::MakePipe => {
                let (reader, writer) = anon_pipe()?;
                let (ours, theirs) = if readable {
                    (writer, reader)
                } else {
                    (reader, writer)
                };
                Ok((ChildStdio::Owned(theirs.into()), Some(ours)))
            }

            Stdio::Null => {
                let mut opts = OpenOptions::new();
                opts.read(readable);
                opts.write(!readable);
                let path = Path::new(unsafe { CStr::from_bytes_with_nul_unchecked(b"/dev/null\0") }
                    .to_str()
                    .unwrap());
                // into_raw_fd, not as_raw_fd: ownership moves into the
                // ChildStdio and the handle must not be closed when the
                // temporary File would drop.
                let fd = opts.open(path)?.into_raw_fd();
                Ok((
                    ChildStdio::Owned(unsafe { FileDesc::from_raw_fd(fd) }),
                    None,
                ))
            }
        }
    }

    /// Create a pipe for this file descriptor and use it in the child process
    /// as the given file descriptor. See `MemFdExecutable::stdin` for an example.
    pub fn piped() -> Stdio {
        Stdio::MakePipe
    }

    /// Use a null file descriptor, like /dev/null, to either provide no input
    /// or to discard output.
    pub fn null() -> Stdio {
        Stdio::Null
    }

    /// Inherit the parent's file descriptor. This is the default behavior but
    /// is generally not the desired behavior.
    pub fn inherit() -> Stdio {
        Stdio::Inherit
    }
}

impl From<AnonPipe> for Stdio {
    fn from(pipe: AnonPipe) -> Stdio {
        Stdio::Fd(pipe.into())
    }
}

impl From<FileDesc> for Stdio {
    fn from(fd: FileDesc) -> Stdio {
        Stdio::Fd(fd)
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Stdio {
        let raw = file.into_raw_fd();
        Stdio::Fd(unsafe { FileDesc::from_raw_fd(raw) })
    }
}

impl ChildStdio {
    pub fn fd(&self) -> Option<c_int> {
        match *self {
            ChildStdio::Inherit => None,
            ChildStdio::Explicit(fd) => Some(fd),
            ChildStdio::Owned(ref fd) => Some(fd.as_raw_fd()),
        }
    }
}
