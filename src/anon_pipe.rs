//! Anonymous pipes (O_CLOEXEC) and the concurrent stdout/stderr drain.

use std::io::{IoSlice, IoSliceMut, Result};
use std::mem::zeroed;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};

use crate::cvt::cvt;
use crate::file_desc::FileDesc;

pub struct AnonPipe(FileDesc);

pub fn anon_pipe() -> Result<(AnonPipe, AnonPipe)> {
    let mut fds = [0; 2];
    unsafe {
        cvt(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC))?;
        Ok((
            AnonPipe(FileDesc::from_raw_fd(fds[0])),
            AnonPipe(FileDesc::from_raw_fd(fds[1])),
        ))
    }
}

impl AnonPipe {
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.read(buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        self.0.read_vectored(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        self.0.is_read_vectored()
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        self.0.write_vectored(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn read_to_end(&self, buf: &mut Vec<u8>) -> Result<usize> {
        self.0.read_to_end(buf)
    }
}

impl AsRawFd for AnonPipe {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for AnonPipe {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl IntoRawFd for AnonPipe {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl FromRawFd for AnonPipe {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        Self(FromRawFd::from_raw_fd(raw_fd))
    }
}

impl From<AnonPipe> for FileDesc {
    fn from(p: AnonPipe) -> FileDesc {
        p.0
    }
}

/// Drain two pipes concurrently so a child blocked on one cannot stall the
/// other: poll(2) over both, appending into the caller's buffers.
pub fn read2(p1: AnonPipe, v1: &mut Vec<u8>, p2: AnonPipe, v2: &mut Vec<u8>) -> Result<()> {
    p1.set_nonblocking(true)?;
    p2.set_nonblocking(true)?;

    let mut fds: [libc::pollfd; 2] = unsafe { zeroed() };
    fds[0].fd = p1.as_raw_fd();
    fds[0].events = libc::POLLIN | libc::POLLERR | libc::POLLHUP;
    fds[1].fd = p2.as_raw_fd();
    fds[1].events = libc::POLLIN | libc::POLLERR | libc::POLLHUP;

    let mut open = 2u32;
    let mut chunk = [0u8; 8192];
    while open != 0 {
        let n = crate::cvt::cvt_r(|| unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) })?;
        if n == 0 {
            continue; // timeout disabled; spurious wake
        }
        for (i, fd) in fds.iter_mut().enumerate() {
            if fd.revents == 0 {
                continue;
            }
            let buf: &mut Vec<u8> = if i == 0 { v1 } else { v2 };
            let pipe = if i == 0 { &p1 } else { &p2 };
            let err = (fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0;
            match pipe.read(&mut chunk) {
                Ok(0) => {
                    open -= 1;
                    fd.fd = -1;
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                // POLLERR|POLLHUP with no readable data surfaces as EAGAIN
                // on Linux once the buffer drains; anything else is real.
                Err(e) if err => {
                    let _ = e;
                    open -= 1;
                    fd.fd = -1;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}
