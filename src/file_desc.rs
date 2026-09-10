//! Owned raw file descriptor with read/write plumbing.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::io::{IoSlice, IoSliceMut, Read, Result, Write};
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};

use crate::cvt::{cvt, cvt_r_ssize};

pub struct FileDesc(RawFd);

impl FileDesc {
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        cvt_r_ssize(|| unsafe {
            libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        })
    }

    /// Legal vectored read: data lands in the first non-empty buffer.
    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        match first_non_empty_mut(bufs) {
            Some(buf) => self.read(buf),
            None => Ok(0),
        }
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        true
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        cvt_r_ssize(|| unsafe {
            libc::write(self.0, buf.as_ptr() as *const libc::c_void, buf.len())
        })
    }

    /// Legal vectored write: the first non-empty buffer is flushed.
    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        match first_non_empty(bufs) {
            Some(buf) => self.write(buf),
            None => Ok(0),
        }
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        true
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        let flag = if nonblocking { libc::O_NONBLOCK } else { 0 };
        cvt(unsafe { libc::fcntl(self.0, libc::F_SETFL, flag) })?;
        Ok(())
    }

    pub fn read_to_end(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start_len = buf.len();
        let mut chunk = [0u8; 8192];
        loop {
            let read = self.read(&mut chunk)?;
            if read == 0 {
                return Ok(buf.len() - start_len);
            }
            buf.extend_from_slice(&chunk[..read]);
        }
    }

    pub fn duplicate(&self) -> Result<FileDesc> {
        let fd = cvt(unsafe { libc::dup(self.0) })?;
        Ok(FileDesc(fd))
    }
}

fn first_non_empty_mut<'a>(bufs: &'a mut [IoSliceMut<'_>]) -> Option<&'a mut [u8]> {
    bufs.iter_mut().find(|b| !b.is_empty()).map(|b| &mut **b)
}

fn first_non_empty<'a>(bufs: &'a [IoSlice<'_>]) -> Option<&'a [u8]> {
    bufs.iter().find(|b| !b.is_empty()).map(|b| &**b)
}

impl Read for FileDesc {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        FileDesc::read(self, buf)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        FileDesc::read_vectored(self, bufs)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        FileDesc::read_to_end(self, buf)
    }
}

impl Write for FileDesc {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        FileDesc::write(self, buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        FileDesc::write_vectored(self, bufs)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl AsRawFd for FileDesc {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl AsFd for FileDesc {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}

impl IntoRawFd for FileDesc {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl FromRawFd for FileDesc {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        FileDesc(raw_fd)
    }
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl Debug for FileDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("FileDesc").field("fd", &self.0).finish()
    }
}
