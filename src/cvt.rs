//! EINTR-aware syscall result helpers.

use std::io::{Error, Result};

pub fn cvt(ret: libc::c_int) -> Result<libc::c_int> {
    if ret == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// ssize_t flavor of cvt (read/write return isize).
pub fn cvt_ssize(ret: libc::ssize_t) -> Result<usize> {
    if ret < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// Retry an interrupted ssize_t syscall until it completes.
pub fn cvt_r_ssize<F: FnMut() -> libc::ssize_t>(mut f: F) -> Result<usize> {
    loop {
        match cvt_ssize(f()) {
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// Retry an interrupted syscall until it completes or fails for another reason.
pub fn cvt_r<F: FnMut() -> libc::c_int>(mut f: F) -> Result<libc::c_int> {
    loop {
        match cvt(f()) {
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}
