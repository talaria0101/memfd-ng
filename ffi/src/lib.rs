//! C FFI layer over memfd-ng, for embedders that do not speak Rust.
//!
//! The API is intentionally small: spawn, pid, kill, wait, free. Errors come
//! back as negated errno values (0 = success), which C callers can compare
//! against their own `<errno.h>` constants. Nothing ever panics across the
//! boundary: Rust panics are caught and reported as `-EIO`.
//!
//! # Ownership contract
//!
//! - `code` must stay valid and unmodified from `memfd_ng_spawn` until the
//!   child has been waited on or freed: the image is staged into a sealed
//!   memfd at spawn time, but a no-memfd kernel falls back to re-reading the
//!   buffer on every exec.
//! - `name`, `argv` and `envp` strings only need to live until
//!   `memfd_ng_spawn` returns; they are copied.
//! - `argv == NULL` means `[name]`; a non-NULL `argv` is a NULL-terminated
//!   array whose first element is argv[0].
//! - `envp == NULL` inherits the parent environment; a non-NULL `envp` is a
//!   NULL-terminated array of complete `KEY=VALUE` strings (C `execve`
//!   semantics, not an overlay).
//! - Every handle must be released exactly once, with `memfd_ng_wait` or
//!   `memfd_ng_free`. Freeing without waiting leaves a zombie behind, the
//!   same as dropping a `std::process::Child` without `wait`.
//!
//! All three stdio streams of the child are inherited in this first cut;
//! pipe plumbing stays a library-level feature.

use std::ffi::{c_char, CStr};
use std::os::unix::ffi::OsStrExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use memfd_ng::{MemFdExecutable, Stdio};

/// Bumped on incompatible ABI changes.
#[no_mangle]
pub extern "C" fn memfd_ng_abi_version() -> i32 {
    1
}

/// The crate version string (static, NUL-terminated, never freed).
#[no_mangle]
pub extern "C" fn memfd_ng_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Opaque child handle.
pub struct MemFdNgChild {
    child: memfd_ng::Child,
}

fn neg_errno(e: &std::io::Error) -> i32 {
    -e.raw_os_error().unwrap_or(libc::EIO)
}

/// Copy a NULL-terminated array of C strings (C strings may hold arbitrary
/// non-NUL bytes; OsStr keeps them intact).
unsafe fn collect_cstrs(ptr: *const *const c_char) -> Option<Vec<std::ffi::OsString>> {
    if ptr.is_null() {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let p = *ptr.add(i);
        if p.is_null() {
            break;
        }
        out.push(std::ffi::OsString::from(std::ffi::OsStr::from_bytes(
            CStr::from_ptr(p).to_bytes(),
        )));
        i += 1;
    }
    Some(out)
}

/// Spawn the image in a child process. Returns a handle on success, NULL
/// on failure with the negated errno in `*err_out` (when non-NULL).
///
/// # Safety
/// `code` must point to `code_len` readable bytes; `name` (if non-NULL) and
/// the strings in `argv`/`envp` must be valid NUL-terminated C strings until
/// this call returns.
#[no_mangle]
pub unsafe extern "C" fn memfd_ng_spawn(
    code: *const u8,
    code_len: usize,
    name: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    err_out: *mut i32,
) -> *mut MemFdNgChild {
    // 'static by the caller contract above: the buffer outlives the child.
    let image: &'static [u8] = slice::from_raw_parts(code, code_len);
    let result = catch_unwind(AssertUnwindSafe(|| {
        if code.is_null() && code_len > 0 {
            return Err(-libc::EINVAL);
        }
        let name_os = if name.is_null() {
            std::ffi::OsString::from("memfd-ng")
        } else {
            std::ffi::OsString::from(std::ffi::OsStr::from_bytes(CStr::from_ptr(name).to_bytes()))
        };
        let argv_c = collect_cstrs(argv);
        let envp_c = collect_cstrs(envp);

        let mut exe = MemFdExecutable::new(&name_os, image);
        match argv_c {
            Some(v) => {
                if let Some(first) = v.first() {
                    exe.set_program(first.as_os_str());
                    for a in &v[1..] {
                        exe.arg(a.as_os_str());
                    }
                }
            }
            None => {
                exe.set_program(name_os.as_os_str());
            }
        }
        if let Some(e) = envp_c {
            // C envp arrays are complete environments, not overlays
            exe.env_clear();
            for kv in &e {
                let bytes = kv.as_bytes();
                if let Some(eq) = bytes.iter().position(|&b| b == b'=') {
                    let (k, v) = bytes.split_at(eq);
                    if k.is_empty() {
                        continue; // C forbids empty keys anyway
                    }
                    exe.env(
                        std::ffi::OsStr::from_bytes(k),
                        std::ffi::OsStr::from_bytes(&v[1..]),
                    );
                }
            }
        }
        exe.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        match exe.spawn() {
            Ok(child) => Ok(Box::into_raw(Box::new(MemFdNgChild { child }))),
            Err(e) => Err(neg_errno(&e)),
        }
    }))
    .map_err(|_| -libc::EIO)
    .and_then(std::convert::identity);
    match result {
        Ok(handle) => handle,
        Err(err) => {
            if !err_out.is_null() {
                unsafe { *err_out = err };
            }
            std::ptr::null_mut()
        }
    }
}

/// The child's pid (> 0), or a negated errno for a bad handle.
///
/// # Safety
/// `child` must be a handle from `memfd_ng_spawn` that has not been released.
#[no_mangle]
pub unsafe extern "C" fn memfd_ng_pid(child: *mut MemFdNgChild) -> i32 {
    if child.is_null() {
        return -libc::EBADF;
    }
    let child = &*child;
    child.child.id() as i32
}

/// SIGKILL the child. 0 on success, negated errno otherwise.
///
/// # Safety
/// `child` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn memfd_ng_kill(child: *mut MemFdNgChild) -> i32 {
    if child.is_null() {
        return -libc::EBADF;
    }
    let child = &mut *child;
    catch_unwind(AssertUnwindSafe(|| child.child.kill()))
        .unwrap_or_else(|_| Err(std::io::Error::from_raw_os_error(libc::EIO)))
        .map_or_else(|e| neg_errno(&e), |()| 0)
}

/// Reap the child and release the handle. Writes the raw wait(2) status to
/// `*status_out` (decode with your platform's WIFEXITED/WEXITSTATUS macros).
/// Returns 0 or a negated errno. The handle is consumed either way.
///
/// # Safety
/// `child` must be a live handle, released exactly once.
#[no_mangle]
pub unsafe extern "C" fn memfd_ng_wait(child: *mut MemFdNgChild, status_out: *mut i32) -> i32 {
    if child.is_null() {
        return -libc::EBADF;
    }
    let mut boxed = Box::from_raw(child);
    let result = catch_unwind(AssertUnwindSafe(|| boxed.child.wait()))
        .unwrap_or_else(|_| Err(std::io::Error::from_raw_os_error(libc::EIO)));
    match result {
        Ok(status) => {
            if !status_out.is_null() {
                unsafe { *status_out = status.into_raw() };
            }
            0
        }
        Err(e) => neg_errno(&e),
    }
}

/// Release the handle WITHOUT waiting: the child becomes a zombie until some
/// process reaps it, exactly like dropping a `std::process::Child`.
///
/// # Safety
/// `child` must be a live handle, released exactly once.
#[no_mangle]
pub unsafe extern "C" fn memfd_ng_free(child: *mut MemFdNgChild) {
    if !child.is_null() {
        drop(Box::from_raw(child));
    }
}
