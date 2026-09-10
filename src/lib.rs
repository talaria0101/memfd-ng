//! Execute ELF binaries straight from memory.
//!
//! Put the bytes of a Linux executable in a `&[u8]` — `include_bytes!()`,
//! a socket, a compiler — and [`MemFdExecutable`] runs them without the file
//! ever landing on disk:
//!
//! - The payload is written to a `memfd_create(2)` file and executed with
//!   `execveat(2)` + `AT_EMPTY_PATH` (no procfs required), falling back to
//!   `execve("/proc/self/fd/N")`, and finally to a silent, allocation-free
//!   tmpfs ladder for kernels or emulation layers without fd-based exec.
//! - Prepared payloads are sealed (`F_SEAL_SHRINK | F_SEAL_GROW |
//!   `F_SEAL_WRITE`) so nothing can swap the code between the write and the
//!   exec, and repeated spawns reuse the sealed image without rewriting it
//!   (see [`MemFdExecutable::prepare`]).
//! - The memfd carries `MFD_CLOEXEC` and `MFD_EXEC` where the kernel
//!   supports them, so the payload fd is visible to the executing child and
//!   to nothing else, and `vm.memfd_noexec` enforcement modes keep working.
//! - Failures surface as real `std::io::Error` values with the operating
//!   system's own errno, from `spawn()`/`status()`/`output()` just like
//!   `std::process`. The library never writes to stderr.
//!
//! # Environment
//!
//! Set `NO_MEMFDEXEC=1` to skip the memfd path and go straight to the tmpfs
//! ladder (useful under emulators whose execveat support is incomplete).
//!
//! # Example
//!
//! ```no_run
//! use memfd_ng::{MemFdExecutable, Stdio};
//!
//! let code = std::fs::read("/bin/sh").unwrap();
//! let mut sh = MemFdExecutable::new("sh", &code)
//!     .arg("-c")
//!     .arg("echo in-memory; exit 7")
//!     .stdout(Stdio::piped())
//!     .spawn()
//!     .unwrap();
//!
//! let output = sh.wait_with_output().unwrap();
//! assert_eq!(output.stdout, b"in-memory\n");
//! assert_eq!(output.status.code(), Some(7));
//! ```

mod anon_pipe;
mod child;
mod command_env;
mod cvt;
mod executable;
mod file_desc;
mod output;
mod process;
mod stdio;
mod sys;

pub use child::{Child, ChildStderr, ChildStdin, ChildStdout};
pub use executable::MemFdExecutable;
pub use file_desc::FileDesc;
pub use output::Output;
pub use process::ExitStatus;
pub use stdio::Stdio;
