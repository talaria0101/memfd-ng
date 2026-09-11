#![allow(dead_code)] // shared by multiple test binaries; each uses a subset

//! Shared fixtures: real binaries built at test time (static + dynamic), a
//! hand-assembled ELF64 that needs no toolchain, and a serial lock for tests
//! that touch this process's environment.

use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, Once};

static SERIAL: Mutex<()> = Mutex::new(());

/// Lock that survives a poisoned mutex: a panic in one test must not cascade
/// into every later test.
pub fn serial() -> MutexGuard<'static, ()> {
    match SERIAL.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn target_tmpdir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// Compile `code` with the system cc. `static` produces a real static binary
/// so tests exercise large images and non-trivial ELF layouts, not toy
/// stubs. Returns the binary path.
fn cc_build(name: &str, code: &str, link_static: bool) -> PathBuf {
    // Per-process fixture names: test binaries build fixtures in parallel and
    // a shared path would let one binary exec the other's half-written ELF
    // (observed live as ENOEXEC under qemu-user; flaky on the host too).
    let pid = std::process::id();
    let dir = target_tmpdir();
    std::fs::create_dir_all(&dir).expect("create fixture tmpdir");
    let src = dir.join(format!("{name}.{pid}.c"));
    let bin = dir.join(format!("{name}.{pid}"));
    std::fs::write(&src, code).expect("write fixture source");
    // MEMFD_NG_TEST_CC lets cross-environments (qemu-user CI) pick the guest
    // toolchain; fixtures must match the architecture of the test binary.
    let cc = env::var("MEMFD_NG_TEST_CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(cc);
    if link_static {
        cmd.arg("-static");
    }
    let ok = cmd
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .output()
        .expect("cc is required to build test fixtures")
        .status
        .success();
    assert!(ok, "cc failed to build {name}");
    bin
}

const STUB_SRC: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
/* stub <mode> [args...]
   print   : write argv[2..] space-joined + newline
   exit N  : exit with N
   env V   : print getenv(V) or "(unset)"
   pwd     : print cwd
   fds     : count entries in /proc/self/fd (procfs systems)
   cat     : copy stdin to stdout, exit 0
   sleep   : sleep 60 (for kill tests)
   pgroup  : print "pgid=<getpgid(0)> sid=<getsid(0)>"
   crash   : raise(SIGSEGV) (dies by signal, for 128+signal propagation)
*/
int main(int argc, char **argv, char **envp) {
    (void)envp;
    if (argc < 2) return 64;
    if (!strcmp(argv[1], "print")) {
        for (int i = 2; i < argc; i++) printf("%s%s", argv[i], i + 1 < argc ? " " : "");
        printf("\n");
        return 0;
    }
    if (!strcmp(argv[1], "exit")) return argc > 2 ? atoi(argv[2]) : 0;
    if (!strcmp(argv[1], "env")) {
        const char *v = argc > 2 ? getenv(argv[2]) : NULL;
        puts(v ? v : "(unset)");
        return 0;
    }
    if (!strcmp(argv[1], "pwd")) {
        char buf[4096];
        puts(getcwd(buf, sizeof buf) ? buf : "(fail)");
        return 0;
    }
    if (!strcmp(argv[1], "fds")) {
        int n = 0;
        for (int fd = 0; fd < 1024; fd++) {
            if (fcntl(fd, F_GETFD) != -1) n++;
        }
        printf("%d\n", n);
        return 0;
    }
    if (!strcmp(argv[1], "cat")) {
        char buf[4096];
        ssize_t n;
        while ((n = read(0, buf, sizeof buf)) > 0) write(1, buf, n);
        return 0;
    }
    if (!strcmp(argv[1], "sleep")) { sleep(60); return 0; }
    if (!strcmp(argv[1], "pgroup")) {
        printf("pgid=%d sid=%d\n", (int)getpgid(0), (int)getsid(0));
        return 0;
    }
    if (!strcmp(argv[1], "crash")) { raise(SIGSEGV); return 0; }
    return 64;
}
"#;


pub fn static_stub() -> &'static PathBuf {
    static INIT: Once = Once::new();
    static mut SLOT: Option<PathBuf> = None;
    unsafe {
        INIT.call_once(|| (*core::ptr::addr_of_mut!(SLOT)) = Some(cc_build("memfd_ng_stub_static", STUB_SRC, true)));
        (*core::ptr::addr_of!(SLOT)).as_ref().unwrap()
    }
}

pub fn dynamic_stub() -> &'static PathBuf {
    static INIT: Once = Once::new();
    static mut SLOT: Option<PathBuf> = None;
    unsafe {
        INIT.call_once(|| (*core::ptr::addr_of_mut!(SLOT)) = Some(cc_build("memfd_ng_stub_dynamic", STUB_SRC, false)));
        (*core::ptr::addr_of!(SLOT)).as_ref().unwrap()
    }
}

pub fn stub_code() -> &'static Vec<u8> {
    static INIT: Once = Once::new();
    static mut SLOT: Option<Vec<u8>> = None;
    unsafe {
        INIT.call_once(|| (*core::ptr::addr_of_mut!(SLOT)) = Some(std::fs::read(static_stub()).expect("read static stub")));
        (*core::ptr::addr_of!(SLOT)).as_ref().unwrap()
    }
}

pub fn dynamic_code() -> &'static Vec<u8> {
    static INIT: Once = Once::new();
    static mut SLOT: Option<Vec<u8>> = None;
    unsafe {
        INIT.call_once(|| (*core::ptr::addr_of_mut!(SLOT)) = Some(std::fs::read(dynamic_stub()).expect("read dynamic stub")));
        (*core::ptr::addr_of!(SLOT)).as_ref().unwrap()
    }
}

/// Hand-assembled x86_64 ELF64: 64-byte ehdr + 56-byte phdr + `exit(42)`.
/// No toolchain, no libc, fully deterministic — the smallest real image.
#[cfg(target_arch = "x86_64")]
pub const TINY_ELF_EXIT42: &[u8] = &[
    // ehdr
    0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // e_entry 0x400078
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_phoff 64
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // e_shoff 0
    0x00, 0x00, 0x00, 0x00, // e_flags
    0x40, 0x00, // e_ehsize 64
    0x38, 0x00, // e_phentsize 56
    0x01, 0x00, // e_phnum 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // phdr @64: PT_LOAD R+X, vaddr 0x400000, filesz/memsz 0x90
    0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // code @0x78: mov eax,60; mov edi,42; syscall
    0xb8, 0x3c, 0x00, 0x00, 0x00,
    0xbf, 0x2a, 0x00, 0x00, 0x00,
    0x0f, 0x05,
];

/// The tmpfs ladder's file prefix, for leftover checks.
pub const FALLBACK_PREFIX: &str = ".memfd-ng-";

/// True when the running kernel is at least `major.minor`; used to skip
/// pidfd-era assertions on ancient kernels instead of failing them.
pub fn kernel_at_least(major: u64, minor: u64) -> bool {
    let info = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut parts = info.split('.');
    let k_major: u64 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let k_minor: u64 = parts
        .next()
        .and_then(|p| p.trim_start_matches("0").parse().ok())
        .unwrap_or(0);
    (k_major, k_minor) >= (major, minor)
}

/// Remove leftovers from earlier runs so cleanliness assertions stay
/// hermetic no matter what state the machine is in.
pub fn clear_stale_fallback_files(dir: &PathBuf) {
    for entry in std::fs::read_dir(dir).expect("read dir").filter_map(|e| e.ok()) {
        if entry.file_name().to_string_lossy().starts_with(FALLBACK_PREFIX) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Fail when the tmpfs ladder left files behind in the given directory.
pub fn assert_no_fallback_leftovers(dir: &PathBuf) {
    let leftovers: Vec<_> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(FALLBACK_PREFIX))
        .collect();
    assert!(
        leftovers.is_empty(),
        "tmpfs ladder left files behind: {leftovers:?}"
    );
}

pub fn tmpdir() -> PathBuf {
    env::temp_dir()
}
