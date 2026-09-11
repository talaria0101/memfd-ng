//! Behavior tests: memfd mechanics, sealing, the tmpfs ladder, the CLOEXEC
//! pipe protocol, and cleanup guarantees. Everything here has a hard
//! assertion, not just a "it didn't crash" shape.

mod common;

use std::thread::sleep;
use std::time::{Duration, Instant};

#[cfg(target_arch = "x86_64")]
use common::TINY_ELF_EXIT42;
use common::stub_code;
use std::os::unix::io::AsRawFd;

use memfd_ng::{MemFdExecutable, Stdio};

#[test]
fn memfd_name_visible_in_child() {
    let _guard = common::serial();
    // the image name must reach /proc/<pid>/exe as /memfd:<name>
    let out = MemFdExecutable::new("ng-name-probe", &std::fs::read("/usr/bin/readlink").unwrap())
        .arg("/proc/self/exe")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    let exe = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(
        exe.starts_with("/memfd:ng-name-probe"),
        "expected /memfd:ng-name-probe, got {exe:?}"
    );
}

#[test]
fn image_fd_not_leaked_into_children() {
    let _guard = common::serial();
    // MFD_CLOEXEC: the child must see exactly the std stdio set (0-3)
    let out = MemFdExecutable::new("stub", stub_code())
        .arg("fds")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    let n: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    assert!(n <= 4, "child inherited extra fds: {n} (memfd leaked?)");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn tiny_elf_without_libc_exits_42() {
    let _guard = common::serial();
    let st = MemFdExecutable::new("tiny", TINY_ELF_EXIT42).status().unwrap();
    assert_eq!(st.code(), Some(42));
}

#[test]
fn large_payload_survives_the_write_loop() {
    let _guard = common::serial();
    // a real binary padded to ~9 MiB with trailing garbage (loaders ignore
    // bytes past the last PT_LOAD): exercises partial-write looping far
    // beyond one page.
    let mut code = stub_code().to_vec();
    code.resize(9 * 1024 * 1024, b'\0');
    let out = MemFdExecutable::new("big-stub", &code)
        .args(["print", "still-works-at-9MiB"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"still-works-at-9MiB\n");
}

#[test]
fn sealing_is_applied_and_visible() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("sealed-stub", stub_code());
    exe.prepare().unwrap();
    assert!(exe.is_prepared() && exe.is_sealed());

    // read the seal bits back from the kernel. (fdinfo's Seals line no
    // longer exists on 6.18+; F_GET_SEALS is the interface that remains.)
    let path = exe.memfd_path().expect("procfs available in tests");
    let probe = std::fs::File::open(&path).unwrap();
    let bits = unsafe { libc::fcntl(probe.as_raw_fd(), 1034 /* F_GET_SEALS */) };
    assert!(bits >= 0, "F_GET_SEALS failed");
    let bits = bits as u32;
    const SEAL_SHRINK: u32 = 0x1;
    const SEAL_GROW: u32 = 0x2;
    const SEAL_WRITE: u32 = 0x8;
    assert_eq!(
        bits & (SEAL_SHRINK | SEAL_GROW | SEAL_WRITE),
        SEAL_SHRINK | SEAL_GROW | SEAL_WRITE,
        "image not fully sealed"
    );

    // and the sealed image still executes
    let out = exe
        .arg("print")
        .arg("sealed-and-runnable")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"sealed-and-runnable\n");
}

#[test]
fn unsealed_opt_out_works() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("unsealed-stub", stub_code());
    exe.sealed(false);
    exe.prepare().unwrap();
    assert!(exe.is_prepared());
    assert!(!exe.is_sealed());
    let out = exe.arg("exit").arg("0").status().unwrap();
    assert!(out.success());
}

#[test]
fn prepared_spawn_reuses_the_image() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("reuse-stub", stub_code());
    exe.arg("exit"); // mode is argv[1]; later spawnes only add args
    exe.prepare().unwrap();
    let path_before = exe.memfd_path().unwrap();
    for i in 0..5 {
        let st = exe.arg(i.to_string()).status().unwrap();
        // argv[2] stays the FIRST appended value; assert it stays stable and
        // every spawn reuses the same sealed image
        assert_eq!(st.code(), Some(0), "iteration {i}");
    }
    let path_after = exe.memfd_path().unwrap();
    assert_eq!(path_before, path_after, "spawn should not rewrite the image");
}

#[test]
fn tmpfs_ladder_leaves_no_files() {
    let guard = common::serial();
    let _guard = &guard;
    std::env::set_var("NO_MEMFDEXEC", "1");
    let out = MemFdExecutable::new("fb-stub", stub_code())
        .arg("print")
        .arg("from-tmpfs")
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    std::env::remove_var("NO_MEMFDEXEC");
    drop(guard);

    assert_eq!(out.stdout, b"from-tmpfs\n");
    // the library must stay silent on the fallback path too
    assert_eq!(out.stderr, b"", "library must never write to stderr");
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

#[test]
fn corrupt_payload_reports_real_errno() {
    let _guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    let err = MemFdExecutable::new("bogus", b"\x7fELF-not-really")
        .status()
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(8 /* ENOEXEC */));
    // and nothing was left on disk by any fallback attempt
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

#[test]
fn concurrent_spawns_are_safe() {
    let _guard = common::serial();
    let code = stub_code();
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let code: &'static Vec<u8> = code;
            std::thread::spawn(move || {
                let out = MemFdExecutable::new("concurrent", code)
                    .args(["print", &format!("thread-{i}")])
                    .stdout(Stdio::MakePipe)
                    .output()
                    .unwrap();
                assert_eq!(out.stdout, format!("thread-{i}\n").into_bytes());
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn try_wait_and_reap_cleanup() {
    let _guard = common::serial();
    let mut child = MemFdExecutable::new("slow-stub", stub_code())
        .arg("sleep")
        .spawn()
        .unwrap();
    assert!(child.try_wait().unwrap().is_none(), "child finished too fast");
    child.kill().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            assert_eq!(st.signal(), Some(9));
            break;
        }
        assert!(Instant::now() < deadline, "child never reaped");
        sleep(Duration::from_millis(10));
    }
}

#[test]
fn output_collector_handles_interleaved_streams() {
    let _guard = common::serial();
    // both streams pipe; the child prints on both; read2 must not deadlock
    // or truncate (drives the poll loop)
    let sh_code = std::fs::read("/bin/sh").unwrap();
    let out = MemFdExecutable::new("sh", &sh_code)
        .args([
            "-c",
            "for i in 1 2 3 4 5; do echo out-$i; echo err-$i >&2; done",
        ])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"out-1\nout-2\nout-3\nout-4\nout-5\n");
    assert_eq!(out.stderr, b"err-1\nerr-2\nerr-3\nerr-4\nerr-5\n");
}

#[test]
fn no_stdio_override_inherits_cleanly() {
    let _guard = common::serial();
    // default stdio is inherit: run something silent and check the status
    let st = MemFdExecutable::new("stub", stub_code())
        .arg("exit")
        .arg("7")
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(7));
}

#[test]
fn null_stdio_discards() {
    let _guard = common::serial();
    let out = MemFdExecutable::new("stub", stub_code())
        .args(["print", "discarded"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"");
    assert!(out.status.success());
}

#[test]
fn memfd_path_is_none_before_prepare() {
    let _guard = common::serial();
    let exe = MemFdExecutable::new("nothing", stub_code());
    assert!(!exe.is_prepared());
    assert!(exe.memfd_path().is_none());
}

#[test]
fn static_stub_is_really_static() {
    let _guard = common::serial();
    // guard the fixture's promise: no interpreter segment
    let out = std::process::Command::new("file")
        .arg("-b")
        .arg(common::static_stub())
        .output()
        .unwrap();
    let desc = String::from_utf8_lossy(&out.stdout);
    if desc.contains("statically linked") || desc.contains("static-pie") {
        return;
    }
    panic!("fixture lost its static link: {desc}");
}

#[test]
fn unmodified_env_inherits_the_parent_environment() {
    let _guard = common::serial();
    // std parity: a command with NO env modifications inherits the parent's
    // whole environment. Regression: this crate used to hand the exec an
    // empty environment instead (found in REVIEW-7).
    std::env::set_var("MEMFD_NG_CANARY", "inherited-whole");
    let out = MemFdExecutable::new("stub", stub_code())
        .args(["env", "MEMFD_NG_CANARY"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    std::env::remove_var("MEMFD_NG_CANARY");
    assert_eq!(out.stdout, b"inherited-whole\n");
}

#[test]
fn child_argv0_reaches_the_program() {
    let _guard = common::serial();
    // the stub prints nothing about argv0; use sh's builtin to read it
    let sh_code = std::fs::read("/bin/sh").unwrap();
    let out = MemFdExecutable::new("sh", &sh_code)
        .args(["-c", "echo $0"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"sh\n");
    let mut exe = MemFdExecutable::new("sh", &sh_code);
    exe.set_program(std::ffi::OsStr::new("my-shell"));
    let out = exe
        .args(["-c", "echo $0"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"my-shell\n");
}

#[test]
fn prepare_then_spawn_stress() {
    let _guard = common::serial();
    // 50 prepared spawns with a growing argv: every spawn must reuse the
    // sealed image (path stable), keep every earlier argument (argv is
    // append-only, like std), and stay silent.
    let mut exe = MemFdExecutable::new("stress-stub", stub_code());
    exe.arg("print");
    exe.prepare().unwrap();
    let path_before = exe.memfd_path().unwrap();
    for i in 0..50 {
        let tag = format!("iter-{i}");
        let out = exe.arg(&tag).stdout(Stdio::MakePipe).output().unwrap();
        let line = String::from_utf8_lossy(&out.stdout);
        assert!(line.starts_with("iter-0"), "accumulated argv lost early args at {i}");
        assert!(line.contains(&tag), "latest arg missing at iteration {i}");
        assert!(out.status.success(), "iteration {i}");
        assert_eq!(out.stderr, b"");
    }
    assert_eq!(path_before, exe.memfd_path().unwrap(), "image must not be rewritten");
}

#[test]
fn interleaved_pipes_and_large_stdout() {
    let _guard = common::serial();
    // ~1 MiB through stdout while stderr also drains: exercises read2's
    // poll loop beyond single-buffer sizes
    let sh_code = std::fs::read("/bin/sh").unwrap();
    let out = MemFdExecutable::new("sh-big", &sh_code)
        .args([
            "-c",
            "dd if=/dev/zero bs=1024 count=1024 2>/dev/null; echo done >&2",
        ])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout.len(), 1024 * 1024);
    assert!(out.stdout.iter().all(|&b| b == 0));
    assert_eq!(out.stderr, b"done\n");
}
