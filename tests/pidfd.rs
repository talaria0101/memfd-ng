//! pidfd spawn: clone3(CLONE_VFORK | CLONE_PIDFD) gives every child a
//! poll-able, PID-reuse-immune handle. These tests prove the handle exists
//! (fork() cannot produce one), that it polls, that kill/wait/try_wait go
//! through it, and that the vfork suspension does not corrupt the parent.

mod common;

use std::thread::sleep;
use std::time::Duration;

use common::{kernel_at_least, stub_code};
use memfd_ng::{MemFdExecutable, Stdio};

fn count_open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("procfs")
        .filter_map(|e| e.ok())
        .count()
}

#[test]
fn spawn_hands_out_a_pidfd() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old for clone3(CLONE_PIDFD); skipping");
        return;
    }
    let mut child = MemFdExecutable::new("pidfd-probe", stub_code())
        .arg("sleep")
        .spawn()
        .unwrap();
    assert!(
        child.pidfd().is_some(),
        "clone3(CLONE_PIDFD) must yield a pidfd (its existence proves the \
         clone3 path ran: plain fork() cannot produce one)"
    );
    child.kill().unwrap();
    let st = child.wait().unwrap();
    assert_eq!(st.signal(), Some(9));
}

#[test]
fn pidfd_polls_before_and_after_exit() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    use std::os::unix::io::AsRawFd;

    let mut child = MemFdExecutable::new("pidfd-poll", stub_code())
        .arg("sleep")
        .spawn()
        .unwrap();
    let pidfd = child.pidfd().expect("pidfd").as_raw_fd();

    // still running: a zero-timeout poll must report nothing
    let mut fds = [libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
    assert_eq!(n, 0, "pidfd signalled POLLIN while the child still runs");

    child.kill().unwrap();

    // exited: POLLIN must fire (before the reap, which is the whole point)
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut fds = [libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        }];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) };
        assert!(n >= 0, "poll failed");
        if n == 1 {
            assert_ne!(fds[0].revents & libc::POLLIN, 0);
            break;
        }
        assert!(std::time::Instant::now() < deadline, "pidfd never polled readable");
    }
    let st = child.wait().unwrap();
    assert_eq!(st.signal(), Some(9));
}

#[test]
fn wait_and_try_wait_go_through_the_pidfd() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    // exit status must survive the waitid(P_PIDFD) decode (status@24 -> raw)
    let st = MemFdExecutable::new("pidfd-exit", stub_code())
        .args(["exit", "42"])
        .status()
        .unwrap();
    assert_eq!(st.code(), Some(42));

    // try_wait via WNOHANG on the pidfd
    let mut child = MemFdExecutable::new("pidfd-trywait", stub_code())
        .arg("sleep")
        .spawn()
        .unwrap();
    assert!(child.try_wait().unwrap().is_none());
    child.kill().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            assert_eq!(st.signal(), Some(9));
            break;
        }
        assert!(std::time::Instant::now() < deadline, "child never reaped");
        sleep(Duration::from_millis(5));
    }
    // idempotent: the cached status comes back
    let again = child.wait().unwrap();
    assert_eq!(again.signal(), Some(9));
}

#[test]
fn kill_after_reap_still_refuses() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    let mut child = MemFdExecutable::new("pidfd-reap", stub_code())
        .args(["exit", "0"])
        .spawn()
        .unwrap();
    child.wait().unwrap();
    assert!(child.kill().is_err(), "must refuse to signal a reaped pid");
}

#[test]
fn spawning_does_not_leak_pidfds() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    let baseline = count_open_fds();
    for i in 0..30 {
        let mut child = MemFdExecutable::new("pidfd-leak", stub_code())
            .args(["exit", &i.to_string()])
            .spawn()
            .unwrap();
        let st = child.wait().unwrap();
        assert_eq!(st.code(), Some(i));
    }
    assert_eq!(
        count_open_fds(),
        baseline,
        "pidfds (or anything else) leaked across spawn/wait cycles"
    );
}

#[test]
fn vfork_suspension_does_not_corrupt_the_parent() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    // The child runs (without CLONE_VM) while the parent is suspended; its
    // writes land in a private COW copy. Give it a big argv so the child's
    // own pre-exec activity has plenty of surface, and verify the parent's
    // own memory and the child's behavior afterwards.
    let args: Vec<String> = (0..200).map(|i| format!("image-{i}-{}", "x".repeat(50))).collect();
    let expected = args.join(" ");
    let mut exe = MemFdExecutable::new("vfork-integrity", stub_code());
    exe.arg("print").args(&args);
    let out = exe.stdout(Stdio::MakePipe).output().unwrap();
    let got = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
    assert_eq!(got, expected, "child argv garbled under vfork spawn");
    assert!(out.status.success());

    // concurrent spawns under vfork: several children at once must not
    // interfere with each other or the parent
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let args: &'static Vec<String> = Box::leak(Box::new(args.clone()));
            std::thread::spawn(move || {
                let mut exe = MemFdExecutable::new("vfork-threads", stub_code());
                exe.arg("print").args(args.iter().take(50));
                let out = exe.stdout(Stdio::MakePipe).output().unwrap();
                assert!(out.stdout.starts_with(b"image-0-"));
                assert_eq!(out.status.code(), Some(0), "thread {i}");
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn pidfd_path_coexists_with_the_tmpfs_ladder() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    common::clear_stale_fallback_files(&common::tmpdir());
    // NO_MEMFDEXEC=1: memfd skipped, tmpfs ladder runs, pidfd still handed out
    std::env::set_var("NO_MEMFDEXEC", "1");
    let out = MemFdExecutable::new("pidfd-ladder", stub_code())
        .args(["print", "pidfd-plus-ladder"])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    std::env::remove_var("NO_MEMFDEXEC");
    assert_eq!(out.stdout, b"pidfd-plus-ladder\n");
    assert_eq!(out.stderr, b"");
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

#[test]
fn large_parent_stack_survives_vfork_child_activity() {
    let _guard = common::serial();
    if !kernel_at_least(5, 3) {
        println!("kernel too old; skipping");
        return;
    }
    // Recurse deep in the parent, spawn from the bottom of the stack, then
    // unwind and verify every frame's sentinel: the child's pre-exec work
    // must never have touched the parent's live frames.
    const DEPTH: usize = 64;
    fn recurse(depth: usize, sentinels: &mut [u64; DEPTH]) -> Option<u8> {
        sentinels[depth] = 0xAAAA_0000 + depth as u64;
        if depth + 1 < DEPTH {
            let got = recurse(depth + 1, sentinels);
            // verify the frames below this one before returning
            for (d, slot) in sentinels.iter().enumerate().skip(depth) {
                assert_eq!(
                    *slot,
                    0xAAAA_0000 + d as u64,
                    "parent stack frame {d} clobbered by the vfork child"
                );
            }
            return got;
        }
        // bottom of the stack: spawn from here
        let st = MemFdExecutable::new("vfork-deep", stub_code())
            .args(["exit", "42"])
            .status()
            .unwrap();
        Some(st.code().unwrap() as u8)
    }
    let mut sentinels = [0u64; DEPTH];
    assert_eq!(recurse(0, &mut sentinels), Some(42));
    for (d, slot) in sentinels.iter().enumerate() {
        assert_eq!(*slot, 0xAAAA_0000 + d as u64);
    }
}
