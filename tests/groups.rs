//! Process-group options: setsid() and process_group() builder knobs, with
//! std::process::Command::process_group as the oracle where they overlap.
//!
//! Every probe spawns with stdout piped so the asserting test knows the
//! child's real pid and can compare it against what the child reports.

mod common;

use std::io::Read;

use common::{dynamic_code, stub_code};
use memfd_ng::{MemFdExecutable, Stdio};
use std::os::unix::process::CommandExt;
use std::process::Command as StdCommand;

/// Spawn `exe` with the `pgroup` mode, returning (pid, pgid, sid) — all from
/// the same child process.
fn probe(mut exe: MemFdExecutable) -> (i32, i32, i32) {
    exe.arg("pgroup");
    let mut child = exe.stdout(Stdio::MakePipe).stderr(Stdio::MakePipe).spawn().unwrap();
    let pid = child.id() as i32;
    let mut buf = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut buf)
        .unwrap();
    let mut errbuf = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut errbuf)
        .unwrap();
    let st = child.wait().unwrap();
    assert!(st.success(), "stub failed: {errbuf:?}");
    assert_eq!(errbuf, "", "library must stay silent");
    let parse = |prefix: &str| {
        buf.split_whitespace()
            .find(|t| t.starts_with(prefix))
            .and_then(|t| t[prefix.len()..].parse().ok())
            .unwrap_or_else(|| panic!("bad pgroup line: {buf:?}"))
    };
    (pid, parse("pgid="), parse("sid="))
}

#[test]
fn setsid_gives_the_child_its_own_session() {
    let _guard = common::serial();
    let mut one = MemFdExecutable::new("setsid-one", stub_code());
    one.setsid(true);
    let (pid, pgid, sid) = probe(one);

    let mut two = MemFdExecutable::new("setsid-two", stub_code());
    two.setsid(true);
    let (pid2, pgid2, sid2) = probe(two);

    // setsid: the child becomes session AND group leader, in a session of
    // its own — different from ours and from its siblings'
    assert_eq!(pgid, pid, "setsid must make the child a session+group leader");
    assert_eq!(pgid2, pid2);
    assert_ne!(sid, sid2, "different children get different sessions");
    assert_ne!(sid, unsafe { libc::getsid(0) }, "child must not share our session");
}

#[test]
fn process_group_zero_makes_the_child_a_group_leader() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("pgroup-zero", stub_code());
    exe.process_group(0);
    let (pid, pgid, sid) = probe(exe);
    assert_eq!(pgid, pid, "pgid(0) must make the child lead its own group");
    assert_eq!(sid, unsafe { libc::getsid(0) }, "process_group(0) must not change the session");
}

#[test]
fn process_group_joins_the_named_group() {
    let _guard = common::serial();
    let parent_pgid = unsafe { libc::getpgid(0) };
    let mut exe = MemFdExecutable::new("pgroup-join", stub_code());
    exe.process_group(parent_pgid);
    let (_, pgid, sid) = probe(exe);
    assert_eq!(pgid, parent_pgid, "child must join the parent's group");
    assert_eq!(sid, unsafe { libc::getsid(0) });
}

#[test]
fn process_group_parity_with_std() {
    let _guard = common::serial();
    // std::process::Command::process_group(0) is the oracle: the child leads
    // its own group. Compare the observable shape, not the literal pid.
    let mut std_child = StdCommand::new(common::static_stub())
        .arg("pgroup")
        .process_group(0)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let std_pid = std_child.id() as i32;
    let mut std_line = String::new();
    std_child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut std_line)
        .unwrap();
    std_child.wait().unwrap();
    let std_pgid: i32 = std_line
        .split_whitespace()
        .find(|t| t.starts_with("pgid="))
        .and_then(|t| t["pgid=".len()..].parse().ok())
        .unwrap_or_else(|| panic!("bad std pgroup line: {std_line:?}"));
    assert_eq!(std_pgid, std_pid, "std oracle shape changed");

    let mut ng = MemFdExecutable::new("pgroup-parity", stub_code());
    ng.process_group(0);
    let (pid, pgid, _) = probe(ng);
    assert_eq!(pgid, pid, "ng must match the std oracle shape");
}

#[test]
fn setsid_then_process_group_fails_with_the_kernel_verdict() {
    let _guard = common::serial();
    // The kernel refuses setpgid(2) on a session leader (EPERM). Our order
    // is setsid first, then setpgid: a command asking for both must fail
    // closed with the kernel's own errno through the exec-failure channel,
    // never silently drop one of the two requests.
    let mut exe = MemFdExecutable::new("setsid-pg", stub_code());
    exe.setsid(true).process_group(0);
    let err = exe.arg("pgroup").status().unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EPERM));
}

#[test]
fn process_groups_work_on_dynamic_payloads_too() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("pgroup-dyn", dynamic_code());
    exe.setsid(true);
    let (pid, pgid, sid) = probe(exe);
    assert_eq!(pgid, pid);
    assert_eq!(sid, pid);
}

#[test]
fn default_is_no_session_or_group_change() {
    let _guard = common::serial();
    // without the knobs the child inherits the parent's session and group
    let exe = MemFdExecutable::new("pgroup-default", stub_code());
    let (_, pgid, sid) = probe(exe);
    assert_eq!(pgid, unsafe { libc::getpgid(0) });
    assert_eq!(sid, unsafe { libc::getsid(0) });
}
