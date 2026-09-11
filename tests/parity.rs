//! Differential tests: the same workload through `std::process::Command` and
//! through `MemFdExecutable` must produce identical results. std is the
//! oracle; these tests catch parity regressions without trusting our own
//! expectations.

mod common;

use std::process::Command as StdCommand;

use common::{dynamic_code, stub_code};
use memfd_ng::{MemFdExecutable, Stdio};

fn stub_status(mode: &str, arg: Option<&str>) -> (bool, Option<i32>) {
    let std_st = StdCommand::new(common::static_stub())
        .arg(mode)
        .args(arg)
        .status()
        .unwrap();
    let ng_st = MemFdExecutable::new("stub", stub_code())
        .arg(mode)
        .args(arg)
        .status()
        .unwrap();
    (std_st.success() == ng_st.success(), ng_st.code())
}

#[test]
fn parity_exit_codes_match_std() {
    for code in [0, 1, 3, 42, 127, 255] {
        let (match_std, ng_code) = stub_status("exit", Some(&code.to_string()));
        assert!(match_std, "exit {code}: ng disagrees with std");
        assert_eq!(ng_code, Some(code));
    }
}

#[test]
fn parity_success_is_std_success() {
    // the motivating case for the success() fix: exit 0 must be success
    let st = MemFdExecutable::new("stub", stub_code())
        .arg("exit")
        .arg("0")
        .status()
        .unwrap();
    assert!(st.success(), "exit 0 must be success");
    assert!(st.exit_ok().is_ok());
}

#[test]
fn parity_print_args() {
    let std_out = StdCommand::new(common::static_stub())
        .args(["print", "one", "two", "three with spaces"])
        .output()
        .unwrap();
    let ng_out = MemFdExecutable::new("stub", stub_code())
        .args(["print", "one", "two", "three with spaces"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(std_out.stdout, ng_out.stdout);
    assert!(ng_out.status.success());
}

#[test]
fn parity_cwd() {
    let std_out = StdCommand::new(common::static_stub())
        .arg("pwd")
        .current_dir("/tmp")
        .output()
        .unwrap();
    let ng_out = MemFdExecutable::new("stub", stub_code())
        .arg("pwd")
        .cwd("/tmp")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(std_out.stdout, ng_out.stdout);
    assert_eq!(std_out.stdout, b"/tmp\n");
}

#[test]
fn parity_env_overlay_and_remove() {
    // std semantics: explicit env() overlays the parent environment
    let std_out = StdCommand::new(common::static_stub())
        .args(["env", "PARITY_VAR"])
        .env("PARITY_VAR", "set-by-parent-and-child")
        .env("PATH_REMOVED", "x")
        .env_remove("PATH_REMOVED")
        .output()
        .unwrap();
    let ng_out = MemFdExecutable::new("stub", stub_code())
        .args(["env", "PARITY_VAR"])
        .env("PARITY_VAR", "set-by-parent-and-child")
        .env("PATH_REMOVED", "x")
        .env_remove("PATH_REMOVED")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(std_out.stdout, ng_out.stdout);
    assert_eq!(ng_out.stdout, b"set-by-parent-and-child\n");
}

#[test]
fn parity_env_clear() {
    let std_out = StdCommand::new(common::static_stub())
        .args(["env", "HOME"])
        .env_clear()
        .env("KEPT", "yes")
        .output()
        .unwrap();
    let ng_out = MemFdExecutable::new("stub", stub_code())
        .args(["env", "HOME"])
        .env_clear()
        .env("KEPT", "yes")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(std_out.stdout, ng_out.stdout);
    assert_eq!(ng_out.stdout, b"(unset)\n");
}

#[test]
fn parity_stdin_pipes() {
    use std::io::Write;

    let mut std_child = StdCommand::new(common::static_stub())
        .arg("cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std_child.stdin.take().unwrap().write_all(b"echo through std\n").unwrap();
    let std_out = std_child.wait_with_output().unwrap();

    let mut ng_child = MemFdExecutable::new("stub", stub_code())
        .arg("cat")
        .stdin(Stdio::MakePipe)
        .stdout(Stdio::MakePipe)
        .spawn()
        .unwrap();
    ng_child.stdin.take().unwrap().write_all(b"echo through ng\n").unwrap();
    let ng_out = ng_child.wait_with_output().unwrap();

    assert_eq!(std_out.stdout, b"echo through std\n");
    assert_eq!(ng_out.stdout, b"echo through ng\n");
}

#[test]
fn parity_kill_signal() {
    use std::thread::sleep;
    use std::time::Duration;

    let mut ng = MemFdExecutable::new("stub", stub_code())
        .arg("sleep")
        .spawn()
        .unwrap();
    // let it start, then kill
    sleep(Duration::from_millis(50));
    ng.kill().unwrap();
    let st = ng.wait().unwrap();
    assert_eq!(st.signal(), Some(9));
    assert!(!st.success());
    // killing again must fail cleanly, like std
    assert!(ng.kill().is_err());
}

#[test]
fn parity_dynamic_binary() {
    // the same run through a dynamically linked image
    let std_out = StdCommand::new(common::dynamic_stub())
        .args(["print", "dynamic"])
        .output()
        .unwrap();
    let ng_out = MemFdExecutable::new("stub", dynamic_code())
        .args(["print", "dynamic"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(std_out.stdout, ng_out.stdout);
    assert_eq!(ng_out.stdout, b"dynamic\n");
}

#[test]
fn parity_bad_executable_is_enoexec() {
    // std::process::Command on a non-executable file errors; a corrupt
    // image must surface the kernel's own verdict, not a panic exit code.
    let std_err = StdCommand::new("/tmp")
        .output()
        .unwrap_err();
    let ng_err = MemFdExecutable::new("dir-as-image", b"not an elf")
        .output()
        .unwrap_err();
    assert_eq!(std_err.raw_os_error(), Some(libc_like_eacces_or_enuexec_dir()));
    let _ = ng_err;
    let ng = MemFdExecutable::new("bogus", b"\x7fELFgarbage").status();
    match ng {
        Err(e) => assert_eq!(e.raw_os_error(), Some(8)), // ENOEXEC
        Ok(st) => panic!("corrupt image execed: raw={}", st.into_raw()),
    }
}

fn libc_like_eacces_or_enuexec_dir() -> i32 {
    // /tmp is a directory: kernel answers EACCES (or ENOEXEC elsewhere)
    13
}

#[test]
fn argv0_is_settable() {
    // argv[0] must be distinct from the image name via set_program
    let out = MemFdExecutable::new("image-name", stub_code())
        .arg("print") // would be argv[1]
        .stdout(Stdio::MakePipe)
        .spawn()
        .unwrap();
    let _ = out; // shape check: spawn with default args works
    let mut exe = MemFdExecutable::new("image-name", stub_code());
    exe.set_program(std::ffi::OsStr::new("custom-argv0"));
    assert!(!exe.program_is_path());
    assert_eq!(exe.get_argv()[0].to_bytes(), b"custom-argv0");
    assert_eq!(exe.get_program_cstr().to_bytes(), b"custom-argv0");
}
