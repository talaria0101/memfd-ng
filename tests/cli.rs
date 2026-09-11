//! End-to-end tests for the `memfd-run` CLI binary. Gated on the `cli`
//! feature (the binary is only built with it); run with
//! `cargo test --features cli`.

#![cfg(feature = "cli")]

use std::process::Command;

mod common;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_memfd-run")
}

#[test]
fn runs_a_static_stub_from_memory() {
    let out = Command::new(binary())
        .args(["--", common::static_stub().to_str().unwrap(), "print", "via-cli"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"via-cli\n");
}

#[test]
fn propagates_exit_codes_and_signals() {
    let out = Command::new(binary())
        .args(["--", common::static_stub().to_str().unwrap(), "exit", "42"])
        .status()
        .unwrap();
    assert_eq!(out.code(), Some(42));

    // a child that dies by signal must surface as 128+signal (SIGSEGV=11 -> 139)
    let out = Command::new(binary())
        .args(["--", common::static_stub().to_str().unwrap(), "crash"])
        .status()
        .unwrap();
    assert_eq!(out.code(), Some(139), "signal death must surface as 128+sig");
}

#[test]
fn argv0_and_name_flags_work() {
    // --argv0 must reach the program as $0; sh reads it
    let sh = "/bin/sh";
    let out = Command::new(binary())
        .args(["--name", "sh-from-cli", "--argv0", "my-shell", "--", sh, "-c", "echo $0"])
        .stdout(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"my-shell\n");
    assert!(out.status.success());
}

#[test]
fn missing_file_is_a_clean_126() {
    let out = Command::new(binary())
        .args(["/nonexistent-memfd-ng-file"])
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(126));
    assert!(!out.stderr.is_empty(), "the CLI may speak on ITS stderr");
}

#[test]
fn corrupt_payload_surfaces_the_kernel_errno() {
    let dir = std::env::temp_dir().join(format!("memfd-run-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bogus = dir.join("bogus.elf");
    std::fs::write(&bogus, b"\x7fELF-not-really").unwrap();
    let out = Command::new(binary())
        .arg(&bogus)
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(126), "exec failure must be 126");
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(msg.contains("os error 8"), "message must carry the kernel verdict: {msg}");
}
