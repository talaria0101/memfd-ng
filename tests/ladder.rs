//! Exec-ladder tests that force the fallback rungs. These require the
//! `test-hooks` feature:
//!
//! ```sh
//! cargo test --features test-hooks
//! ```
//!
//! Hooks:
//! - `MEMFD_NG_TEST_NO_EXECVEAT` — the child skips `execveat(2)` (old kernel)
//! - `MEMFD_NG_TEST_NO_PROC`     — the process pretends procfs is absent
//!   (skips the `/proc/self/fd` rung, keeps tmpfs names, uses the named rung)

#![cfg(feature = "test-hooks")]

mod common;

use common::{stub_code, TINY_ELF_EXIT42};
use memfd_ng::{MemFdExecutable, Stdio};

#[test]
fn rung2_proc_path_executes_when_execveat_is_refused() {
    let guard = common::serial();
    std::env::set_var("MEMFD_NG_TEST_NO_EXECVEAT", "1");
    let out = MemFdExecutable::new("rung2-stub", stub_code())
        .args(["print", "via-procfd-rung"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    std::env::remove_var("MEMFD_NG_TEST_NO_EXECVEAT");
    drop(guard);
    assert_eq!(out.stdout, b"via-procfd-rung\n");
    assert!(out.status.success());
}

#[test]
fn named_rung_executes_and_parent_cleans_up_without_procfs() {
    // With procfs "absent": no execveat, no /proc/self/fd rung, the tmpfs
    // payload keeps its name, and the named rung must exec it. The parent
    // owns the name from the moment the child reports it and unlinks after
    // reaping — assert nothing is left behind.
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("MEMFD_NG_TEST_NO_EXECVEAT", "1");
    std::env::set_var("MEMFD_NG_TEST_NO_PROC", "1");

    let out = MemFdExecutable::new("named-rung-stub", stub_code())
        .args(["print", "via-named-rung"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();

    std::env::remove_var("MEMFD_NG_TEST_NO_PROC");
    std::env::remove_var("MEMFD_NG_TEST_NO_EXECVEAT");
    drop(guard);

    assert_eq!(out.stdout, b"via-named-rung\n");
    assert!(out.status.success());
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

#[test]
fn named_rung_failure_cleans_up_via_pipe_protocol() {
    // Same no-procfs corner, but the payload cannot exec at all: the child
    // reports the errno through the CLOEXEC pipe and the parent must unlink
    // the still-named file it inherited ownership of.
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("MEMFD_NG_TEST_NO_PROC", "1");

    let err = MemFdExecutable::new("doomed", b"definitely not an elf")
        .status()
        .unwrap_err();

    std::env::remove_var("MEMFD_NG_TEST_NO_PROC");
    drop(guard);

    // the verdict must still be the kernel's own (ENOEXEC), not a panic
    assert_eq!(err.raw_os_error(), Some(8));
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

#[test]
fn tiny_elf_still_runs_through_every_rung() {
    // smoke the deterministic payload through the forced rungs one at a time
    let cases: &[(&str, Option<&str>)] = &[
        ("execveat", None),
        ("procfd", Some("MEMFD_NG_TEST_NO_EXECVEAT")),
        ("named", Some("MEMFD_NG_TEST_NO_PROC")),
    ];
    for (label, hook) in cases {
        let guard = common::serial();
        let unset = hook.map(|h| {
            std::env::set_var(h, "1");
            h
        });
        let st = MemFdExecutable::new("tiny", TINY_ELF_EXIT42).status().unwrap();
        if let Some(h) = unset {
            std::env::remove_var(h);
        }
        drop(guard);
        assert_eq!(st.code(), Some(42), "tiny elf failed on the {label} rung");
    }
}
