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

#[cfg(target_arch = "x86_64")]
use common::TINY_ELF_EXIT42;
use common::stub_code;
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
    // image keeps its name, and the named rung must exec it. The parent
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
    // Same no-procfs corner, but the image cannot exec at all: the child
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
#[cfg(target_arch = "x86_64")]
fn tiny_elf_still_runs_through_every_rung() {
    // smoke the deterministic image through the forced rungs one at a time
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

#[test]
fn otmpfile_staging_serves_the_whole_ladder() {
    // Default staging now tries O_TMPFILE first. With named staging forbidden
    // by hook, every ladder configuration must still work — a success here
    // proves the O_TMPFILE path (write phase fully anonymous) carried it.
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("MEMFD_NG_TEST_NO_NAMED_STAGE", "1");

    // 1. ordinary rungs (memfd available): tmpfs staging is not even reached,
    //    but the suite proves the hook does not break normal operation
    let out = MemFdExecutable::new("otmp-memfd", stub_code())
        .args(["print", "otmp-normal"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"otmp-normal\n");

    // 2. fallback ladder with procfs: O_TMPFILE + /proc/self/fd reopen
    std::env::set_var("NO_MEMFDEXEC", "1");
    let out = MemFdExecutable::new("otmp-proc", stub_code())
        .args(["print", "otmp-via-proc-reopen"])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"otmp-via-proc-reopen\n");
    assert_eq!(out.stderr, b"", "library must stay silent");
    std::env::remove_var("NO_MEMFDEXEC");

    // 3. fallback ladder without procfs: O_TMPFILE + linkat dance (needs
    //    CAP_DAC_READ_SEARCH; as non-root this test degrades to EPERM-
    //    enforced failure, which is exactly what the hook asked for)
    std::env::set_var("MEMFD_NG_TEST_NO_EXECVEAT", "1");
    std::env::set_var("MEMFD_NG_TEST_NO_PROC", "1");
    let out = MemFdExecutable::new("otmp-norproc", stub_code())
        .args(["print", "otmp-via-linkat-dance"])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output();
    match out {
        Ok(o) => assert_eq!(o.stdout, b"otmp-via-linkat-dance\n"),
        Err(e) => assert_eq!(e.raw_os_error(), Some(1) /* EPERM: hook-enforced */),
    }

    for h in [
        "MEMFD_NG_TEST_NO_NAMED_STAGE",
        "MEMFD_NG_TEST_NO_EXECVEAT",
        "MEMFD_NG_TEST_NO_PROC",
    ] {
        std::env::remove_var(h);
    }
    common::assert_no_fallback_leftovers(&common::tmpdir());
    drop(guard);
}

#[test]
fn legacy_named_staging_still_works_when_otmpfile_is_off() {
    // A/B control: with O_TMPFILE skipped by hook, the classic named flow
    // must behave exactly as before (write -> chmod -> exec, parent cleanup).
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("MEMFD_NG_TEST_NO_OTMPFILE", "1");
    std::env::set_var("MEMFD_NG_TEST_NO_EXECVEAT", "1");
    std::env::set_var("MEMFD_NG_TEST_NO_PROC", "1");

    let out = MemFdExecutable::new("legacy-named", stub_code())
        .args(["print", "legacy-named-staging"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();

    for h in [
        "MEMFD_NG_TEST_NO_OTMPFILE",
        "MEMFD_NG_TEST_NO_EXECVEAT",
        "MEMFD_NG_TEST_NO_PROC",
    ] {
        std::env::remove_var(h);
    }
    drop(guard);
    assert_eq!(out.stdout, b"legacy-named-staging\n");
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

#[test]
fn otmpfile_off_procmode_still_cleans_up_failures() {
    // A/B control with procfs: O_TMPFILE skipped, the named-create-then-
    // unlink flow must still leave nothing behind on success and failure.
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("MEMFD_NG_TEST_NO_OTMPFILE", "1");
    std::env::set_var("NO_MEMFDEXEC", "1");

    let out = MemFdExecutable::new("legacy-proc", stub_code())
        .args(["print", "legacy-with-procfs"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"legacy-with-procfs\n");

    let err = MemFdExecutable::new("legacy-doomed", b"still not an elf")
        .status()
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(8) /* ENOEXEC */);

    std::env::remove_var("NO_MEMFDEXEC");
    std::env::remove_var("MEMFD_NG_TEST_NO_OTMPFILE");
    drop(guard);
    common::assert_no_fallback_leftovers(&common::tmpdir());
}
