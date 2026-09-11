//! Failure-mode injection tests: degraded directories, empty
//! images, NUL rejection, argument volume. Each one drives a real failure
//! mode end to end and asserts we fail closed with the kernel's own verdict.

mod common;

use common::{stub_code, FALLBACK_PREFIX};
use memfd_ng::{MemFdExecutable, Stdio};

/// `/proc` is mounted `noexec` on every normal Linux system, so pointing the
/// ladder at it exercises the `ST_NOEXEC` skip against a real noexec mount:
/// the run must survive by moving on to `/dev/shm`.
#[test]
fn tmpfs_ladder_skips_a_real_noexec_mount() {
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("NO_MEMFDEXEC", "1");
    std::env::set_var("TMPDIR", "/proc");
    let out = MemFdExecutable::new("noexec-ladder", stub_code())
        .args(["print", "survived-noexec"])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    std::env::remove_var("TMPDIR");
    std::env::remove_var("NO_MEMFDEXEC");

    // every assertion stays inside the lock: env::temp_dir() and the env
    // vars themselves are process-global, and the next test may mutate them
    // the moment the guard drops
    assert_eq!(out.stdout, b"survived-noexec\n");
    assert_eq!(out.stderr, b"", "library must stay silent on the ladder");
    // /proc itself must not have been written to
    assert!(
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| !e.file_name().to_string_lossy().starts_with(FALLBACK_PREFIX)),
        "ladder tried to stage inside the noexec mount"
    );
    common::assert_no_fallback_leftovers(&common::tmpdir());
    drop(guard);
}

/// Dead directories at every env-controlled rung: the ladder must walk past
/// them and land on `/dev/shm`, which is not env-controlled.
#[test]
fn tmpfs_ladder_walks_past_dead_directories() {
    let guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    std::env::set_var("NO_MEMFDEXEC", "1");
    std::env::set_var("XDG_RUNTIME_DIR", "/nonexistent-mfd-a");
    std::env::set_var("TMPDIR", "/nonexistent-mfd-b");
    std::env::set_var("HOME", "/nonexistent-mfd-c");
    let out = MemFdExecutable::new("dead-dirs", stub_code())
        .args(["print", "landed-on-dev-shm"])
        .stdout(Stdio::MakePipe)
        .stderr(Stdio::MakePipe)
        .output()
        .unwrap();
    for v in ["XDG_RUNTIME_DIR", "TMPDIR", "HOME", "NO_MEMFDEXEC"] {
        std::env::remove_var(v);
    }

    // assertions inside the lock, same reason as the noexec test above
    assert_eq!(out.stdout, b"landed-on-dev-shm\n");
    assert_eq!(out.stderr, b"");
    common::assert_no_fallback_leftovers(&common::tmpdir());
    drop(guard);
}

/// An empty image is not an executable: the caller gets the kernel's
/// ENOEXEC, never a hang, a panic, or a phantom success.
#[test]
fn empty_payload_fails_with_enoexec() {
    let _guard = common::serial();
    let err = MemFdExecutable::new("empty", b"").status().unwrap_err();
    assert_eq!(err.raw_os_error(), Some(8 /* ENOEXEC */));
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

/// NUL bytes in arguments are rejected before anything is forked — std's
/// discipline — and without leaving state behind.
#[test]
fn nul_byte_in_argument_is_rejected() {
    let _guard = common::serial();
    common::clear_stale_fallback_files(&common::tmpdir());
    let err = MemFdExecutable::new("nul-arg", stub_code())
        .arg("bad\0arg")
        .status()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    // rejection happens before the fork: the ladder must be untouched
    common::assert_no_fallback_leftovers(&common::tmpdir());
}

/// One thousand arguments survive argv construction and the exec verbatim.
#[test]
fn large_argument_vectors_round_trip() {
    let _guard = common::serial();
    let args: Vec<String> = (0..1000).map(|i| format!("arg{i}")).collect();
    let mut exe = MemFdExecutable::new("many-args", stub_code());
    exe.arg("print").args(&args);
    let out = exe
        .arg("sentinel") // argv[1002]; proves nothing was dropped
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(
        out.stdout,
        format!("{} sentinel\n", args.join(" ")).into_bytes()
    );
}

/// Environment values containing `=` round-trip unharmed through the
/// key=value reconstruction.
#[test]
fn environment_values_with_equals_signs_round_trip() {
    let _guard = common::serial();
    let out = MemFdExecutable::new("eq-env", stub_code())
        .arg("env")
        .arg("WEIRD_VALUE")
        .env("WEIRD_VALUE", "a=b=c=d")
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"a=b=c=d\n");
}

/// `sealed(false)` after a `prepare()` must invalidate the cached image —
/// the next spawn stages a fresh unsealed image instead of silently
/// re-running the old sealed one.
#[test]
fn unsealing_after_prepare_invalidates_the_cache() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("reseat", stub_code());
    exe.prepare().unwrap();
    assert!(exe.is_prepared() && exe.is_sealed());
    exe.sealed(false);
    assert!(!exe.is_prepared(), "sealed() must invalidate the cache");
    assert!(!exe.is_sealed());
    exe.prepare().unwrap();
    assert!(exe.is_prepared() && !exe.is_sealed());
    let st = exe.arg("exit").arg("0").status().unwrap();
    assert!(st.success());
}
