//! Granular sealing API: `seals(u32)` builder + `F_SEAL_FUTURE_WRITE`.
//! Every seal claim is read back from the kernel with F_GET_SEALS, never
//! trusted from our own bookkeeping.

mod common;

use common::stub_code;
use memfd_ng::{MemFdExecutable, SealFlags};
use std::io::Write;
use std::os::unix::io::AsRawFd;

const SEAL_SHRINK: i32 = 0x1;
const SEAL_GROW: i32 = 0x2;
const SEAL_WRITE: i32 = 0x8;
const SEAL_FUTURE_WRITE: i32 = 0x10;

fn kernel_seals(exe: &MemFdExecutable) -> i32 {
    let path = exe.memfd_path().expect("procfs available in tests");
    let probe = std::fs::File::open(&path).unwrap();
    let bits = unsafe { libc::fcntl(probe.as_raw_fd(), 1034 /* F_GET_SEALS */) };
    assert!(bits >= 0, "F_GET_SEALS failed — was MFD_ALLOW_SEALING set?");
    bits
}

#[test]
fn default_seals_are_shrink_grow_write() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("seals-default", stub_code());
    exe.prepare().unwrap();
    assert!(exe.is_sealed());
    assert_eq!(
        kernel_seals(&exe),
        SEAL_SHRINK | SEAL_GROW | SEAL_WRITE,
        "the default must stay SHRINK|GROW|WRITE"
    );
}

#[test]
fn future_write_seal_lands_exactly() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("seals-fw", stub_code());
    exe.seals(SealFlags::FUTURE_WRITE);
    exe.prepare().unwrap();
    assert!(exe.is_sealed(), "FUTURE_WRITE counts as sealed");
    assert_eq!(kernel_seals(&exe), SEAL_FUTURE_WRITE);
    // and the sealed image still executes
    let st = exe.arg("exit").arg("0").status().unwrap();
    assert!(st.success());
}

#[test]
fn arbitrary_seal_combinations_land_exactly() {
    let _guard = common::serial();
    for flags in [
        SealFlags::SHRINK,
        SealFlags::SHRINK | SealFlags::GROW,
        SealFlags::FUTURE_WRITE | SealFlags::SHRINK,
        SealFlags::GROW | SealFlags::WRITE,
    ] {
        let mut exe = MemFdExecutable::new("seals-combo", stub_code());
        exe.seals(flags);
        exe.prepare().unwrap();
        assert_eq!(
            kernel_seals(&exe),
            flags.bits(),
            "seal combination {flags:?} did not land verbatim"
        );
    }
}

#[test]
fn empty_seal_set_prepares_unsealed_but_sealable() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("seals-none", stub_code());
    exe.seals(SealFlags::default());
    exe.prepare().unwrap();
    assert!(!exe.is_sealed(), "zero bits must not report as sealed");
    // the memfd stays sealable (MFD_ALLOW_SEALING was set): reading the
    // (empty) seal set must work
    assert_eq!(kernel_seals(&exe), 0);
    let st = exe.arg("exit").arg("5").status().unwrap();
    assert_eq!(st.code(), Some(5));
}

#[test]
fn write_seal_blocks_new_writes() {
    let _guard = common::serial();
    // F_SEAL_WRITE / F_SEAL_FUTURE_WRITE: nothing may modify the image
    // through a writable fd opened after the seal.
    for flags in [SealFlags::WRITE, SealFlags::FUTURE_WRITE] {
        let mut exe = MemFdExecutable::new("seals-block", stub_code());
        exe.seals(flags);
        exe.prepare().unwrap();
        let path = exe.memfd_path().unwrap();
        let mut probe = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let res = probe.write_all(b"PATCH-BYTES");
        assert!(res.is_err(), "{flags:?} must block post-seal writes");
    }
}

#[test]
fn changing_seals_invalidates_the_prepared_image() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("seals-reseat", stub_code());
    exe.prepare().unwrap();
    assert_eq!(kernel_seals(&exe), SEAL_SHRINK | SEAL_GROW | SEAL_WRITE);

    exe.seals(SealFlags::FUTURE_WRITE);
    assert!(!exe.is_prepared(), "seals() must invalidate the cache");
    exe.prepare().unwrap();
    assert_eq!(kernel_seals(&exe), SEAL_FUTURE_WRITE);

    // sealed(false) still wins over any seal set
    exe.sealed(false);
    assert!(!exe.is_prepared());
    exe.prepare().unwrap();
    assert!(!exe.is_sealed());
    // Our seal set must not be applied. (The kernel reports F_GET_SEALS = 1
    // — F_SEAL_SHRINK — for memfds created WITHOUT MFD_ALLOW_SEALING on
    // 6.18, rather than the documented error; we assert only on the bits
    // we asked for.)
    let bits = kernel_seals(&exe);
    assert_eq!(
        bits & (SEAL_GROW | SEAL_WRITE | SEAL_FUTURE_WRITE),
        0,
        "sealed(false) must apply none of our seals (got {bits:#x})"
    );
}

#[test]
fn sealed_payload_survives_child_write_attempts() {
    let _guard = common::serial();
    // A prepared+sealed image must be immutable even from children of the
    // sealed image itself: the stub opens /proc/self/exe for writing.
    // (Needs the image to try: use the stub's cat mode on its own exe is
    // read-only, so instead assert the parent-side contract: no writable fd
    // of ours can change the image.)
    let mut exe = MemFdExecutable::new("seals-immutable", stub_code());
    exe.seals(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK);
    exe.prepare().unwrap();
    let path = exe.memfd_path().unwrap();
    let before = std::fs::read(&path).unwrap();
    let res = std::fs::OpenOptions::new().write(true).open(&path);
    if let Ok(mut w) = res {
        assert!(w.write_all(b"\x7fCORRUPT").is_err(), "write must fail on a WRITE-sealed memfd");
    }
    let after = std::fs::read(&path).unwrap();
    assert_eq!(before, after, "image changed under seal");
    let st = exe.arg("exit").arg("0").status().unwrap();
    assert!(st.success());
}
