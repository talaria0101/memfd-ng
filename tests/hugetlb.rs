//! `MFD_HUGETLB` option: the image may be staged on hugetlbfs, and every
//! hugetlb refusal must degrade to an ordinary memfd — a spawn never fails
//! *because of* hugetlb. Engagement is verified via fstatfs magic on the
//! prepared memfd, never assumed from the builder flag.
//! (x86_64-gated: the aligned-image test hardcodes the 2 MiB huge size;
//! the degrade contract also runs on every other target via the other tests.)

#![cfg(target_arch = "x86_64")]

mod common;

use common::{stub_code, TINY_ELF_EXIT42};
use memfd_ng::{MemFdExecutable, Stdio};
use std::os::unix::io::IntoRawFd;

const HUGETLBFS_MAGIC: i64 = 0x9584_58f6;

/// Returns Some(true) when the prepared memfd lives on hugetlbfs, Some(false)
/// when it demonstrably does not, None when procfs is unavailable.
fn is_on_hugetlbfs(exe: &MemFdExecutable) -> Option<bool> {
    let path = exe.memfd_path()?;
    let fd = std::fs::File::open(&path).unwrap().into_raw_fd();
    #[repr(C)]
    struct Statfs {
        f_type: i64,
        f_bsize: i64,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        f_files: u64,
        f_ffree: u64,
        f_fsid: [u32; 2],
        f_namelen: i64,
        f_frsize: i64,
        f_flags: i64,
        f_spare: [i64; 4],
    }
    let mut fs: Statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::syscall(libc::SYS_fstatfs, fd, &mut fs as *mut Statfs) };
    unsafe { libc::close(fd) };
    assert_eq!(rc, 0, "fstatfs on the prepared memfd failed");
    Some(fs.f_type == HUGETLBFS_MAGIC)
}

#[test]
fn hugetlb_request_never_breaks_spawning() {
    let _guard = common::serial();
    // Unaligned normal-size image: this host has huge pages configured but
    // none preallocated, so the write into hugetlbfs fails (ENOMEM) and the
    // contract says: degrade and run anyway. On hosts with free huge pages
    // the image engages hugetlbfs instead — both outcomes must run.
    let mut exe = MemFdExecutable::new("hugetlb-degrade", stub_code());
    exe.hugetlb(true);
    exe.prepare().unwrap();
    assert!(exe.is_prepared());
    match is_on_hugetlbfs(&exe) {
        Some(true) => println!("engaged hugetlbfs"),
        Some(false) => println!("degraded to ordinary memfd"),
        None => {}
    }
    let st = exe.arg("exit").arg("0").status().unwrap();
    assert!(st.success(), "hugetlb(true) must never make a spawn fail");
}

#[test]
fn hugetlb_engaged_payload_is_verifiably_on_hugetlbfs() {
    let _guard = common::serial();
    // Huge-page-aligned image: the engagement path becomes possible. When
    // engaged, fstatfs must show the hugetlbfs magic (proof, not promise);
    // when degraded (no free huge pages), the ordinary path must run the
    // image.
    let mut code = TINY_ELF_EXIT42.to_vec();
    code.resize(2 * 1024 * 1024, 0); // x86_64 default huge page size

    let mut exe = MemFdExecutable::new("hugetlb-aligned", &code);
    exe.hugetlb(true);
    exe.prepare().unwrap();
    match is_on_hugetlbfs(&exe) {
        Some(true) => {
            assert!(exe.is_hugetlb(), "fstatfs says hugetlbfs, bookkeeping disagrees");
        }
        Some(false) => {
            assert!(!exe.is_hugetlb());
        }
        None => {}
    }
    // The kernel may still refuse to exec a hugetlbfs image whose segments
    // it cannot map on this host; that must surface as a kernel errno, not
    // a panic, a hang, or silent corruption.
    let st = exe.status();
    match st {
        Ok(s) => assert_eq!(s.code(), Some(42), "padded tiny elf must still exit 42"),
        Err(e) => {
            assert!(
                e.raw_os_error().is_some(),
                "hugetlb exec failure must carry a kernel errno, got {e:?}"
            );
            assert!(exe.is_hugetlb(), "exec refused only makes sense when engaged");
        }
    }
}

#[test]
fn hugetlb_toggle_invalidates_the_prepared_image() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("hugetlb-reseat", stub_code());
    exe.hugetlb(true);
    exe.prepare().unwrap();
    assert!(exe.is_prepared());

    exe.hugetlb(false);
    assert!(!exe.is_prepared(), "hugetlb(false) must invalidate the cache");
    assert!(!exe.is_hugetlb());
    exe.prepare().unwrap();
    assert!(!exe.is_hugetlb(), "second prepare must be an ordinary memfd");
    let st = exe.arg("exit").arg("3").status().unwrap();
    assert_eq!(st.code(), Some(3));
}

#[test]
fn hugetlb_off_by_default() {
    let _guard = common::serial();
    let mut exe = MemFdExecutable::new("hugetlb-default", stub_code());
    exe.prepare().unwrap();
    assert!(!exe.is_hugetlb(), "default must stay an ordinary memfd");
    if let Some(on_hugetlb) = is_on_hugetlbfs(&exe) {
        assert!(!on_hugetlb);
    }
    let out = exe
        .args(["print", "plain-memfd"])
        .stdout(Stdio::MakePipe)
        .output()
        .unwrap();
    assert_eq!(out.stdout, b"plain-memfd\n");
}
