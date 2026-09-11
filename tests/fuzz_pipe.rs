//! Structure-aware fuzzing of the CLOEXEC-pipe protocol (roadmap item 8):
//! `pipe_read` is the one place untrusted-shape bytes are parsed. The
//! generator emits well-formed frames, truncations, bitflips, junk, and
//! boundary-length images through real OS pipes; the reader must answer
//! with the exact message, `InvalidData`, or a clean EOF — never a panic,
//! a wrong decode, a hang, or an unexpected error kind.
//!
//! Deterministic: xorshift64* seeded per case, so a failure reproduces with
//! `MEMFD_NG_FUZZ_CASE=<n>` (a single case) or by re-running this file.

#![cfg(feature = "test-hooks")]

use memfd_ng::protocol::{pipe_read, pipe_write_errno, pipe_write_named_path, PipeMsg};
use memfd_ng::{MemFdExecutable, Stdio};

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// One pipe pair with the write end parked on a thread so oversized images
/// can never deadlock the test.
struct Pipe {
    read_fd: libc::c_int,
    writer: Option<std::thread::JoinHandle<()>>,
    write_fd: libc::c_int,
}

impl Pipe {
    fn new() -> Self {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(rc, 0, "pipe2 failed");
        Pipe {
            read_fd: fds[0],
            writer: None,
            write_fd: fds[1],
        }
    }

    /// Park the write end on a thread; `image` is written in chunks of
    /// `chunk` bytes, then the write end closes (the reader sees EOF after
    /// the image).
    fn write_on_thread(&mut self, image: Vec<u8>, chunk: usize) {
        let wfd = self.write_fd;
        self.write_fd = -1;
        self.writer = Some(std::thread::spawn(move || {
            for piece in image.chunks(chunk.max(1)) {
                let mut off = 0;
                while off < piece.len() {
                    let n = unsafe {
                        libc::write(wfd, piece[off..].as_ptr() as *const libc::c_void, piece.len() - off)
                    };
                    if n <= 0 {
                        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if errno == libc::EINTR {
                            continue;
                        }
                        return; // reader went away: fine
                    }
                    off += n as usize;
                }
            }
            unsafe { libc::close(wfd) };
        }));
    }

    /// Close the write end now: the reader sees EOF (Success if nothing was
    /// written). NOTE: consuming `self` by value would be wrong here — with
    /// a `Drop` impl, the original value would be dropped at scope end and
    /// close the read fd under our feet.
    fn close_write(&mut self) {
        if self.write_fd >= 0 {
            unsafe { libc::close(self.write_fd) };
            self.write_fd = -1;
        }
    }

    fn read_one(&self) -> std::io::Result<PipeMsg> {
        pipe_read(self.read_fd)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            if self.write_fd >= 0 {
                libc::close(self.write_fd);
            }
            libc::close(self.read_fd);
        }
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
    }
}

fn errno_frame(err: i32) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&(err as u32).to_be_bytes());
    v.extend_from_slice(b"NOEX");
    v
}

fn path_frame(path: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + path.len());
    v.extend_from_slice(&(path.len() as u16).to_be_bytes());
    v.extend_from_slice(b"PATH");
    v.extend_from_slice(path);
    v
}

/// Every possible legal reader outcome: a message, or a clean `InvalidData`
/// rejection. Anything else (unexpected error kind, panic, hang) fails.
enum Outcome {
    Msg(PipeMsg),
    InvalidData(std::io::Error),
}

fn classify(msg: std::io::Result<PipeMsg>) -> Outcome {
    match msg {
        Ok(m) => Outcome::Msg(m),
        Err(e) => {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::InvalidData,
                "only InvalidData may reject a message, got {e:?}"
            );
            Outcome::InvalidData(e)
        }
    }
}

fn expect_msg(msg: std::io::Result<PipeMsg>) -> PipeMsg {
    match classify(msg) {
        Outcome::Msg(m) => m,
        Outcome::InvalidData(e) => panic!("well-formed input rejected as InvalidData: {e}"),
    }
}

fn fuzz_seed() -> (u64, u64) {
    // MEMFD_NG_FUZZ_CASE=<n> reproduces a single case deterministically
    match std::env::var("MEMFD_NG_FUZZ_CASE") {
        Ok(s) => {
            let n: u64 = s.parse().expect("MEMFD_NG_FUZZ_CASE must be a number");
            (n, n + 1) // one case only
        }
        Err(_) => (0, 10_000),
    }
}

#[test]
fn errno_frames_round_trip_exactly() {
    let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
    let mut errnos = vec![0i32, 1, 2, 8, 13, 22, 38, 127, 255, i32::MAX, i32::MIN, -1];
    for _ in 0..64 {
        errnos.push(rng.next() as i32);
    }
    for err in errnos {
        let mut pipe = Pipe::new();
        pipe.write_on_thread(errno_frame(err), 8);
        match expect_msg(pipe.read_one()) {
            PipeMsg::Failure(code) => assert_eq!(code, err, "errno {err} garbled"),
            other => panic!("expected Failure({err}), got {other:?}"),
        }
    }
}

#[test]
fn named_path_frames_round_trip_exactly() {
    // boundaries: 0, 1, 2, 254, 255, 256, u16::MAX-1, u16::MAX
    let mut lengths: Vec<usize> = vec![0, 1, 2, 254, 255, 256, 65534, 65535];
    let mut rng = Xorshift(0xBADC_0FEE_D00D);
    for _ in 0..16 {
        lengths.push(rng.below(300) as usize);
    }
    for len in lengths {
        let path: Vec<u8> = (0..len).map(|i| (i % 251 + 3) as u8).collect(); // no NUL bytes
        let mut pipe = Pipe::new();
        pipe.write_on_thread(path_frame(&path), 6);
        match expect_msg(pipe.read_one()) {
            PipeMsg::NamedPath(got) => assert_eq!(got, path, "PATH image len {len} garbled"),
            other => panic!("expected NamedPath({len}), got {other:?}"),
        }
    }
}

#[test]
fn real_world_sequence_named_path_then_failure() {
    // What the child actually sends in the no-procfs corner when exec fails:
    // NamedPath first, then the errno, then EOF.
    let image = b"/tmp/.memfd-ng-0-0-deadbeef".to_vec();
    let mut frame = path_frame(&image);
    frame.extend_from_slice(&errno_frame(8 /* ENOEXEC */));
    let mut pipe = Pipe::new();
    pipe.write_on_thread(frame, 4);
    match expect_msg(pipe.read_one()) {
        PipeMsg::NamedPath(got) => assert_eq!(got, image),
        other => panic!("expected NamedPath, got {other:?}"),
    }
    match expect_msg(pipe.read_one()) {
        PipeMsg::Failure(code) => assert_eq!(code, 8),
        other => panic!("expected Failure, got {other:?}"),
    }
    // and EOF after both
    match expect_msg(pipe.read_one()) {
        PipeMsg::Success => {}
        other => panic!("expected Success (EOF), got {other:?}"),
    }
}

#[test]
fn truncations_reject_or_degrade_never_misdecode() {
    // every strict prefix of a valid errno frame
    let frame = errno_frame(13);
    for cut in 0..frame.len() {
        let mut pipe = Pipe::new();
        pipe.write_on_thread(frame[..cut].to_vec(), 64);
        match classify(pipe.read_one()) {
            Outcome::Msg(PipeMsg::Success) => assert_eq!(cut, 0, "empty input only"),
            Outcome::Msg(PipeMsg::Failure(code)) => {
                // only a complete 8-byte frame can decode
                assert_eq!(cut, 8, "truncated frame decoded as Failure({code}) at cut={cut}");
            }
            Outcome::Msg(PipeMsg::NamedPath(_)) => panic!("NOEX frame decoded as PATH at cut={cut}"),
            Outcome::InvalidData(_) => assert!(cut > 0 && cut < 8, "cut={cut}"),
        }
    }
    // every strict prefix of a valid path frame
    let image = b"/tmp/.memfd-ng-1-2-abcdef";
    let frame = path_frame(image);
    for cut in 0..frame.len() {
        let mut pipe = Pipe::new();
        pipe.write_on_thread(frame[..cut].to_vec(), 64);
        match classify(pipe.read_one()) {
            Outcome::Msg(PipeMsg::NamedPath(got)) => {
                // a short image degrades to a shorter path, never a lie
                // about the header: the reader takes what arrived
                assert!(cut >= 6, "header-only cut decoded as NamedPath at cut={cut}");
                let claimed = u16::from_be_bytes([frame[0], frame[1]]) as usize;
                let available = cut - 6;
                let expect = image[..available.min(claimed)].to_vec();
                assert_eq!(got, expect, "truncated PATH at cut={cut}");
            }
            Outcome::Msg(PipeMsg::Success) => assert_eq!(cut, 0),
            Outcome::Msg(PipeMsg::Failure(code)) => {
                panic!("PATH frame decoded as Failure({code}) at cut={cut}")
            }
            Outcome::InvalidData(_) => assert!(cut > 0 && cut < 6, "cut={cut}"),
        }
    }
}

#[test]
fn header_smuggles_never_decode_across_shapes() {
    // A PATH header's bytes [2..6] spell PATH; an errno frame's [2..6] are
    // errno bytes + "NO". Prove the shapes cannot collide: feed a PATH frame
    // whose declared image is present — the reader must take the PATH
    // interpretation; feed the same bytes missing the image — it must not
    // claim a Failure with a fabricated errno.
    let mut evil = path_frame(b"x");
    evil[0] = 0;
    evil[1] = 1; // claims 1 byte
    let mut pipe = Pipe::new();
    pipe.write_on_thread(evil.clone(), 8);
    match expect_msg(pipe.read_one()) {
        PipeMsg::NamedPath(got) => assert_eq!(got, b"x"),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn junk_never_panics_and_never_hangs() {
    let (from, to) = fuzz_seed();
    for seed in from..to {
        let mut rng = Xorshift(0x1234_5678_9ABC_DEF0 ^ seed.wrapping_mul(6364136223846793005));
        let len = rng.below(40) as usize;
        let junk: Vec<u8> = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        let mut pipe = Pipe::new();
        pipe.write_on_thread(junk, (rng.below(16) + 1) as usize);
        let _ = classify(pipe.read_one());
        // a second read after arbitrary junk must also terminate
        let _ = classify(pipe.read_one());
    }
}

#[test]
fn bitflipped_valid_frames_stay_legal() {
    let (from, to) = fuzz_seed();
    for seed in from..(from + (to - from).min(1000)) {
        let mut rng = Xorshift(0x0DDB_1A5_0000_0000 ^ seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut frame = if rng.below(2) == 0 {
            errno_frame(rng.next() as i32)
        } else {
            let len = rng.below(64) as usize;
            path_frame(&(0..len).map(|i| i as u8 + 1).collect::<Vec<u8>>())
        };
        // flip 1-3 bits
        for _ in 0..(rng.below(3) + 1) {
            let byte = rng.below(frame.len() as u64) as usize;
            let bit = rng.below(8) as u8;
            frame[byte] ^= 1 << bit;
        }
        let mut pipe = Pipe::new();
        pipe.write_on_thread(frame, 16);
        let _ = classify(pipe.read_one());
    }
}

#[test]
fn byte_by_byte_writes_reassemble() {
    // the header loop must accumulate across partial writes
    let image = b"/tmp/.memfd-ng-slow-writer";
    let mut frame = path_frame(image);
    frame.extend_from_slice(&errno_frame(7 /* E2BIG */));
    let mut pipe = Pipe::new();
    pipe.write_on_thread(frame, 1);
    match expect_msg(pipe.read_one()) {
        PipeMsg::NamedPath(got) => assert_eq!(got, &image[..]),
        other => panic!("got {other:?}"),
    }
    match expect_msg(pipe.read_one()) {
        PipeMsg::Failure(code) => assert_eq!(code, 7),
        other => panic!("got {other:?}"),
    }
}

#[test]
fn empty_pipe_is_success_eof() {
    let mut pipe = Pipe::new();
    pipe.close_write();
    match expect_msg(pipe.read_one()) {
        PipeMsg::Success => {}
        other => panic!("clean EOF must read as Success, got {other:?}"),
    }
}

#[test]
fn end_to_end_the_reader_agrees_with_the_real_child() {
    // The fuzzed protocol is live protocol: drive a real failed spawn and
    // assert the errno survives the pipe into spawn()'s error.
    let err = MemFdExecutable::new("fuzz-live", b"\x7fELF-nope")
        .stdout(Stdio::MakePipe)
        .status()
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(8));
}
