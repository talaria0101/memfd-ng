//! Spawn-latency harness: `cargo bench` (harness = false).
//!
//! Compares memfd-ng against std::process::Command on identical workloads so
//! the numbers are grounded in something external. The interesting columns:
//! - cold image: memfd written per spawn (the normal library path)
//! - prepared image: written and sealed once, then re-execed
use std::io::Write;
use std::process::Command;
use std::time::Instant;

use memfd_ng::MemFdExecutable;

fn body() -> &'static str {
    r#"
#include <unistd.h>
int main(void) { return 0; }
"#
}

fn build_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let src = dir.join("bench_stub.c");
    std::fs::write(&src, body()).unwrap();
    let bin = dir.join("bench_stub");
    let ok = Command::new("cc")
        .args(["-static", "-O2", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .expect("cc")
        .success();
    assert!(ok, "failed to build bench fixture");
    bin
}

fn time_n<F: FnMut()>(label: &str, n: u32, mut f: F) -> std::time::Duration {
    // warm-up
    for _ in 0..5 {
        f();
    }
    let start = Instant::now();
    for _ in 0..n {
        f();
    }
    let d = start.elapsed();
    println!("{label:>28}: {:>10.1?}  ({:.3} us/spawn)", d, d.as_micros() as f64 / n as f64);
    d
}

fn main() {
    let n: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let tmp = std::env::temp_dir().join(format!("memfd-ng-bench-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let bin = build_fixture(&tmp);
    let code = std::fs::read(&bin).unwrap();

    println!("== spawn exit-0 fixture, {n} iterations ==");
    time_n("std::process::Command", n, || {
        Command::new(&bin).status().unwrap();
    });
    time_n("memfd-ng cold", n, || {
        MemFdExecutable::new("bench", &code).status().unwrap();
    });
    time_n("memfd-ng prepared", n, || {
        let mut exe = MemFdExecutable::new("bench", &code);
        exe.prepare().unwrap();
        for _ in 0..1 {
            exe.status().unwrap();
        }
    });
    // the prepared loop above includes prepare() each time; measure the
    // marginal cost of prepared spawns without the prepare:
    let mut exe = MemFdExecutable::new("bench", &code);
    exe.prepare().unwrap();
    time_n("memfd-ng re-spawn", n, || {
        exe.status().unwrap();
    });

    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::io::stdout().flush();
}
