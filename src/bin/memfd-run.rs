//! `memfd-run`: exec a file straight from memory from your shell.
//!
//! Reads the file's bytes, stages them in a memfd (falling back to the tmpfs
//! ladder exactly like the library), and executes them in a child process.
//!
//! ```text
//! memfd-run [--name NAME] [--argv0 ARGV0] [--] FILE [ARGS...]
//! ```
//!
//! Compiled only under the `cli` feature to keep the library lean:
//! `cargo build --features cli`.

use std::io::Write;
use std::process::ExitCode;

use memfd_ng::{MemFdExecutable, Stdio};

fn usage() -> ! {
    eprintln!(
        "usage: memfd-run [--name NAME] [--argv0 ARGV0] [--] FILE [ARGS...]\n\
         \n\
         Reads FILE into memory, stages it as a sealed memfd and executes it.\n\
         ARGS are passed to the program; the child's exit code is propagated\n\
         (a signal death becomes 128+signal). The library never touches disk\n\
         unless the kernel refuses fd-based exec entirely."
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut name: Option<String> = None;
    let mut argv0: Option<String> = None;
    let mut file: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut no_more_flags = false;

    while let Some(a) = args.next() {
        if !no_more_flags && a == "--" {
            no_more_flags = true;
        } else if !no_more_flags && a == "--name" {
            name = Some(args.next().unwrap_or_else(|| usage()));
        } else if !no_more_flags && a == "--argv0" {
            argv0 = Some(args.next().unwrap_or_else(|| usage()));
        } else if !no_more_flags && a.starts_with('-') && a != "-" {
            eprintln!("memfd-run: unknown flag {a:?}");
            usage();
        } else if file.is_none() {
            file = Some(a);
        } else {
            rest.push(a);
        }
    }

    let file = file.unwrap_or_else(|| usage());
    let code = match std::fs::read(&file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("memfd-run: cannot read {file}: {e}");
            return ExitCode::from(126);
        }
    };
    let name = name.unwrap_or_else(|| {
        std::path::Path::new(&file)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "memfd-run".to_string())
    });

    let mut exe = MemFdExecutable::new(&name, &code);
    if let Some(a0) = argv0 {
        exe.set_program(std::ffi::OsStr::new(a0.as_str()));
    }
    exe.args(&rest);
    // keep the child's stdio attached to the terminal unless the caller pipes
    exe.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());

    match exe.status() {
        Ok(status) => {
            let _ = std::io::stdout().flush();
            match status.code() {
                Some(c) => ExitCode::from(c as u8),
                None => match status.signal() {
                    Some(sig) => ExitCode::from((128 + sig) as u8),
                    None => ExitCode::from(1),
                },
            }
        }
        Err(e) => {
            eprintln!("memfd-run: exec failed: {e}");
            ExitCode::from(126)
        }
    }
}
