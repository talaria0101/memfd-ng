# Review 5 — documentation and claims audit

Pass: every number, name and promise in `README.md`, `docs/ROADMAP.md`,
`Cargo.toml` and the test fixtures re-checked against the code and the
instruments that produced them. Build + full suite green after fixes.

## Findings and dispositions

| # | claim as written | reality | disposition |
| --- | --- | --- | --- |
| R5-1 | fixture described as a "121-byte ELF64" | the array is **136 bytes** | README fixed; fixture re-measured programmatically |
| R5-2 | fixture `p_filesz`/`p_memsz` = `0x90` (144) — **8 bytes past end of file**; the kernel tolerated it, which is tolerance a deterministic fixture must not rely on | fixed to `0x88` (exactly the file size); tiny-elf tests re-run green |
| R5-3 | bench table carried the first session's run (172/529/273 µs) | fresh run measured 178/563/283 µs | table refreshed from `cargo bench`, with a run-variance note |
| R5-4 | MSRV 1.64 claimed in `Cargo.toml` | **false at review time**: `std::os::fd` (child.rs) stabilized in 1.66 | imports moved to `std::os::unix::io`; remaining lib surface scanned feature-by-feature (atomics, `matches!`, `bool::then`, `IoSlice`, inline format args — all ≤ 1.58) |
| R5-5 | "no clang required" (tests) | verified: fixtures build with `cc` (gcc 15.3 here); no clang in this environment | claim stands |
| R5-6 | "x86_64/aarch64 glibc+musl build-verified; static musl runtime-verified" | re-verified against the current tree: all four targets build; the static musl binary runs the full smoke suite | claim stands |
| R5-7 | zero upstream references in the tree | re-grepped across `*.rs`, `*.toml`, `*.md`, `*.sh`, `LICENSE`, and the git log: zero hits | rule holds |
| R5-8 | `docs/ROADMAP.md` items | each accepted item traced to a code hook that exists or a measured gap; refused items keep reasons | consistent |
| R5-9 | `scripts/test.sh` is the documented gate | executed end to end: clippy `-D warnings`, both test suites, release build, bench | passes |
| R5-10 | `Cargo.toml` metadata (keywords, categories, license field, description) | checked against registry conventions (`os::unix-apis`, `0BSD`) | consistent |

## Verdict

Every load-bearing claim now traces to a committed instrument or a code path
that was re-executed this review. Two claims were wrong and are fixed (R5-1
with its kernel-tolerance hazard, R5-4); one was refreshed (R5-3).
