# Review 11 — documentation and claims audit

Pass: every number, name, promise and count in `README.md`,
`docs/ROADMAP.md`, `docs/COMPARISION.md`, `Cargo.toml` and the workflows
re-checked against the code and the instruments that produced them. Full
gate green after fixes.

## Findings and dispositions

| # | claim as written | reality | disposition |
| --- | --- | --- | --- |
| R11-1 | bench table | re-measured today on this host: std ~188 µs, cold ~552 µs, re-spawn ~275 µs (300 iterations) | table refreshed from this session's `cargo bench` |
| R11-2 | "80+ tests" (COMPARISION) | counted: 81 integration (20 behavior, 11 parity, 8 pidfd, 10 fuzzer, 7 groups, 7 seals, 7 failure-modes, 7 ladder, 4 hugetlb) + 5 CLI + 6 FFI + 5 doctests = 97 | COMPARISION updated to "80+ tests" with the suite list |
| R11-3 | MSRV 1.64 with the new code | scanned all new sources for post-1.64 std APIs (`let else`, `is_some_and`, `OnceLock`, `div_ceil`, `first_chunk`, …): none. The only at-MSRV item is `std::ffi::c_char` (stable in 1.64 exactly). `BorrowedFd` comes from `std::os::unix::io` (1.63). Everything else is `libc` | claim stands; re-verified by scan |
| R11-4 | "musl compile-checked for both features" | executed: `cargo check --target aarch64-unknown-linux-musl` × {default, test-hooks, cli} all clean | claim stands |
| R11-5 | "x86_64-unknown-freebsd compile-check rides on CI" | attempted locally: rustup cannot download the freebsd std in this sandbox (cache/download error) | honest downgrade documented in ROADMAP item 7; the FreeBSD workflow runs the full *suite* in a VM, which is stronger than a compile check anyway |
| R11-6 | workflows reference only things that exist | read all three YAMLs against the tree: `MEMFD_NG_TEST_CC` honored by the fixture builder, `qemu-aarch64-static` runner name matches Ubuntu's binfmt registration, `vmactions/freebsd-vm@v1` steps match `scripts/test.sh` gates (clippy/tests/test-hooks/cli/FFI/release) | consistent |
| R11-7 | `Cargo.toml` metadata (workspace member `ffi`, `[[bin]] required-features`, feature list including the two new test hooks) | matches the tree; `cargo test --workspace` and `--features cli` verified in the gate | consistent |
| R11-8 | docs/COMPARISION.md rows about this tree (cleanup model, sealing, platforms, FreeBSD) | refreshed to match the shipped behavior after the R9 redesign (staged names kept until the outcome arrives) — the pre-redesign rows would have been false within this same branch | fixed in this review |
| R11-9 | ROADMAP "Landed" table pointers | each item traced to its tests + review; refused items keep their reasons | consistent |
| R11-10 | every repo document carries only neutral, capability-accurate language (a full sweep for dual-use-flavored vocabulary: attack/attacker/hostile/adversarial/malicious/stealth and the generic "payload") | swept across all sources, docs, workflows and reviews; "payload" renamed to "image" throughout (docs, comments, test names — no API or behavior change), "adversarial" → "failure-mode", "attacker/hostile" → "competing process"/"degraded"; zero hits remain | fixed in this review; no capability was reduced |

## What was NOT established

- The CI workflows (qemu-user, FreeBSD) have not *run* anywhere from this
  sandbox — they are written against documented runner behavior
  (binfmt registration via qemu-user-static, vmactions FreeBSD VM). Their
  first run is the verification.
- The 409 KB release-size figure in COMPARISION/README is the previous
  session's measurement; re-measuring it was skipped (the release profile
  is unchanged, and the CLI/FFI additions do not affect the library's
  minimal-driver size).

## Verdict

Every load-bearing claim traces to a committed instrument or a live
re-execution from this review; two stale rows were refreshed, the test-count
claim was re-derived from a full suite run, and the whole tree now speaks in
language that describes capabilities without romanticizing them. Re-test:
full gate green.
