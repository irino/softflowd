## Project Overview
- rsoftflowd and rsoftflowctl: the Rust version of softflowd (https://github.com/irino/softflowd).
  It exports NetFlow v1/v5/v9, IPFIX (https://datatracker.ietf.org/doc/html/rfc7011) and PSAMP.
- The C version in the parent directory is the reference, and `cpp/` is the C++ version.
  The Rust version follows the C version: command line, exported datagrams, control socket.
  A bug of the C version is fixed in the Rust version, not reproduced (the C++ version does the same).
- goflowd (https://github.com/irino/goflowd) is not ported for now.
  Its features are to be integrated only into the Rust version in the end.
- The output binaries are `rsoftflowd` and `rsoftflowctl`.
  The `softflowd` and `softflowctl` aliases in Cargo.toml are to be removed.
- 
- The version number is independent of the C and the C++ versions.

## Commands
- Build (debug): cargo build
- Build (release): cargo build --release
- Format: cargo fmt
- Lint: cargo clippy --all-targets -- -D warnings
- Test: cargo test
- Toolchain: Rust 1.85 or newer (edition 2024) and libpcap-dev.
- CI (`.github/workflows/build.yml`, job `rust`) runs `cargo fmt --check`, clippy with `-D warnings` and `cargo test`.
  Run the same three commands in `rust/` before a patch.
- Comparison with the C version: `python3 tools/softflowd_test_collector.py compat --skip-cpp`
  (see the commands in `doc/DIFFERENCES-FROM-C.en.md`).

## Code Style Guidelines
- Rust Style Guideline https://doc.rust-lang.org/style-guide/
- Source code comments are in English.
- Documentation comments are rustdoc (`//!` for a module, `///` for an item), not Doxygen.
- Function names and the file structure follow the C and C++ versions where practical.
  Functions keep the snake_case names of the C version.
  Types follow Rust style (`struct FLOW` becomes `Flow`).
  The name of the C/C++ original is to be kept in the rustdoc comment (an `Original:` section).
- `unsafe` is used in a few places (R7 in `doc/DIFFERENCES-FROM-C.en.md`). As a general rule, the use of `unsafe` code is prohibited. If it must be used due to a lack of alternatives, it should be localized (e.g., in a file named `unsafe.rs`).
- 
## Git
- Commit message: English, no Conventional Commits prefix, one imperative sentence like the existing log,
  e.g. `Fix the warnings of clippy in the Rust version`.
- Small, targeted diffs. One fix per patch.
- Patches are numbered (`git format-patch`), and the number is the one used in `doc/DIFFERENCES-FROM-C.*.md`.
- A patch that fixes a difference updates its row in `doc/DIFFERENCES-FROM-C.en.md` and `.ja.md`
  (status, patch number and subject, date of the check).

## Directory
|Directory|Description                                                              |
|---------|-------------------------------------------------------------------------|
|src      |Library source (`src/exporter` has the export code)                      |
|src/bin  |rsoftflowd and rsoftflowctl                                              |
|tests    |Test code                                                                |
|doc      |Documents (the differences from the C version)                           |
|man      |Man pages and the extra roff text used by build.rs                       |
