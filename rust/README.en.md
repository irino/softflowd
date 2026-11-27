# rsoftflowd

A Rust rewrite of [irino/softflowd](https://github.com/irino/softflowd), a
flow-based network monitor. The executables are `rsoftflowd` and
`rsoftflowctl`.

## Introduction

`rsoftflowd` listens promiscuously on a network interface and semi-statefully
tracks network flows. The flows are exported as NetFlow version 1, 5, 9 or 10
(IPFIX) datagrams, or as PSAMP. It tracks IPv6 flows and exports to IPv6
hosts.

The C version in the parent directory is the reference: the Rust version
follows it (command line, exported datagrams, control socket). Where the Rust
version still differs, the differences are listed and tracked in
[doc/DIFFERENCES-FROM-C.en.md](doc/DIFFERENCES-FROM-C.en.md). The version
number (`0.1.0`) is independent of the C and the C++ versions.

## Companion Project: NetFlow Collector

If you need a NetFlow collector, see the companion project "flowd"
(http://www.mindrot.org/projects/flowd/). Any NetFlow-compatible collector
works with rsoftflowd.

## Build

The version of Rust is pinned in `rust-toolchain.toml`; rustup installs it at
the first `cargo` run in `rust/`. The minimum is Rust 1.88. libpcap
(`libpcap-dev`) is needed.

```sh
cd rust
cargo build --release      # target/release/rsoftflowd and rsoftflowctl
```

## Executables

- `rsoftflowd`: the daemon. It takes the options of the C version `softflowd`,
  short and long (`rsoftflowd -h`).
- `rsoftflowctl`: sends a command to the control socket of a running daemon:
  `rsoftflowctl [-c|--control-socket PATH] <command>`, for example `statistics`,
  `dump-flows`, `expire-all` or `shutdown`. The default socket is
  `/var/run/softflowd.ctl`.
- `cargo build` writes the manual pages `man/rsoftflowd.8` and
  `man/rsoftflowctl.8` (`build.rs`).

## Check and test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo test` runs the unit tests and the integration tests in `tests/`.
CI (the job `rust` of `.github/workflows/build.yml`) runs these three commands.

To run them before every commit that changes the Rust source, enable the hook
once per clone (from the top of the repository):

```sh
git config core.hooksPath .githooks
```

The hook also keeps its earlier check of the clang-format of the staged C
changes. `git commit --no-verify` skips it for one commit; CI still runs.

## Comparison with the C version

The tools are in `../tools` (Python, standard library only; see
[../tools/README.md](../tools/README.md)). They need the C version built in the
top directory (`autoreconf -if; ./configure; make`, see `../README.md`) and
the Rust version built as above. Run them from the top directory. The commands
and the list of differences are in
[doc/DIFFERENCES-FROM-C.en.md](doc/DIFFERENCES-FROM-C.en.md).

**The gate** runs `cargo fmt --check`, `cargo clippy` and `cargo test` and the
comparison of the two builds (`softflowd_test.py --strict`), and sorts every
reported difference with `tools/gate_expected.json`. The last line is
`GATE: PASS` or `GATE: FAIL`:

```sh
tools/softflowd_test_suite.py gate --rust-dir rust -- --a ./softflowd \
    --b rust/target/release/rsoftflowd --ctl-a ./softflowctl \
    --ctl-b rust/target/release/rsoftflowctl --skip-build --skip-cpp --skip-rust \
    --skip-static --skip-direct --skip-psamp --collector python --no-benchmark --no-gauge-clock
```

**The garbage corpus** reads mutated pcaps with both builds; the exported flows,
the statistics and the exit status must agree and the Rust version must not
crash. Quick by default, `--full` for the whole corpus:

```sh
tools/softflowd_test_suite.py fuzz --a ./softflowd --b rust/target/release/rsoftflowd
```

**Golden datagrams** save what the Rust version exports for every case of the
byte for byte step, and compare a later build with it, without the C version.
A patch that is not about the format must not change a byte. The directory is
large (one file per case), so keep it outside the repository:

```sh
tools/softflowd_test_suite.py --b rust/target/release/rsoftflowd --save-golden DIR
tools/softflowd_test_suite.py --b rust/target/release/rsoftflowd --check-golden DIR
```

The checks of a live capture (signals, shutdown, start order) need root: they
are SKIPPED otherwise.

## Development

See [AGENTS.md](AGENTS.md) for the conventions (comments, commit messages,
patches).
