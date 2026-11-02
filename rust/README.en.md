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

## Check and test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI (the job `rust` of `.github/workflows/build.yml`) runs these three commands.

To run them before every commit that changes the Rust source, enable the hook
once per clone (from the top of the repository):

```sh
git config core.hooksPath .githooks
```

The hook also keeps its earlier check of the clang-format of the staged C
changes. `git commit --no-verify` skips it for one commit; CI still runs.

The comparison with the C version is `tools/softflowd_test_collector.py
compat`; the commands are in
[doc/DIFFERENCES-FROM-C.en.md](doc/DIFFERENCES-FROM-C.en.md).

## Development

See [AGENTS.md](AGENTS.md) for the conventions (comments, commit messages,
patches).
