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

Needs Rust 1.85 or newer (edition 2024) and libpcap (`libpcap-dev`).

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

The comparison with the C version is `tools/softflowd_test_collector.py
compat`; the commands are in
[doc/DIFFERENCES-FROM-C.en.md](doc/DIFFERENCES-FROM-C.en.md).

## Development

See [AGENTS.md](AGENTS.md) for the conventions (comments, commit messages,
patches).
