# rsoftflowd

Welcome to **rsoftflowd**, a flow-based network monitor.

## Introduction

`rsoftflowd` listens promiscuously on a network interface and semi-statefully
tracks network flows. These flows can be reported using NetFlow version 1, 5, 
9, or 10 (IPFIX) datagrams. `rsoftflowd` is fully IPv6 capable: it can track IPv6 flows and 
export to IPv6 hosts.

`rsoftflowd` is a Rust rewrite/port of [softflowd](https://github.com/irino/softflowd).

## Companion Project: NetFlow Collector

If you are in need of a NetFlow collector, you may be interested in 
softflowd's companion project "flowd" (http://www.mindrot.org/projects/flowd/). 
flowd is a NetFlow collector that is maintained in parallel with
softflowd and includes a few handy features, such as the ability
to filter flows it receives as well as Perl and Python APIs to its
storage format. 

*Note: You don't have to use flowd: any NetFlow-compatible collector should work with rsoftflowd.*

## Building

To build `rsoftflowd` and its control tool `rsoftflowctl`, run:

```bash
cargo build --release
```

This will generate the binaries under `target/release/`.
