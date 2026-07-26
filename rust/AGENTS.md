## Project Overview
- RUST Netflow v1/v5/v9 and IPFIX (https://datatracker.ietf.org/doc/html/rfc7011) Exporter program
- porting from softflowd (URL: https://github.com/irino/softflowd, Lnaguage: C) to Rust
- porting from goflowd (URL: https://github.com/irino/goflowd, Lnaguage: go) to Rust

## Commands
- Build for normatl (debug): cargo build
- Build for release: cargo build --release
- Formatter: cargo fmt
- Test: cargo test

## Code Style Guidelines
- Rust Style Guideline https://doc.rust-lang.org/style-guide/
- Do not use unsafe rust code

## Git
- Commit message: Conventional Commits (https://www.conventionalcommits.org/en/v1.0.0/)

## Directory
|Directory|Description                                                      |
|---------|-----------------------------------------------------------------|
|src      |Soruce code                                                      |
|tests    |Test code                                                        |
|reference|Reference source code which is managed by other git repogitories.|
