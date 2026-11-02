# Differences between rsoftflowd and the C version

Status of `rust/` compared with the C version of this tree.  Every item says
how it was found:

- **measured**: found by running both binaries.
- **source**: found by reading the source or the repository, not run.
- **not measured**: known to be unchecked.

## Measurement

| | |
|---|---|
| Measured on | 2026-11-02 |
| Base | upstream `3281d94`, before the patches of this series (they do not change the behavior) |
| Tools | Rust 1.85.1, debug build, built-in Python collector |
| C binary | the development C build of the same commit |

The numbers in "Found" and "Fixed in" below are the numbers of the patches of
the series started on 2026-11-02 (`0001` is the patch that added this
document).  The subject of the patch is the stable key: the commit hash
changes when a patch is applied.

## Status

| ID | Summary | Found | Status | Fixed in | Verified |
|----|---------|-------|--------|----------|----------|
| D1 | NetFlow v9: extra elements differ | 2026-11-02 | open | | |
| D2 | IPFIX flowEndReason values are wrong | 2026-11-02 | fixed | 0007 Fix the flowEndReason values of the Rust version | 2026-11-02, compat `--strict` C against Rust: IPFIX MATCHED for the IPv4 and IPv6 pcaps (24 records each) |
| D3 | Command line errors: 47 of 75 cases differ | 2026-11-02 | open | | |
| D4 | No ntopng | 2026-11-02 | open | | |
| D5 | Program name and version not unified | 2026-11-02 | open | | |
| D6 | Log format differs | 2026-11-02 | open | | |
| D7 | PSAMP records differ (not measured) | 2026-11-02 | open | | |
| D8 | compat step 5 not reached (not measured) | 2026-11-02 | open | | |
| D9 | Maximum lifetime: C compares with `>`, Rust with `>=` | 2026-11-02 | open | | |
| D10 | Overflow eviction: C keeps the previous flowEndReason, Rust writes lack of resources | 2026-11-02 | open | | |
| R1 | `rust/AGENTS.md` does not match the repository | 2026-11-02 | fixed | 0006 Update AGENTS.md and the README of the Rust version to the current policy | 2026-11-02, read against the repository |
| R2 | No Rust job in CI | 2026-11-02 | fixed | 0004 Add a CI job that checks the format, clippy and the tests of the Rust version | 2026-11-02, the commands run locally on a clean checkout |
| R3 | `cargo fmt --check` fails | 2026-11-02 | fixed | 0002 Format the Rust version with cargo fmt | 2026-11-02, local |
| R4 | `cargo clippy -D warnings` fails (20 warnings) | 2026-11-02 | fixed | 0003 Fix the warnings of clippy in the Rust version | 2026-11-02, local |
| R5 | `cargo doc -D warnings` fails | 2026-11-02 | open | | |
| R6 | The main part of the daemon is in the binary | 2026-11-02 | open | | |
| R7 | `unsafe` in 22 lines | 2026-11-02 | open | | |
| R8 | `rust/tests/run_compat_tests.py` and `rust/doc/test.ja.md` duplicate the tools | 2026-11-02 | open | | |
| R9 | CI fails when the stable Rust gets newer: new clippy lints (`collapsible_if`, `is_multiple_of`) | 2026-11-02 (the log of the `rust` job) | open | | |

"fixed" means that a patch fixed it and "Verified" says how it was checked.
Do not delete a fixed row; the history is the point.

### How to update this file

- A patch that fixes an item changes its row in the same patch: Status
  `fixed`, "Fixed in" with the number and the subject of the patch, and
  "Verified" with the date and what was run.
- A difference that is found later gets a new row with a new ID; IDs are
  never reused.
- To measure again, run the commands in "How to reproduce", then update
  "Measured on", "Base" and the text of the items whose result changed.

## How to reproduce

```sh
# Needs rustc/cargo 1.85 or newer (edition 2024) and libpcap-dev.
python3 tools/gen_ci_smoke_pcap.py -n 20 pcaps/http.cap
python3 tools/gen_ci_smoke_pcap.py -6 -n 20 pcaps/v6-http.cap
python3 tools/softflowd_test_collector.py compat --skip-cpp \
    --collector python --pcap-dir pcaps --no-benchmark --no-gauge-clock
```

The last pair of the output, `A=softflowd vs B=rsoftflowd`, is the Rust one.
See `tools/softflowd_test_collector.py` for the other options.

## Result of the compat test (measured)

| Step | Result |
|------|--------|
| 1 command line options | PASSED |
| 2 control socket | PASSED |
| 3 NetFlow v1, IPv4 and IPv6 pcaps | MATCHED (24 records) |
| 3 NetFlow v5, IPv4 and IPv6 pcaps | MATCHED (24 records) |
| 3 NetFlow v9, IPv4 and IPv6 pcaps | FAILED (D1) |
| 3 IPFIX, IPv4 and IPv6 pcaps | FAILED (D2) |
| 4 PSAMP | not run for Rust: the PSAMP records are known to differ (D7) |
| 5 byte for byte, expiry log, -M, live capture | not reached (see D8) |

In the failing tests the first 13 columns of every record (times, addresses,
ports, protocol, flags, packets, bytes) are identical.  Only the extra
information elements differ.

## Differences

The text of each item is the state on the "Measured on" date; the Status table
says what has been fixed since.

### D1. NetFlow v9 extra elements (measured)

In the decoded v9 records C shows flowEndReason (136) and flowDirection (61).
Rust shows icmpTypeCode (32, on TCP and UDP records too) and vlanId (58) and
neither 136 nor 61.  The Rust v9 templates list 32 and 58 and not 61 and 136
(`src/exporter/export.rs`, `build_templates()`, the `version == 9` branch).
What the C v9 templates contain was not read out; only the decoded records
were compared.

### D2. IPFIX flowEndReason values (measured, a Rust bug)

The numbers do not follow the IANA IPFIX registry for flowEndReason (IE 136),
which the C version uses (`softflowd.h`, `IPFIX_flowEndReason_*`).

| Reason | C (correct) | Rust |
|--------|-------------|------|
| idle timeout | 1 | 4 |
| active timeout | 2 | 1 |
| end of flow | 3 | 3 |
| lack of resources | 5 | 2 |

In the test 12 of 20 flows have idle timeout: C writes 1, Rust writes 4.
Rust: `src/bin/rsoftflowd.rs`, about lines 785 and 867-893.  The C logic is
`flow_update_expiry()` in `softflowd.c`.

### D3. Command line errors (measured)

The 75 cases of `PARITY_CLI_ERROR_CASES` were run on both binaries and the
exit status compared (text of messages was not compared).  47 differ:

| Kind | Cases | Examples |
|------|-------|----------|
| C exits 1, Rust exits 2 (clap usage error) | 20 | `-z`, `-v 99`, `-T bogus`, `-r X -r X` |
| Rust accepts, C rejects (exit 0 against 1) | 18 | `-i ""`, `-n ""`, `-t bogus`, `-t udp=abc`, `-I abc`, `-i nonexistent0`, a bad capture filter, a bad control socket path |
| C accepts, Rust rejects | 7 | `-s abc`, `-B abc`, `-C abc`, `-R abc`, `-R 99999`, `-R -1`, `-c /nonexistent/dir/ctl` |
| Rust panics (exit 101) | 2 | `-T port`, `-t maxlife=99999999999` |

The 28 cases not listed here have the same exit status.
In the "Rust accepts" group wrong input is only logged, and the daemon goes
on or exits with 0.  Which of the other two groups are wanted
(clap's exit status 2 against the C exit status 1) is a decision, not a bug.

### D4. ntopng (source)

No reference to ntopng in `rust/src`.  The C version has `ntopng.c`.

### D5. Program name and version (source)

The `softflowd` and `softflowctl` aliases in `Cargo.toml` are one-line
`include!` files.  Version: Rust 0.1.0.  The names in the usage, the syslog
ident and `rust/man/*.8` are not unified yet.

### D6. Logging (measured)

Rust prints `env_logger` lines (`[time LEVEL rsoftflowd] ...`) where C writes
the plain message.  Not compared in detail.

### D7. PSAMP (not measured)

The help of `compat --psamp` says that the Rust PSAMP records differ.  The
difference has not been listed.

### D8. Step 5 of the compat test (not measured)

The byte for byte comparison stops at the failing step 3, so it was not run.
It needs D1 and D2 fixed first.

### D9. Maximum lifetime comparison (source)

A flow is expired by `maxlife` when its age is greater than the limit in C
(`softflowd.c`, `flow_update_expiry()`: `... > ft->param.maximum_lifetime`) and
when it is greater than or equal to the limit in Rust
(`src/bin/rsoftflowd.rs`: `... >= param.maximum_lifetime`).  Not run; the
effect is one second at the boundary.

### D10. flowEndReason on overflow eviction (source)

When flows are expired because the table is full (`R_OVERFLOWS` in C) the C
version does not set flowEndReason and the flow keeps its previous value (the
code around `softflowd.c:1734`).  The Rust version writes lack of resources
(`evict_oldest_flow()`).  C sets lack of resources for a hash collision and
for flows over the byte limit.  Which one is wanted is a decision; C may have
simply forgotten the case.

## Repository state (source)

IDs R1 to R8 of the Status table.  The state is the one on the "Measured on"
date.

- **R1**: `rust/AGENTS.md` says Conventional Commits, no `unsafe`, and
  mentions `reference/` and goflowd.  The commit style here is not
  Conventional Commits, `unsafe` is used (R7) and `rust/reference/` does not
  exist.
- **R2**: `.github/workflows/build.yml` has no Rust job.  The Rust build was
  only run by `compat`.
- **R3, R4, R5**: the baseline of the checks for CI was `cargo fmt --check`
  failing (2444 lines of diff), `cargo clippy --all-targets -- -D warnings`
  failing (20 warnings) and `cargo doc` with `-D warnings` failing (an
  unresolved link `idx:`).  `cargo test` passed (17 tests).
- **R6**: `src/bin/rsoftflowd.rs` has 1056 lines; the main part of the daemon
  is in the binary, not in the library.
- **R7**: `unsafe` appears in 22 lines (`rsoftflowd.rs` 7, `export.rs` 12,
  `psamp.rs` 1, `lib.rs` 1, `net_util_unsafe.rs` 1; the word may be in a
  comment).
- **R8**: `rust/tests/run_compat_tests.py` (480 lines) and `rust/doc/test.ja.md`
  are the prototype of `tools/softflowd_test_collector.py` (the maintainer's
  statement of 2026-11-02) and are to be deleted.  Whether other scripts in
  `tools/` duplicate it was checked: only `tools/deprecated/collector.pl` and
  `tools/deprecated/benchmark_export.sh`, which `collect` and `bench` replace,
  do.
- **R9**: the `rust` job of CI installed the newest stable Rust, whose clippy
  has new lints.  The log showed `collapsible_if` in `src/control.rs` and
  `src/exporter/export_common.rs`; a local run with Rust 1.91.1 showed
  `collapsible_if` in `src/bin/rsoftflowd.rs` (10 places) and
  `manual_is_multiple_of` as well.  The collapsed `if` uses let chains, which
  need Rust 1.88.
