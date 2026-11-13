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
| D1 | NetFlow v9: extra elements differ | 2026-11-02 | fixed | 0011 Use the same templates for NetFlow v9 as for IPFIX | 2026-11-02, compat `--strict` C against Rust: NetFlow v9 MATCHED for the IPv4 and IPv6 pcaps (24 records each); `tests/netflow9_templates.rs` fails on the old code |
| D2 | IPFIX flowEndReason values are wrong | 2026-11-02 | fixed | 0007 Fix the flowEndReason values of the Rust version | 2026-11-02, compat `--strict` C against Rust: IPFIX MATCHED for the IPv4 and IPv6 pcaps (24 records each) |
| D3 | Command line errors: 47 of 75 cases differ | 2026-11-02 | open | | |
| D4 | No ntopng | 2026-11-02 | fixed | Add the export to ntopng (-v ntopng) as an optional Cargo feature | 2026-11-02, integration test passes (feature on); note that -v ntopng-json is not ported |
| D5 | Program name and version not unified | 2026-11-02 | fixed | 0016 Remove alias binaries | 2026-11-02, cargo build generates only rsoftflowd and rsoftflowctl |
| D6 | Logging | 2026-11-02 | fixed | Implement syslog and stderr logging matching C versions and messages | 2026-11-02, integration test captures stderr and compares first four lines with C wording |
| D7 | PSAMP message headers (sequence number and export time) differ from C | 2026-11-02 | fixed | Fix PSAMP sequence number and export time in psamp.rs | 2026-11-07, integration test checks sequence numbers of the first 20 messages for a 120-packet pcap |
| D8 | compat step 6 not reached (not measured) | 2026-11-02 | fixed | 0011 Use the same templates for NetFlow v9 as for IPFIX | 2026-11-02, step 6 ran for the first time (its result is D12) |
| D9 | Maximum lifetime: C compares with `>`, Rust with `>=` | 2026-11-02 | fixed | 0014 Compare the maximum lifetime with > as the C version does | 2026-11-02, unit test maximum_lifetime_expiry_boundary passes (fails on old code) |
| D10 | Overflow eviction: C keeps the previous flowEndReason, Rust writes lack of resources | 2026-11-02 | open | | |
| D11 | NetFlow v9 option template: C has interfaceName (IE 82), Rust has not | 2026-11-02 | fixed | 0015 Add interfaceName to the NetFlow v9 option template | 2026-11-02, unit test test_netflow_v9_option_template_has_interface_name passes (fails on old code) |
| D12 | compat step 6: most byte-for-byte checks differ (see the text) | 2026-11-02 | open | | |
| D13 | Command line (part of D3): wrong `-t` options are accepted, and a large time panics | 2026-11-02 | fixed | 0012 Reject the wrong -t options as the C version does | 2026-11-02, the 75 cases of D3 run again: the cases of `-t` no longer differ (exit status differs in 38 cases, was 47); unit tests of `parse_duration` and `apply_timeouts` |
| D14 | Command line (part of D3): `-T port` panics; C accepts it | 2026-11-02 | fixed | 0013 Accept -T port in the Rust version | 2026-11-02, the 75 cases of D3 run again: no panic is left (exit status differs in 37 cases, was 38); a test of the names of the levels |
| D15 | Overflow eviction: Rust dropped evicted flows instead of exporting them (part of D12) | 2026-11-02 | fixed | Export evicted flows in evict_oldest_flow() | 2026-11-02, unit test test_flow_eviction_exports passes (fails on old code) |
| D16 | NetFlow v5 flow_sequence grows twice as fast as in C (part of D12) | 2026-11-07 | fixed | Fix flow_sequence in export_build_flow_header() for NetFlow v5 | 2026-11-07, unit test test_exporter_netflow_v5_sequence_numbers passes (fails on old code) |
| D17 | Command line (part of D3): startup order and validation of `-n`, `-I`, interface, BPF filter, and control socket differ from C | 2026-11-02 | fixed | Check options and open capture before daemonizing, and reject bad -n and -I | 2026-11-07, unit tests for `parse_boot_time_reinit`, integration tests for exit status 1 without daemonizing |
| D18 | Ignored packets statistics: Rust did not count non-IP and too short packets (part of D12) | 2026-11-10 | fixed | Count non-IP and too short packets in parse_packet() and capture loop | 2026-11-10, unit tests for parse_packet() and counter test pass |
| R1 | `rust/AGENTS.md` does not match the repository | 2026-11-02 | fixed | 0006 Update AGENTS.md and the README of the Rust version to the current policy | 2026-11-02, read against the repository |
| R2 | No Rust job in CI | 2026-11-02 | fixed | 0004 Add a CI job that checks the format, clippy and the tests of the Rust version | 2026-11-02, the commands run locally on a clean checkout |
| R3 | `cargo fmt --check` fails | 2026-11-02 | fixed | 0002 Format the Rust version with cargo fmt | 2026-11-02, local |
| R4 | `cargo clippy -D warnings` fails (20 warnings) | 2026-11-02 | fixed | 0003 Fix the warnings of clippy in the Rust version | 2026-11-02, local |
| R5 | `cargo doc -D warnings` fails | 2026-11-02 | fixed | Escape unresolved link in rust/src/opts.rs | 2026-11-11, cargo doc passes |
| R6 | The main part of the daemon is in the binary | 2026-11-02 | fixed | Split main() into functions (targets, capture, signals, loop) | cargo test, fmt, clippy -D warnings pass |
| R6-1 | accumulate_stats() moved to stats.rs (part of R6) | 2026-11-11 | fixed | Move accumulate_stats() to stats.rs | cargo test, fmt, clippy -D warnings pass |
| R6-2 | Expiry code moved to expire.rs (part of R6) | 2026-11-12 | fixed | Move expiry code to expire.rs | cargo test, fmt, clippy -D warnings pass |
| R6-3 | Option helpers moved to opts.rs (part of R6) | 2026-11-13 | fixed | Move option helpers to opts.rs | cargo test, fmt, clippy -D warnings pass |
| R6-4 | Packet processing moved to capture.rs (part of R6) | 2026-11-13 | fixed | Move process_parsed_packet() to capture.rs | cargo test, fmt, clippy -D warnings pass |
| R6-5 | main() split into functions, targets and capture moved (part of R6) | 2026-11-14 | fixed | Split main() into functions (targets, capture, signals, loop) | cargo test, fmt, clippy -D warnings pass |
| R7 | `unsafe` in 22 lines | 2026-11-02 | open | | |
| R7-1 | Replace the clock() calls with a safe CPU clock helper (part of R7) | 2026-11-14 | fixed | Replace clock() with nix clock_gettime CPU clock helper | cargo test, fmt, clippy -D warnings pass |
| R8 | `rust/tests/run_compat_tests.py` and `rust/doc/test.ja.md` duplicate the tools | 2026-11-02 | open | | |
| R9 | CI fails when the stable Rust gets newer: new clippy lints (`collapsible_if`, `manual_is_multiple_of`) | 2026-11-02 (the log of the `rust` job) | fixed | 0008 Fix the clippy findings of Rust 1.91 and require Rust 1.88; 0009 Pin the Rust version of the Rust version and let CI use it | 2026-11-02, the three cargo commands of the CI job with Rust 1.91.1: fmt, clippy and 18 tests pass; the CI job itself has not run yet |
| R10 | Nothing checks the Rust version before a commit | 2026-11-02 | fixed | 0010 Add the checks of the Rust version to the pre-commit hook | 2026-11-02, tried in a scratch clone (see the text of R10) |

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
python3 tools/softflowd_test.py --skip-cpp \
    --collector python --pcap-dir pcaps --no-benchmark --no-gauge-clock
```

The last pair of the output, `A=softflowd vs B=rsoftflowd`, is the Rust one.
See `tools/softflowd_test.py` for the other options.

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
information elements elements differ.

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

After patch 0012 (D13, the `-t` cases): 38 cases differ; 20 are C 1 against
Rust 2, 10 are accepted by Rust, 7 are accepted by C and 1 panics (`-T port`).
After patch 0013 (D14, `-T port`): 37 cases differ and none panics.
In the "Rust accepts" group wrong input is only logged, and the daemon goes
on or exits with 0.  Which of the other two groups are wanted
(clap's exit status 2 against the C exit status 1) is a decision, not a bug.

### D4. ntopng

Export to ntopng (`-v ntopng`) is implemented as an optional Cargo feature `"ntopng"`, supporting the ZeroMQ PUB socket and nDPI serializer TLV payload (`zmq_msg_hdr_v4`). Note that `-v ntopng-json` is not ported.

### D5. Program name and version (source)

The `softflowd` and `softflowctl` aliases in `Cargo.toml` were removed; only
`rsoftflowd` and `rsoftflowctl` are built.

### D6. Logging (measured)

With `-d`, messages go to stderr as plain text without timestamp or level prefix, matching C. Without `-d`, messages go to syslog (ident `rsoftflowd`, `LOG_DAEMON`, with the PID) at the levels of the C calls (`LOG_DEBUG`, `LOG_INFO`, `LOG_WARNING`, `LOG_ERR`). The wording, levels, and order of log messages match the C version.

| C Message / Format | C Level | Rust Message / Format | Rust Level |
|---|---|---|---|
| `%s v%s starting data collection` | `LOG_NOTICE` | `rsoftflowd v0.1.0 starting data collection` | `log::info!` |
| `Exporting flows from %s to [%s]:%s` | `LOG_NOTICE` | `Exporting flows from {} to [{}]:{}` | `log::info!` |
| `Shutting down after pcap EOF` | `LOG_NOTICE` | `Shutting down after pcap EOF` | `log::info!` |
| `Shutting down on user request` | `LOG_WARNING` | `Shutting down on user request` | `log::warn!` |
| `Exiting immediately on user request` | `LOG_WARNING` | `Exiting immediately on user request` | `log::warn!` |
| `Exiting immediately on internal error` | `LOG_ERR` | `Exiting immediately on internal error` | `log::error!` |
| `SIGHUP received (config reload not implemented)` | `LOG_INFO` | `SIGHUP received (config reload not implemented)` | `log::info!` |
| `stats: tracked=%u total_packets=%llu` | `LOG_INFO` | `stats: tracked={} total_packets={}` | `log::info!` |
| `Exiting on poll: %s` | `LOG_ERR` | `Exiting on poll: {}` | `log::error!` |
| `Exiting on pcap_dispatch: %s` | `LOG_ERR` | `Exiting on pcap_dispatch: {}` | `log::error!` |
| `Fatal error - exiting immediately` | `LOG_WARNING` | `Fatal error - exiting immediately` | `log::warn!` |
| `Unable to export flows` | `LOG_WARNING` | `Unable to export flows` | `log::warn!` |
| `Starting expiry scan: mode %d` | `LOG_DEBUG` | `Starting expiry scan: mode {}` | `log::debug!` |
| `Queuing flow seq:%" PRIu64 " (%p) for expiry reason %d` | `LOG_DEBUG` | `Queuing flow seq:{} ({:p}) for expiry reason {}` | `log::debug!` |
| `Finished scan %d flow(s) to be evicted` | `LOG_DEBUG` | `Finished scan {} flow(s) to be evicted` | `log::debug!` |
| `EXPIRED: %s (%p)` | `LOG_DEBUG` | `EXPIRED: {} ({:p})` | `log::debug!` |
| `Forcing expiry of %d flows` | `LOG_INFO` | `Forcing expiry of {} flows` | `log::info!` |
| `Out of memory while expiring flows - all flows expired` | `LOG_ERR` | `Out of memory while expiring flows - all flows expired` | `log::error!` |
| `Needed to expire %d flows, but only %d active` | `LOG_ERR` | `Needed to expire {} flows, but only {} active` | `log::error!` |
| `Control socket "%s"` | `LOG_DEBUG` | `Control socket "{}"` | `log::debug!` |
| `Control socket yielded no data` | `LOG_ERR` | `Control socket yielded no data` | `log::error!` |
| `process_packet: flow_get failed` | `LOG_ERR` | `process_packet: flow_get failed` | `log::error!` |
| `process_packet: expiry_get failed` | `LOG_ERR` | `process_packet: expiry_get failed` | `log::error!` |
| `ADD FLOW %s` | `LOG_DEBUG` | `ADD FLOW {}` | `log::debug!` |
| `COLLISION %s` | `LOG_DEBUG` | `COLLISION {}` | `log::debug!` |
| `Sending flow packet len = %d` | `LOG_DEBUG` | `Sending flow packet len = {}` | `log::debug!` |
| `packet len %d: %s` | `LOG_INFO` | `packet len {}: {}` | `log::info!` |
| `cpu clocks: %ld` | `LOG_INFO` | `cpu clocks: {}` | `log::info!` |
| `cpu clocks (export): %ld (%lu calls)` | `LOG_INFO` | `cpu clocks (export): {} ({} calls)` | `log::info!` |

### D7. PSAMP (fixed)

The PSAMP message headers (IPFIX message header sequence number and export time), template `dataLinkFrameSection` field length (fixed at 1390 bytes, matching C `PSAMP_DATALINKFRAME_SIZE`), and `sectionExportedOctets` (reporting actual captured frame length `caplen`, capped at 1390 bytes) were aligned with the C version. `observationTimeMicroseconds` retains Rust's RFC-compliant NTP fraction calculation `((tv_usec * 2^32) / 1,000,000)` (noting C's non-compliant $+1\mu s$ offset quirk).

### D8. Step 6 of the compat test (not measured)

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

### D11. NetFlow v9 option template (source)

The v9 option template of the C version has the scope interface and three
option fields: samplingInterval (34), samplingAlgorithm (35) and interfaceName
(82, 16 bytes) (`ipfix_fields.h`, `field_nf9option`).  The Rust version writes
the first two only (`put_templates()`, the `version == 9` branch).  How much it
changes the size of the first v9 datagram was not isolated; see D12.

### D12. Byte-for-byte comparison, compat step 6 (measured)

Step 6 ran for the first time on 2026-11-02, after 0011 made step 3 pass.
Command: the one in "How to reproduce" with `--a` and `--b` and `--strict`
(C against Rust).  The causes were not analyzed; this is what was seen.

- Datagrams: "exported datagrams: 125 of 140 runs differ".
  - With `-m N` (flows that are expired by the size of the table) C sends
    many datagrams and Rust sends one, for NetFlow v1, v5, v9 and IPFIX
    (for example `-v 5 -a -m 5`: 36 datagrams from C, 1 from Rust).
  - NetFlow v5: byte 19 of the second datagram differs; bytes 16 to 19 of
    the v5 header are the flow sequence number.
  - NetFlow v9 and IPFIX: the first datagram differs in size (`-v 9 -a`: C 1360
    bytes, Rust 1388; `-v 10 -a -T ether`: C 1312, Rust 1376).  D11 is one
    known difference of the v9 option template; the rest is not known.
- Packet statistics (5 tests): in 4 of them Rust shows 0 for the packets that
  are not IP or that are too short and C counts them; in the fifth (`-v psamp`,
  not IP) the number of the packets read differs (C 240, Rust 235).
- Command lines: 75 of 75 differ when the text of the messages is compared
  too (D3 compares the exit status only); `-t general=0`, `-t bogus=1`,
  `-t tcp`, `-t tcp=` and `-t tcp=xyz` exit with 0 in Rust and 1 in C.
- Also different: the CPU clocks of `-g` (2 tests, and 2 more on the loopback
  interface), the daemon (privileges, syslog), and the replies of the control
  commands `exit` and `shutdown`.  In the live tests on the loopback interface
  the log lines of these commands and the behavior on SIGHUP, SIGINT, SIGTERM
  and SIGUSR1 differ too.
- The same: `-M` exports the same datagrams as without it; the expire-all
  at the end of a file (`-a`); the idle expiry (`-t expint=3`); packets that
  are read together; the statistics of `-a` on a live interface.
- Note on datagram packing: Differences in datagram record packing efficiency and splitting between C and Rust (e.g. 23 records vs 22 records) are intentional, RFC-compliant, and governed by transport packet size limits (`IPFIX_SOFTFLOWD_MAX_PACKET_SIZE` = 1428 bytes, derived from standard Ethernet MTU 1500 minus IP and UDP/TCP headers). IPFIX (RFC 7011) does not require rigid record-count parity with C as long as message lengths, set lengths, 4-byte set padding, and MTU/packet size constraints are respected. (Future enhancement: dynamically querying output interface MTU and subtracting IP header size and transport header size - UDP, TCP, SCTP, including up to 60 bytes for TCP options - to compute max packet size).

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
- **R6**: `src/bin/rsoftflowd.rs` main() has been split into functions, with targets
  and capture setup moved to `netsock.rs` and `capture.rs`.
- **R7**: `unsafe` appears in 22 lines (`rsoftflowd.rs` 7, `export.rs` 12,
  `psamp.rs` 1, `lib.rs` 1, `net_util_unsafe.rs` 1; the word may be in a
  comment).
- **R8**: `rust/tests/run_compat_tests.py` (480 lines) and `rust/doc/test.ja.md`
  are the prototype of `tools/softflowd_test.py` (the maintainer's
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
- **R10**: a failure like R9 was only seen after the push.  The existing
  `.githooks/pre-commit` only checked the clang-format of C changes; the
  patch keeps that check as it is and adds the Rust checks.  Tried in a
  scratch clone with clang-format 18 and Rust 1.91.1: a badly formatted C
  file stops the commit; a badly formatted Rust file stops the commit; a
  commit of documents only runs neither cargo; a correct Rust change runs
  the three cargo commands and is committed.
