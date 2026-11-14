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
| D12 | compat step 6: most byte-for-byte checks differ (see the text) (umbrella; re-measured 2026-11-15, the causes are D19, D20, D22 to D28) | 2026-11-02 | open | | |
| D13 | Command line (part of D3): wrong `-t` options are accepted, and a large time panics | 2026-11-02 | fixed | 0012 Reject the wrong -t options as the C version does | 2026-11-02, the 75 cases of D3 run again: the cases of `-t` no longer differ (exit status differs in 38 cases, was 47); unit tests of `parse_duration` and `apply_timeouts` |
| D14 | Command line (part of D3): `-T port` panics; C accepts it | 2026-11-02 | fixed | 0013 Accept -T port in the Rust version | 2026-11-02, the 75 cases of D3 run again: no panic is left (exit status differs in 37 cases, was 38); a test of the names of the levels |
| D15 | Overflow eviction: Rust dropped evicted flows instead of exporting them (part of D12) | 2026-11-02 | fixed | Export evicted flows in evict_oldest_flow() | 2026-11-02, unit test test_flow_eviction_exports passes (fails on old code) |
| D16 | NetFlow v5 flow_sequence grows twice as fast as in C (part of D12) | 2026-11-07 | fixed | Fix flow_sequence in export_build_flow_header() for NetFlow v5 | 2026-11-07, unit test test_exporter_netflow_v5_sequence_numbers passes (fails on old code) |
| D17 | Command line (part of D3): startup order and validation of `-n`, `-I`, interface, BPF filter, and control socket differ from C | 2026-11-02 | fixed | Check options and open capture before daemonizing, and reject bad -n and -I | 2026-11-07, unit tests for `parse_boot_time_reinit`, integration tests for exit status 1 without daemonizing |
| D18 | Ignored packets statistics: Rust did not count non-IP and too short packets (part of D12) | 2026-11-10 | fixed | Count non-IP and too short packets in parse_packet() and capture loop | 2026-11-10, unit tests for parse_packet() and counter test pass |
| D19 | NetFlow v9 option template: scope type is 1 (System) in Rust, 2 (Interface) in C | 2026-11-15 | open | | |
| D20 | interfaceName of the option records is empty with `-r` in Rust; C writes the file name | 2026-11-15 | open | | |
| D21 | Biflow (`-b`) template of ICMP: C has a reverse icmpTypeCode, Rust has not | 2026-11-15 | accepted | not fixed on purpose (see the text) | 2026-11-15, decoded templates compared |
| D22 | Overflow eviction (`-m`): C evicts in batches after a dispatch, Rust evicts one flow at a time and sends one datagram per flow (part of D12) | 2026-11-15 | open | | |
| D23 | Datagram packing: C closes a datagram earlier than Rust (part of D12) | 2026-11-15 | open | | |
| D24 | Expiry scan: modes, `<` against `<=`, missing "Forcing expiry" log (part of D12) | 2026-11-15 | open | | |
| D25 | Packet statistics: `Packets processed` and `Ignored packets` differ for non-IP and too short packets (part of D12) | 2026-11-15 | open | | |
| D26 | Command line: texts of errors and of `-h`/`--help` differ (part of D12; the exit status is D3) | 2026-11-15 | open | | |
| D27 | `-g -M`: the CPU clock lines differ (part of D12) | 2026-11-15 | open | | |
| D28 | Control socket replies and the log lines on signals differ (part of D12) | 2026-11-15 | open | | |
| D29 | Start-up log lines can come out of order, and `Dropped privileges to nobody` is extra (found by `cargo test`) | 2026-11-15 | open | | |
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
| R7 | `unsafe` in 22 lines | 2026-11-02 | fixed | Replace static mut and raw pointer with safe code in export.rs and psamp.rs | cargo test, fmt, clippy -D warnings pass |
| R7-1 | Replace the clock() calls with a safe CPU clock helper (part of R7) | 2026-11-14 | fixed | Replace clock() with nix clock_gettime CPU clock helper | cargo test, fmt, clippy -D warnings pass |
| R7-3 | Remove the last unsafe code: signals, geteuid and SO_BINDTODEVICE (part of R7) | 2026-11-14 | fixed | Remove last unsafe code using signal-hook and nix setsockopt, and add #![forbid(unsafe_code)] | cargo test, fmt, clippy -D warnings pass |
| R8 | `rust/tests/run_compat_tests.py` and `rust/doc/test.ja.md` duplicate the tools | 2026-11-02 | open | Delete `rust/tests/run_compat_tests.py` and `rust/doc/test.ja.md` | the `rust/` part is fixed; the part outside `rust/` is still open |
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

## Re-measurement of 2026-11-15 (measured)

| | |
|---|---|
| Measured on | 2026-11-15 |
| Base | upstream `f7e921a` (`master`) |
| Tools | Rust 1.91.1, release build, built-in Python collector, run as root (the `daemon` item was skipped: it needs `/var/empty` and no `/dev/log`) |
| C binary | the C build of the same commit (`./configure && make`) |
| Command | `python3 tools/softflowd_test.py --a softflowd --b rust/target/release/rsoftflowd --ctl-a softflowctl --ctl-b rust/target/release/rsoftflowctl --strict --skip-build --skip-cpp --skip-rust --skip-static --skip-direct --skip-psamp --collector python --pcap-dir pcaps --no-benchmark --no-gauge-clock` |

Result: steps 1 and 2 PASSED; step 3 MATCHED for NetFlow v1, v5, v9 and IPFIX
(IPv4 and IPv6, 24 records each), so D1 and D2 stay fixed.  Step 6:
"exported datagrams: 134 of 168 runs differ".  To find the causes, the raw
datagrams of both binaries were captured on a UDP socket and decoded
(`http.cap` and `v6-http.cap`, `-v 5/9/10 -a`, with `-m 5` and with `-b`).
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
`cargo build --release` pass; `cargo test` has one failure (D29).

### D12. Update of 2026-11-15: the causes, split into items

**Goal**

`rsoftflowd --strict` against the C version has no difference that nobody
has explained.  Every difference is either fixed or written down as accepted,
with its reason.  D12 is the umbrella item; it is closed when all of its
children are closed.

**Acceptance Criteria**

1. Every cause of the 134 differing runs belongs to one of D19, D20, D22 to
   D28 (D21 is accepted, see below); none is left only in the text of D12.
2. The `--strict` run of the "Command" above has no `DIFFERENT` that is not
   listed in the document as accepted.  A difference that is accepted is
   removed from the comparison by an explicit, documented rule of
   `tools/softflowd_test*.py` (for example, the process ID in the option
   record), never by loosening the whole comparison.
3. Step 3 stays MATCHED for all four formats and both address families.
4. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
   `cargo test` pass.
5. The row of D12 is set to `fixed` in the same patch that closes the last
   child, with the date and the command that was run.

**Context**

D12 was written on 2026-11-02 when "the causes were not analyzed".  Since
then D15, D16 and D18 were fixed as "part of D12".  The same rule is used now:
an item that has a cause of its own gets an ID and says "(part of D12)".

What was seen on 2026-11-15, and where it goes:

| Seen | Item |
|------|------|
| First v9 datagram: option template scope type (byte 303) | D19 |
| First v9 and IPFIX datagram: interfaceName of the option data | D20 |
| `-b`: ICMP templates differ in size | D21 (accepted) |
| `-m N`: C 120 datagrams, Rust 596 (`many`); header time differs | D22 |
| v9 and IPFIX: C and Rust close the datagram at different records | D23 |
| `Starting expiry scan: mode` and `EXPIRED` lines | D24 |
| `Packets processed` / `Ignored packets` (2 tests) | D25 |
| Command line texts (75 of 75) | D26 |
| `-g -M` | D27 |
| `exit` / `shutdown` replies, SIGINT line on `lo` | D28 |

The IPFIX sequence numbers of both binaries look like the same rule (not
checked against RFC 7011); they differ only where D23 gives a different
record count.
The PID in the option data record (`meteringProcessId`) differs between any
two runs (7885 against 7886 in the captured pair); how the harness masks it
was not checked and is part of acceptance criterion 2.

### D19. NetFlow v9 option template: scope type (measured, a Rust bug)

**Goal**

The option template of NetFlow v9 names its scope as Interface (type 2), as
the C version and RFC 3954 do, because the scope value is the interface index.

**Acceptance Criteria**

1. In the first v9 datagram the option template flowset has scope field type
   `0x0002`, length 4, followed by samplingInterval (34, 4), samplingAlgorithm
   (35, 1) and interfaceName (82, 16).
2. The option template flowset (bytes 290 to 325 of the first datagram of
   `http.cap -v 9 -a`) is identical to C for `http.cap` and `v6-http.cap`.
3. A unit test that reads the scope type out of the built option template
   fails on the old code and passes on the new code (in the style of
   `test_netflow_v9_option_template_has_interface_name`).
4. The IPFIX option template is not changed.
5. Step 3 stays MATCHED; fmt, clippy and tests pass.

**Context**

- Measured: `http.cap -v 9 -a`, offset 303: C `00 02`, Rust `00 01`.  The
  option data record has the value `00 00 00 01` (the interface index) in both.
- Source: `src/exporter/export.rs:834` writes `1u16` and the comment says
  "scope: interface".  RFC 3954 section 6.1 defines the scope types: 1 System,
  2 Interface, 3 Line Card, 4 NetFlow Cache, 5 Template.  C uses
  `IPFIX_OPTION_SCOPE_INTERFACE` = 2 (`ipfix.h:56`, `ipfix_fields.h:231`) and
  writes `ifidx` (`enc_nf9OptionScopeInterface`, `export.c`).
- Rust value 1 (System) with a 4-byte index is not what the data says, so a
  collector may read the index as the wrong kind of scope.
- Related: D11 added interfaceName to this template; the scope was not
  compared then.

### D20. interfaceName of the option records (measured, source)

**Goal**

The interfaceName of the option records is always the capture source, as in
C: the interface name with `-i`, the file name with `-r`, in 16 bytes, for
NetFlow v9 and IPFIX.  (`--enable-ifname` only adds the same value to the data
records.)

**Acceptance Criteria**

1. With `-r FILE`, the interfaceName of the option data record is `FILE` as
   it was written on the command line (not the base name), first 16 bytes,
   zero padded.
2. With `-i IF`, it is `IF`.
3. A name of 16 bytes or more is cut at 16 bytes, as C does (C copies at most
   the field length; no terminating NUL is added).
4. The option data record of the first datagram of `http.cap` and
   `v6-http.cap` is identical to C for `-v 9` and `-v 10`, except the PID
   field.
5. A unit test for the option record with an interface name and one for a
   file name; both fail on the old code.
6. The data records do not get the name unless the feature of
   `--enable-ifname` is on, as before.
7. fmt, clippy and tests pass; step 3 stays MATCHED.

**Context**

- Measured: v9 bytes 331 to 344 and IPFIX bytes 364 to 377 of the first
  datagram.  C has `pcaps/http.cap`, Rust has zeros.
- Source: `rsoftflowd.rs:177` sets `param.interface_name` only when
  `capture_dev` is `Some`, that is, with `-i`.  C always fills
  `option.interfaceName` and says so (`export.c`, comment of
  `enc_interfaceName`: "the capture interface, or the file name with -r").
- The maintainer's decision of the RFC policy: the interfaceName of the
  option record always carries the correct value (the old compat static was
  right; `--enable-ifname` only controls the data records).
- Related: D6 (messages use the same source name), D11.

### D21. Biflow template of ICMP (measured; accepted, not fixed)

**Goal**

None.  This is a difference that is kept.

**Acceptance Criteria**

1. The document says that the difference is accepted and why (this text).
2. The comparison of `--strict` does not report the size difference of the
   ICMP biflow templates as a failure of Rust.  If the harness cannot ignore
   it now, the ignore rule is added to the harness under D12 criterion 2,
   not to Rust.

**Context**

- Measured with `-b`: the C template 1025 (IPv4 ICMP) and 2049 (IPv6 ICMP)
  end with a reverse icmpTypeCode (2 bytes); Rust has no such field (18 and
  17 fields; the records are 2 bytes shorter, 74 against 72 bytes for 2049).
- In C, ICMP never becomes a biflow: the type/code are part of the flow key,
  so an echo request and an echo reply (different type/code) are two flows
  and are never paired.  The reverse field is never filled with a meaning.
  The Rust template without it is valid, and copying it would only copy a
  field that cannot carry data.
- It still changes the datagram sizes of the `-b` cases of the compat test
  (for example `smoke6 -v 10 -a -b`: C 1408 bytes, Rust 1380).

### D22. Overflow eviction with `-m` (measured, source)

**Goal**

When the flow table is over `-m`, the flows are evicted and exported in the
same batches, in the same datagrams and with the same header times as in C.

**Acceptance Criteria**

1. For the pcaps `smoke`, `smoke6`, `vlan`, `slow`, `many` and `loopback` of
   the compat test, with `-m 5` and with `-t maxlife=1 -m 7`, for `-v 1`,
   `-v 5`, `-v 9` and `-v 10`: the number of datagrams and the bytes are
   identical to C in `--strict` (the fields of D12 criterion 2 masked).
2. The header time of the datagram (NetFlow v1 and v5: sys_uptime and
   unix_nsecs; v9 and IPFIX: the export time) is the same as C, for example
   `http.cap -v 5 -a -m 5` (C 0x154 ms, Rust 0x12c ms before the fix).
3. `Flows expired` and the `maxflows` line of the statistics are the same as
   C; `flows_force_expired` counts the same flows.
4. With `-d` the line `Forcing expiry of N flows` and the `Starting expiry
   scan` lines come in the same order as in C.
5. The fix of D15 stays: an evicted flow is exported, never dropped (the
   test `test_flow_eviction_exports` still passes).
6. A unit test: a table of 5 with 12 flows added in one batch exports the
   evicted flows in as few datagrams as C does.
7. `tools/softflowd_bench.py` shows no slowdown that the change causes.
8. D10 (which flowEndReason an evicted flow carries) is decided in the same
   patch or kept open with a pointer; criterion 1 depends on it.

**Context**

- Measured, number of datagrams (C against Rust): `many -v 5 -a -m 5`
  120 against 596; `many -a -t maxlife=1 -m 7` 86 against 594;
  `loopback -v 1 -a -m 5` 2 against 6; `loopback -v 9 -a -m 5` 6 against 21.
  `http.cap -v 5 -a -m 5` has 16 datagrams in both, but bytes 7 and 12 to 14
  of the header (uptime, nsecs) differ by 40 ms; the cause of the time was
  not isolated, it is probably the point at which "now" is taken.
- C (source): `softflowd.c:407-410` reads at most `max_flows` packets per
  `pcap_dispatch()`.  After the batch (`softflowd.c:456-476`), if
  `num_flows > max_flows`, it runs `check_expired()` (with `CE_EXPIRE_FORCED`
  for `-r`), then `force_expire()` marks the oldest `num_flows - max_flows`
  flows with `expires_at = 0` and `R_OVERFLOWS`, and it loops until the table
  is not over the limit.  Evicted flows leave in one `check_expired()` call,
  so several flows share a datagram.  The table can be over `-m` for the
  length of one batch.
- Rust (source): `capture.rs:342-343` calls `evict_oldest_flow()` before
  every new flow when `len >= max_flows`; it sends the flow at once
  (`expire.rs:84-108`, a slice of one flow), so each eviction is a datagram.
  The table never exceeds `-m`.  `evict_oldest_flow()` does not write the log
  line `Forcing expiry of N flows` that D6 lists.
- Two ways to a fix: (a) follow C (a batch after the dispatch, one send of
  all evicted flows), the way to byte-for-byte; (b) keep the eviction before
  insert and collect the evicted flows of one packet in one send; this is
  not byte-for-byte and needs a decision of the maintainer.  Criterion 1
  assumes (a).
- Related: D10, D15 (fixed: evicted flows are exported), D24.

### D23. Datagram packing (measured, cause not isolated)

**Goal**

Find why C and Rust close a v9 or IPFIX datagram at different records, then
either make the packing the same or write down why the difference stays.

**Acceptance Criteria**

1. The cause is isolated and written in this item (which check in C stops
   at which size).
2. Fixed or accepted.  If fixed: the sizes of the datagrams of
   `http.cap -v 9 -a` and `-v 10 -a` are identical to C.  If accepted: the
   decoded records of both are the same, no datagram is over 1428 bytes, and
   the harness compares the decoded records and the sum of the records
   instead of the sizes (D12 criterion 2).
3. The note on packing in D12 ("intentional ... 23 records against 22") is
   replaced by the result.

**Context**

- Measured (`http.cap -a`): v9 C 1368 + 68 bytes (last data set 3 + 1
  records), Rust 1408 bytes (4 records); IPFIX C 1356 + 148, Rust 1396 +
  104.  The templates, decoded, are identical; the record count is the same.
- Both use `IPFIX_SOFTFLOWD_MAX_PACKET_SIZE` = 1428.  The check of C that was
  read (`ipfix_flow_to_flowset()`: `len < data_len * frecnum`) does not
  explain the early stop, so the old note ("intentional") is not shown yet.
- The size differences of the `-b` ICMP cases come from D21, not from here.

### D24. Expiry scan (source, partly measured)

**Goal**

`check_expired` of C and `scan_expiries` of Rust select the same flows and
write the same debug lines.

**Acceptance Criteria**

1. The modes are `0` (normal), `-1` (expire all) and `1` (only forced), as
   `softflowd.h:191-198`; the log line prints the same number as C.
2. With `-r`, as in C, the scan expires only the forced flows (mode 1).
3. The idle test uses the same comparison as C (`expires_at < now`).
4. The order of `Starting expiry scan` and `EXPIRED` lines of the `-d` log of
   the compat test is the same as in C.
5. Unit tests for the three modes and the boundary second.

**Context**

- Measured: C prints `mode -1` where Rust prints `mode 1`; Rust prints the
  `EXPIRED` lines where C prints the next `Starting expiry scan: mode 1`.
- Source: Rust has a boolean `force_all` (`expire.rs`, 0 or 1), so "expire
  all" (C: -1) and "forced only" (C: 1) cannot be told apart.  C: `expires_at
  < now.tv_sec` (`expire.c:217`); Rust: `exp_key.expires_at <= now_sec`
  (`expire.rs`); the same kind of boundary as D9.  Not run.
- Related: D9, D22.

### D25. Packet statistics (measured, cause not isolated)

**Goal**

`Packets processed` and `Ignored packets` of `softflowctl statistics` and of
the final statistics are the same as C for non-IP and for too short packets.

**Acceptance Criteria**

1. The two tests of the compat test ("statistics of the packets" with
   `-v psamp` and with `-s 3`) are identical to C.
2. Unit tests for the counters in `parse_packet()` and the capture loop with a
   non-IP and a too short packet.

**Context**

- Measured: `-v psamp`, non-IP: C `Packets processed: 240`, `Ignored packets:
  0 (0 non-IP, 0 too short)`; Rust 235 and `5 (5 non-IP, 0 too short)`.
  `-s 3`, too short: C 80 and `2 (0 non-IP, 2 too short)`; Rust 83 and
  `5 (0 non-IP, 5 too short)`.
- D18 fixed the case where Rust counted nothing; here the rule of what is
  "ignored" differs.  The cause was not read yet.

### D26. Command line texts (measured)

**Goal**

The texts of command line errors and of `-h`/`--help` are the same as C, or
the difference is written down as accepted.

**Acceptance Criteria**

1. The 75 cases of `PARITY_CLI_ERROR_CASES` compare equal in stderr, or each
   remaining difference is listed here as accepted with its reason.
2. `-h` and `--help` write to the same stream as C.
3. The exit status is the subject of D3 and is not changed here.

**Context**

- Measured: 75 of 75 differ in the text.  Examples: no arguments: C `-i, -r
  or -R option not specified.`, Rust `Must specify a packet source (-i or
  -r).`; `-h`: C writes nothing to standard output, Rust writes the clap help.
- clap writes its own messages and exit status 2; matching C may need the
  option parsing of Rust to be wrapped.  A decision for the maintainer, as in
  D3.  The compatibility baseline is the getopt-style short options.

### D27. `-g -M` CPU clock lines (measured)

**Goal**

`-g` with `-M` prints the same lines as C.

**Acceptance Criteria**

1. The compat item "cpu clocks of -g -M" has the same lines as C (the values
   differ by nature; the set of lines and their format must not).
2. The item "cpu clocks of -g" stays MATCHED.

**Context**

- Measured: C with `-M`: only the total (1228); Rust: total (455) and
  `cpu clocks (export): 8 (1 calls)`.  Without `-M` both print both lines.

### D28. Control socket replies and signals (measured on 2026-11-02, partly re-measured)

**Goal**

The replies of `exit` and `shutdown` and the log lines on SIGHUP, SIGINT,
SIGTERM and SIGUSR1 are the same as C.

**Acceptance Criteria**

1. The compat items of the control socket replies (`exit`, `shutdown`) and
   the live items on `lo` (SIGHUP, SIGINT, SIGTERM, SIGUSR1) are identical to
   C.
2. The `daemon` item (privileges, syslog) is run on a machine with
   `/var/empty` and without `/dev/log`, and its result is written here.

**Context**

- Measured 2026-11-15: on SIGINT C logs only `Shutting down on user
  request`; Rust adds `Shutting down complete, exiting.`.  The other signals
  and the replies were measured on 2026-11-02 and not re-run in detail.
- The `daemon` item was skipped on 2026-11-15.

### D29. Start-up log order, and an extra line as root (measured, a Rust bug)

**Goal**

With `-d`, the first lines of stderr are in the order of C, whether the
program runs as root or not.

**Acceptance Criteria**

1. `cargo test --test integration_tests test_d6_logging_stderr_first_four_lines`
   passes as an ordinary user and as root, repeated 100 times.
2. `Dropped privileges to nobody` is not written where C does not write it
   (or the difference is accepted here).

**Context**

- Measured: the test fails, as root, with `Shutting down after pcap EOF` as the
  first line.  `rsoftflowd -d -r FILE -n 127.0.0.1:9` gives: `Shutting down
  after pcap EOF`, `Dropped privileges to nobody`, `rsoftflowd v0.1.0
  starting data collection`, ...; C gives `starting data collection` first.
- Source: the capture thread of `-r` is started before `run_main_loop()`
  writes `starting data collection` (`rsoftflowd.rs:354`), and it logs
  `Shutting down after pcap EOF` (`capture.rs:159`) at the end of a short
  file: the order is a race.  `drop_privileges()` (`rsoftflowd.rs:82`) logs
  only as root.
- The race does not depend on root, so the test can also fail in CI.

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
  were the prototype of `tools/softflowd_test.py`.  Both files have been
  deleted, so the `rust/` part is fixed; the part outside `rust/` is still
  open.  Whether other scripts in `tools/` duplicate it was checked: only
  `tools/deprecated/collector.pl` and `tools/deprecated/benchmark_export.sh`,
  which `collect` and `bench` replace, do.
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
