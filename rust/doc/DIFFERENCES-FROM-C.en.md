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
| D3 | Command line errors: 47 of 75 cases differ | 2026-11-02 | fixed | Exit with status 1 for a wrong command line, and accept the getopt_long grammar | 2026-11-15, `test_d3_wrong_command_line_exits_1` and `test_d3_help_exits_0` (fail on the old code); the 94 cases of the compat item have no `exit status` difference except the 11 of D34 (fixed since) |
| D4 | No ntopng | 2026-11-02 | fixed | Add the export to ntopng (-v ntopng) as an optional Cargo feature | 2026-11-02, integration test passes (feature on); note that -v ntopng-json is not ported |
| D5 | Program name and version not unified | 2026-11-02 | fixed | 0016 Remove alias binaries | 2026-11-02, cargo build generates only rsoftflowd and rsoftflowctl |
| D6 | Logging | 2026-11-02 | fixed | Implement syslog and stderr logging matching C versions and messages | 2026-11-02, integration test captures stderr and compares first four lines with C wording |
| D7 | PSAMP message headers (sequence number and export time) differ from C | 2026-11-02 | fixed | Fix PSAMP sequence number and export time in psamp.rs | 2026-11-07, integration test checks sequence numbers of the first 20 messages for a 120-packet pcap |
| D8 | compat step 6 not reached (not measured) | 2026-11-02 | fixed | 0011 Use the same templates for NetFlow v9 as for IPFIX | 2026-11-02, step 6 ran for the first time (its result is D12) |
| D9 | Maximum lifetime: C compares with `>`, Rust with `>=` | 2026-11-02 | fixed | 0014 Compare the maximum lifetime with > as the C version does | 2026-11-02, unit test maximum_lifetime_expiry_boundary passes (fails on old code) |
| D10 | Overflow eviction: C keeps the previous flowEndReason, Rust writes lack of resources | 2026-11-02 | fixed | Expire the flows over -m in a batch after the packets, as C does | 2026-11-15, an overflowing flow keeps its flowEndReason as in C (the datagrams of the `-m` cases are identical to C) |
| D11 | NetFlow v9 option template: C has interfaceName (IE 82), Rust has not | 2026-11-02 | fixed | 0015 Add interfaceName to the NetFlow v9 option template | 2026-11-02, unit test test_netflow_v9_option_template_has_interface_name passes (fails on old code) |
| D12 | compat step 6: most byte-for-byte checks differ (see the text) (umbrella; re-measured 2026-11-15, the causes are D19, D20, D22 to D28) | 2026-11-02 | open | | |
| D13 | Command line (part of D3): wrong `-t` options are accepted, and a large time panics | 2026-11-02 | fixed | 0012 Reject the wrong -t options as the C version does | 2026-11-02, the 75 cases of D3 run again: the cases of `-t` no longer differ (exit status differs in 38 cases, was 47); unit tests of `parse_duration` and `apply_timeouts` |
| D14 | Command line (part of D3): `-T port` panics; C accepts it | 2026-11-02 | fixed | 0013 Accept -T port in the Rust version | 2026-11-02, the 75 cases of D3 run again: no panic is left (exit status differs in 37 cases, was 38); a test of the names of the levels |
| D15 | Overflow eviction: Rust dropped evicted flows instead of exporting them (part of D12) | 2026-11-02 | fixed | Export evicted flows in evict_oldest_flow() | 2026-11-02, unit test test_flow_eviction_exports passes (fails on old code) |
| D16 | NetFlow v5 flow_sequence grows twice as fast as in C (part of D12) | 2026-11-07 | fixed | Fix flow_sequence in export_build_flow_header() for NetFlow v5 | 2026-11-07, unit test test_exporter_netflow_v5_sequence_numbers passes (fails on old code) |
| D17 | Command line (part of D3): startup order and validation of `-n`, `-I`, interface, BPF filter, and control socket differ from C | 2026-11-02 | fixed | Check options and open capture before daemonizing, and reject bad -n and -I | 2026-11-07, unit tests for `parse_boot_time_reinit`, integration tests for exit status 1 without daemonizing |
| D18 | Ignored packets statistics: Rust did not count non-IP and too short packets (part of D12) | 2026-11-10 | fixed | Count non-IP and too short packets in parse_packet() and capture loop | 2026-11-10, unit tests for parse_packet() and counter test pass |
| D19 | NetFlow v9 option template: scope type is 1 (System) in Rust, 2 (Interface) in C | 2026-11-15 | fixed | Use the Interface scope type in the NetFlow v9 option template | 2026-11-15, option template flowset identical to C for http.cap and v6-http.cap (`-v 9 -a`); `test_netflow_v9_option_template_has_interface_name` now expects scope type 2 and fails on the old code |
| D20 | interfaceName of the option records is empty with `-r` in Rust; C writes the file name | 2026-11-15 | fixed | Write the capture file name to the interfaceName of the option records with -r | 2026-11-15, option data record identical to C for http.cap and v6-http.cap (`-v 9 -a`, `-v 10 -a`) except the PID; unit tests of `interface_name_field()`, integration test `test_d20_option_record_interface_name_is_file_name` (fails on the old code) |
| D21 | Biflow (`-b`) template of ICMP: C has a reverse icmpTypeCode, Rust has not | 2026-11-15 | fixed | ICMP is not a biflow: C, C++ and Rust export an ICMP flow with the unidirectional ICMP template and one record for each direction (no reverse fields); the C and C++ versions differ from 1.1.1 in this | 2026-11-19, C, C++ and Rust: the template sets and the decoded records of `-v 10 -b` (also `-T full`, `-A micro`) of `http.cap` and `v6-http.cap` are the same, and for ICMP they are the same with and without `-b`; the entry of the gate is deleted; the difference from 1.1.1 is allowed in `tools/softflowd_test.py` |
| D22 | Overflow eviction (`-m`): C evicts in batches after a dispatch, Rust evicts one flow at a time and sends one datagram per flow (part of D12) | 2026-11-15 | fixed | Expire the flows over -m in a batch after the packets, as C does | 2026-11-15, the datagrams and the `-D` log of all `-m` and `-t maxlife=1 -m 7` cases of `smoke`, `smoke6`, `vlan`, `slow` and `many` are identical to C (`-v 1`, `5`, `9`, `10`), apart from D23; the live item "burst over -m 10" MATCHED; `test_flow_eviction_exports` and `tests/expire_modes.rs`. Batch: `-m` packets per round (with `-r` the round waits for them); `next_expire_is_now()` as `next_expire() == 0` |
| D23 | Datagram packing: C closes a datagram earlier than Rust (part of D12) | 2026-11-15 | fixed | C: Pack the datagram by the records that are written, not for two per flow | 2026-11-15, with this change of the C version the datagrams of v9 and IPFIX of `http.cap` and `v6-http.cap` are byte for byte the same as Rust (except the PID); compat: 168 runs differ 134 -> 24 (the rest is D21, D32, D33); the same rule is in the C++ version (`records_in_flow`) and in the legacy export `compat/ipfix.c` (the byte for byte comparison of the C++ and the static builds with the C build; CI) |
| D24 | Expiry scan: modes, `<` against `<=`, missing "Forcing expiry" log (part of D12) | 2026-11-15 | fixed | Match the modes, the boundary and the log lines of the expiry scan to C | 2026-11-15, `ExpireMode` (0, -1, 1), `-r` scans only forced flows, `expires_at < now`; the `-d` log of `smoke` and `smoke -m 100` is identical to C; `tests/expire_modes.rs`. Also matched to C in the same scan: the reason of the `Queuing flow` line is the number and comes before the flush mark, the maximum lifetime is counted with `>=`, `sent N netflow packets` is logged before the `EXPIRED` lines, and `flows_dropped` grows when the send fails. The `-d` logs of the `-m` cases still differ: D22 |
| D25 | Packet statistics: `Packets processed` and `Ignored packets` differ for non-IP and too short packets (part of D12) | 2026-11-15 | fixed | Align packet statistics and capture loop counters with C | 2026-11-15, unit tests for non-ip and too short packet counters, integration tests pass |
| D26 | Command line: texts of errors and of `-h`/`--help` differ (part of D12; the exit status is D3) | 2026-11-15 | fixed | clap finds the error, the text, the usage and the exit status are those of C: `usage.txt` (made by `tools/gen_usage_rs.py` from `softflowd -h`), `die_usage()`, `cli_errors.rs`; an option takes the next word also when it begins with `-`; `-r` cancels an earlier `-c`; `-e` resolves a name; the messages of libpcap and of the control socket are C's | 2026-11-24, 83 of the 94 cases of `PARITY_CLI_ERROR_CASES` are the same (before: 17); the 11 that differ were the sloppy numbers of D34 (accepted) and D44 (D44 and D34 fixed since: 123 of 123 are the same); the 66 gate entries of the cases are deleted; `tests/cli_errors.rs` fails with the old code |
| D27 | `-g -M`: the CPU clock lines differ (part of D12) | 2026-11-15 | fixed | Print n/a for the export clock with -M (gauge clock) | 2026-11-16, compat items "cpu clocks of -g -M" MATCHED; the gate entry is deleted |
| D28 | Control socket replies and the log lines on signals differ (part of D12) | 2026-11-15 | fixed | Make the control socket replies, the signals and the final statistics like C | 2026-11-16, "control replies (21 commands, ending with shutdown / exit)", the logs of the shutdown and exit commands, SIGINT, SIGTERM, SIGHUP and SIGUSR1 MATCHED. Follow-up of the first fix: `timeouts` right-aligned to 22 columns, the table size of `statistics` (buckets x 8 bytes) and the libpcap lines (the read times out every second), `dump-flows` in the order of the expiry events (it was the random order of a hash table), the final statistics only with `-r` as in C, a daemon only drops its privileges (with `-d` the control socket could not be removed as root), `ctl connect(...) error:` without " (os error N)"; tests `tests/control_text.rs` |
| D29 | Start-up log lines can come out of order, and `Dropped privileges to nobody` is extra (found by `cargo test`) | 2026-11-15 | fixed | Log start-up messages before starting capture and drop extra privilege log | 2026-11-15, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` (including 20 repetitions of `test_d6_logging_stderr_first_four_lines`) pass as an ordinary user; follow-up: the capture source is opened again before the daemonization and the drop of the privileges (live capture as root, exit status 1 for a missing interface); the capture thread waits for the start-up log lines; `test_d6_logging_stderr_first_four_lines` passed 100 of 100 runs |
| D32 | The option data record of IPFIX ignores `-e` (the exporter address is written as zeros) | 2026-11-15 | fixed | rsoftflowd: fix to include the exporter address in the IPFIX option data record | 2026-11-16, compat items `-e 192.0.2.1` MATCHED; the gate entry is deleted |
| D33 | `-b` with `-H` (and `-T ether`): the MAC address of the reverse direction differs in v9, the sizes in IPFIX | 2026-11-15 | fixed | Use the RFC 7011 values of flowDirection (0 ingress, 1 egress) | 2026-11-16, v9 `-b -T ether -H` MATCHED for all pcaps; `tests/flow_direction.rs`. Cause: Rust wrote 2 for ingress. What stays with `-v 10 -b` is the size of the ICMP biflow templates (D21, accepted) |
| D34 | Command line grammar: C (getopt_long) accepts an abbreviated long option, options after the filter, `-n` twice and sloppy numbers; the Rust version did not (part of D26) | 2026-11-15 | fixed | Exit with status 1 for a wrong command line, and accept the getopt_long grammar | 2026-11-15, `test_d34_getopt_long_grammar` (fails on the old code).  The sloppy numbers were accepted until 2026-11-26; then the C version was made to read a number as a whole decimal number, as rsoftflowd did (the patch "Read the numbers of the options as whole decimal numbers" of C), and rsoftflowd got the texts of C for `-s`, `-B`, `-C`, `-R` and `-x`, the bound of an int for `-B` and `-C`, and the empty value (`-m ''` is a value, and was taken for a missing one).  `tests/cli_numbers.rs` (fails with the old code); 123 of 123 cases of `PARITY_CLI_ERROR_CASES` are the same; the 11 entries of the gate are deleted.  Left: the C++ version still reads the numbers with `atoi`; `-n '' ... -n host:port` (C refuses the first one at once, Rust uses the last one) |
| D35 | A run that is accepted: C logs on standard error in the foreground without `-d`; the Rust version is silent, and the statistics differ (not analyzed) | 2026-11-15 | fixed | Log to standard error for -r, and print the final statistics without the header | 2026-11-16, the 17 accepted runs of the compat command line item are identical to C on standard output and standard error; `test_d35_file_run_logs_to_stderr_and_prints_statistics_without_header` |
| D36 | Idle expiry on a live capture: Rust exports 0.1 to 0.8 s earlier than C (not analyzed; the compat item is sometimes MATCHED) | 2026-11-16 | fixed | Wait like poll() of C before the idle flows are looked at (next_expire) | 2026-11-16, the compat item "live on lo, idle expiry (-t expint=3)" MATCHED in 8 runs out of 8 with the same time as C (it was 0.1 to 0.8 s early in 4 of 6); `test_d36_next_expire_is_like_c` |
| D37 | Found by the fuzz script (G1): a packet that is not longer than the datalink header was counted as too short, a short IPv6 packet was counted twice without `-6`, and the ToS of a flow was that of its last packet (C: of its first) (part of D25) | 2026-11-16 | fixed | Match the classification of short packets and the ToS of a flow to C | 2026-11-16, 320 packet-byte mutations and the cut of every length of the first packets of `http.cap` and `v6-http.cap`: no difference in the records and in the packet counters; `test_d37_*` |
| D38 | Names of the protocols in the per-protocol statistics: C asks the system (`getprotobynumber`, `/etc/protocols`: `xns-idp (22)`), Rust has a short table (`Unknown (22)`) | 2026-11-16 | fixed | Read `/etc/protocols` once and use the first entry of a number, as `getprotobynumber()` does; where the file has no entry the short table is the fallback (the crate forbids `unsafe`, so libc is not called) | 2026-11-19, the 6 runs of the 3 mutated pcaps of `fz3.py` that printed `xns-idp (22)` and `esp (50)`: the statistics are equal to C; `test_d38_protocol_name_comes_from_etc_protocols` fails with the old code |
| D39 | The mean duration of the statistics differs in the second decimal for some captures (C 0.04, Rust 0.05); the order of the expiry is the same. Cause: C subtracted two doubles (sec + usec / 1e6), which lose about 1e-7 s at epoch magnitude; Rust (and C++) subtract the seconds and the microseconds separately, which is exact | 2026-11-16 | fixed | Fix the C version (`update_statistics()` in stats.c), not the Rust version: the exact calculation is the better one | 2026-11-19, 15 of 240 runs of `fz3.py` (60 mutated `http.cap` and `v6-http.cap`, two option sets) differed in the statistics before the patch; after it 5 differ, all in the protocol names (D38), none in the Duration lines; the C++ version was exact already (chrono) |
| D40 | A read error of a pcap file (`-r`; for example a record header with a caplen over the snaplen): C leaves the main loop at once, does not export the flows of the table, writes the statistics and exits with the status 1; Rust flushed the flows and exited with 0 | 2026-11-19 | fixed | The capture thread sends a `ReadError` event; the main loop logs "Exiting on pcap_dispatch" and "Exiting immediately on internal error", skips the expiry and the flush, prints the statistics and exits with 1. A read error of a live device is not changed | 2026-11-19, found by the damaged files of the fuzz script: 30 of 60 differed in the exit status; after the patch the exit status and the statistics are equal to C in all 30; `test_d40_read_error_exits_with_status_1` fails with the old code |
| D41 | The ports of SCTP (132) and DCCP (33) packets: C reads them where the ports of UDP are, Rust left them 0 (the flows of one protocol and two ports had one key) | 2026-11-19 | fixed | Read the ports of UDP, DCCP and SCTP the same way; the whole header that `full_l4hdr_check` requires is 8 octets for UDP, 12 for DCCP (`struct dccp_hdr`), and for SCTP only the ports, as in C | 2026-11-19, found by `http_flip_141` of the full fuzz run (one flow of the protocol 33): the flow records are equal to C with `-v 5`, `-v 9` and `-v 10`; `test_dccp_and_sctp_ports_are_read_like_udp` fails with the old code |
| D42 | A pcap file (or device) of a data link type that softflowd does not read: C writes "Unsupported datalink type N" and exits with 1 before it starts; Rust started, ignored every packet as not IP and exited with 0 | 2026-11-19 | fixed | Check the data link type as C does (the table of `datalink_check()`: Ethernet, PPP, Linux SLL, raw IP, null, loop, pflog) before the filter is applied | 2026-11-19, found by `http_damaged_75` of the full fuzz run (the link type of the file header was 3): the message and the exit status are equal to C; `test_d42_unsupported_datalink_exits_with_status_1` fails with the old code |
| D43 | The buffer size of a live capture without `-B`: C leaves the default of libpcap (2 MiB), Rust set 1 MiB; at a high packet rate Rust lost 6 to 8 % of the packets that C did not lose | 2026-11-19 | fixed | Set the buffer size only when `-B` is given | 2026-11-19, 1 000 000 UDP packets on `lo` from 1 000 source ports on one CPU (a packet generator and the capture compete): C processed 100 %, Rust 92 to 94 % before and 99.6 to 99.8 % after the change; the same effect is seen with the old Rust and `-B 1048576` / `-B 2097152` (93 to 95 % / 99.3 to 99.6 %) |
| D44 | The PSAMP receive mode (`-R port`): in C `-R` is a packet source that receives PSAMP datagrams; the Rust version accepts `-R` and ignores it, and asks for `-i` or `-r` | 2026-11-24 | fixed | rsoftflowd: Receive the PSAMP datagrams of -R like C does | 2026-11-24, found with the cases of D26 (`-R 0 -c /nonexistent/dir/ctl`).  `recvsock()` binds the port while the options are checked (a failure: `bind to UDP port N failed: ...`, status 1); a thread reads the datagrams after the daemonization and passes each packet on as a captured Ethernet packet (`recv_psamp()` of C: only the data records of softflowd, the time as `conv_ntp_to_unix()`, the frame section cut at the end of the datagram, `recv_psamp error` for a datagram that is too short or not IPFIX).  `-R` is the source only without `-i` and `-r`, as in C.  Tests: `tests/psamp_receive.rs`; `tools/psamp_regress.py` (the receiver checks) and the receive cases of the compat step 5 give the same flows as C.  Left: a datagram of `rsoftflowd -v psamp` is read 1 us earlier, because its NTP fraction is not the +1 us of C (D7); after `softflowctl stop` the datagrams are read and dropped, in C they stay in the socket |
| D45 | The exit status after `softflowctl shutdown` and `exit`: C leaves the main loop with the return value of the control socket (1), so it ends with 1 (a signal gives 0); Rust ended with 0 | 2026-11-25 | fixed | rsoftflowd: End with status 1 after the shutdown and exit commands, as C does | 2026-11-25, found with the receiver checks of PSAMP (C 1, Rust 0; also for `-i lo`); after the change C and Rust end with 1 for `shutdown` and `exit` and with 0 for SIGTERM and SIGINT, with `-i lo` and `-R 0`.  `tests/control_exit_status.rs`.  This is a quirk of C (an orderly stop reports a failure) that is kept for parity.  Left, from the code and not measured: with `-r` and `-c`, C writes the final statistics after `exit` too, Rust does not |
| D46 | The boot time (SysUptime of the header, and the start and end times of the flows): C takes the time of the start, and `-a` the time of the first packet; `-I` is looked at when the flows are expired; a time before the boot time is a 32 bit number that wraps.  Rust always took the time of the first packet (also without `-a`), looked at `-I` for each packet with `>=` and the time of the packet, gave 0 for a time before the boot time, and wrote a log line that C does not write | 2026-11-25 | fixed | rsoftflowd: Take the time of the start as the boot time, as C does | 2026-11-25, found with the PSAMP receive mode (packets of 2023).  C and Rust compared with a pcap of 1970: without `-a`, with `-a`, `-a -I 3 -m 2` and `-a -I 1 -m 3` give the same records (without `-a` the times are the same except the few ms between the two starts; the wrapped numbers are the same with `-I`).  `tests/boot_time.rs` (3 of the 4 tests fail on the old code).  The effect: the SysUptime of a live capture is the time since the start of the program, as in C (it was the time since the first packet), and the times of a pcap without `-a` are no longer 0 for the first flow |
| D47 | A daemon (no `-d`, `-D`, `-r`) did not work: the thread of the control socket and the thread that reads the packet source were started before the fork of the daemonization, and a thread does not survive a fork.  `softflowctl` got no answer, and a daemon with `-i` exported nothing (C has no threads) | 2026-11-25 | fixed | rsoftflowd: Start the threads of a daemon after its fork | 2026-11-25, found with the two checks of the gate that were `unexpected` since before ("daemon (privileges, syslog)" and "start order, as root -i lo captures (daemon)"), which were thought to be a problem of the privilege drop.  It is not: the control socket does not answer for a daemon of an ordinary user either (`setpriv --reuid=65534`), and the daemon had 1 thread less than it should.  The source and the control socket are still made before the fork, so that a failure is written to the standard error and exits, as C does; `setup_packet_capture()` returns the function that starts the thread (`CaptureStart`), and `bind_control_socket()` and `spawn_control_server()` are the two halves of `start_control_server()`.  `tests/daemon_mode.rs`: three tests that fail with the old code (the control socket, a daemon that reads the PSAMP port, and, as root, a daemon that reads `lo`).  Left: the privilege drop of C (chroot, `setgroups`) is not done, see D48 |
| D48 | The privilege drop of a daemon of root: C makes `/var/empty` its root directory, sets the groups to the group of `nobody`, and a failure of any step is fatal (exit 1); Rust only set the gid and the uid, ignored the errors, kept the root directory `/`, and had no group | 2026-11-25 | fixed | rsoftflowd: Drop the privileges of a daemon like C does | 2026-11-25, found with D47 (`/proc/PID/root` was `/`).  A daemon of root, `-i lo`, C and Rust: the same uid, gid, groups (only the group of `nobody`), root and cwd (`/var/empty`), the same 72 bytes exported, and the pid file and the control socket stay, as C leaves them.  The gate items "daemon (privileges, syslog)" (the same lines in syslog) and "start order, as root -i lo captures (daemon)" are MATCHED; they were `unexpected` before D47.  `setup_export_targets()` is called before the drop (the root directory is empty, so a name and the sockets have to be made before), and `/etc/protocols` is read before.  `tests/daemon_mode.rs` (as root, with `/var/empty`; fails with the old code).  Accepted: (1) in this root directory C writes `Unknown (N)` for every protocol of `statistics`, because the name service cannot be loaded there (`setprotoent(1)` does not help); Rust writes the names; (2) a program that is not root: C tries the `chroot` and exits 1 ("Unable to chroot"), Rust changes nothing, as before (the tests of a daemon, and a user with the capability for the capture, need it); (3) the user and the directory are fixed (`nobody`, `/var/empty`), C has `--with-chrootdir` |
| D30 | The flows left in the table were not exported at shutdown (SIGINT, SIGTERM, `softflowctl shutdown`) | 2026-11-15 | fixed | Export the flows left in the table at shutdown again | 2026-11-15, compat item "live on lo, burst over -m 10" (60 of 60 records; 50 or less before) |
| D31 | Both ends with the same address (as on `lo`): C makes one Biflow, Rust makes two flows | 2026-11-15 | fixed | Handle same-address Biflow in FlowKey::canonical() using port comparison | 2026-11-15, unit test `test_d31_same_address_biflow` (fails on old code) |
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
| C accepts, Rust rejects | 6 | `-s abc`, `-B abc`, `-C abc`, `-R abc`, `-R 99999`, `-R -1` (`-c /nonexistent/dir/ctl` before `-r` is accepted since D26: `-r` cancels the earlier `-c`, as in C) |
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
   D28 (D21 is fixed, see below); none is left only in the text of D12.
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
| `-b`: ICMP templates differ in size | D21 (fixed) |
| `-m N`: C 120 datagrams, Rust 596 (`many`); header time differs | D22 |
| v9 and IPFIX: C and Rust close the datagram at different records | D23 |
| `Starting expiry scan: mode` and `EXPIRED` lines | D24 |
| `Packets processed` / `Ignored packets` (2 tests) | D25 |
| Command line texts (75 of 75) | D26 (fixed) |
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
   it was written on the command line (not the base name), first 15 bytes,
   zero padded (the field is 16 bytes and ends with a NUL).
2. With `-i IF`, it is `IF`.
3. A name of 15 bytes or more is cut at 15 bytes and the field ends with a
   NUL, as C does (C keeps the name in a buffer of 16 bytes, `IFNAMSIZ`, with
   `strlcpy`, so the 16th byte is always NUL).
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

### D21. Biflow template of ICMP (measured; fixed in C, C++ and Rust)

**Goal**

With `-b`, an ICMP flow is not a biflow: the type and code of a reply (echo
reply) differ from those of the request (echo), so there is no reverse
icmpTypeCode that means anything.  The ICMP and ICMPv6 templates have no
reverse fields, and an ICMP flow is exported as one record for each direction
that has octets, like without `-b`.  Only the flows of the protocols that have
ports (TCP, UDP, SCTP, DCCP) are biflows.  The C version, the C++ version and
the Rust version do the same; the C and C++ versions differ from 1.1.1 in this.
The protocols without ports other than ICMP (GRE, ESP) are not changed.

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

**Update of 2026-11-15 (cause found, fixed in the C version).**  C asks for room for two records for every flow when no Biflow is used: `ipfix_flow_to_flowset()` (`export_template.c`) has `frecnum = bi_flag ? 1 : 2` and returns "full" when `len < data_len * frecnum`, also when only one direction has octets.  A datagram was closed up to one record too early (v9 IPv4: remaining 60 bytes, record 42 bytes, 84 asked).  Rust packs by the real size.  Decision of the maintainer: pack as far as the MTU allows (the RFCs have no rule).  The C version is changed to ask for `bi_flag ? 1 : (octets[0] != 0) + (octets[1] != 0)` records; the Rust version is not changed.  After the change the datagrams of `http.cap` and `v6-http.cap` (`-v 9`, `-v 10`, `-a`) are byte for byte the same (the PID in the IPFIX option record excepted).  Note: the C version now differs from the stable version 1.1.1 in where a datagram ends (not in the records); the stable-against-dev comparison compares the decoded records.

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

### D25. Packet statistics (measured)

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
- Fixed: the rule of what is "ignored", sampling order, and PSAMP packet counting now match C.

### D26. Command line texts (measured) - FIXED (2026-11-24)

**Goal**

The texts of command line errors and of `-h`/`--help`, and the exit status, are
the same as C, or the difference is written down as accepted.

**Acceptance Criteria**

1. The 94 cases of `PARITY_CLI_ERROR_CASES` compare equal in standard output,
   standard error and exit status, or each remaining difference is listed as
   accepted or open with its reason.  Result: 84 are the same; the 10 that
   differ were the sloppy or invalid numbers of D34 (accepted; fixed on 2026-11-26, since then 123 of 123 cases are the same).  (Before D44
   the 11th was `-R 0 -c ...`, 83 were the same.)
2. `-h` and `--help` write the usage of C to standard error and exit with 0.
3. The exit status of a wrong command line is 1 (D3).

**Context**

- Measured before the fix: 75 of 75 cases differed in the text.  Examples: no
  arguments: C `-i, -r or -R option not specified.`, Rust `Must specify a
  packet source (-i or -r).`; `-h`: C writes the usage to standard error, Rust
  wrote the clap help to standard output.
- clap writes its own messages and exit status 2.  The compatibility baseline
  is the getopt-style short options.

**Decision and change**

Choice A of the plan of 2026-11-15 (keep clap and translate its errors; B, a
getopt_long-style parser of our own, was a large change, and C, accepting the
texts, was the interim state of the mixed plan).  D3 had been fixed first (exit
status 1); the grammar was tested as D34; the texts were made like C on
2026-11-24:

- `rust/src/usage.txt` is the standard error of `softflowd -h` of C (default
  build: `-M` and `-S` present, no ntopng); only the program name and the
  version are placeholders.  It is **generated** by `tools/gen_usage_rs.py`:
  run it again when an option of C changes.  `rust/src/usage.rs` has
  `usage_text()`, `print_usage()` and `die_usage(message)` (message, usage,
  exit 1).
- `rust/src/cli_errors.rs` (`parse_daemon_args_or_exit()`) turns the clap
  errors into the texts of C.  It is a module of its own because `build.rs`
  includes `opts.rs` alone, so `opts.rs` cannot refer to `crate::...`.  An
  option that takes a value takes the next word also when it begins with `-`
  (as getopt does; the positional BPF filter is not affected); `-r` cancels an
  earlier `-c`; any other clap error exits with 1 (the default of clap is 2).
- `rsoftflowd.rs` checks in the same order as C and uses `die_usage` at the
  same places; the check that no packet source is given comes after the checks
  of the other options.  `-n`: an empty host goes on to the name lookup
  (`No addresses found for [host]:port`), a port above 65535 or an overflow is
  `Invalid -n argument.`.  `-t`: only the message of a general timeout of 0 has
  no usage.  `-e`: the name is resolved, and a failure prints `getaddrinfo:
  Name or service not known` and goes on.
- The messages of libpcap and of the control socket are those of C:
  `pcap_open_offline(FILE): ...`, `pcap_compile("FILTER"): ...`,
  `pcap_activate: ...`, `pcap_create: ...`, `unix domain bind("PATH") error:
  ...`, `control socket path too long`.

*Test:* `tests/cli_errors.rs` fails with the old code.  *Table:* the exact
first line and exit status of C and of Rust for each case are in
`rust/doc/CLI-PARITY-CASES.md` (made by `tools/gen_cli_parity_cases.py`; a
difference in the table is a row here).  *Gate:* the 66 entries of
single cases are deleted; the entries `SUM` and D34 were left until D34 was fixed (the entry of D44 was deleted when D44 was fixed, and `SUM` went from 11 to 10), and are deleted now: the gate has no entry.

### D27. `-g -M` CPU clock lines (measured) - FIXED (2026-11-15)

**Goal**

`-g` with `-M` prints the same lines as C.

**Acceptance Criteria**

1. The compat item "cpu clocks of -g -M" has the same lines as C (the values
   differ by nature; the set of lines and their format must not).
2. The item "cpu clocks of -g" stays MATCHED.

**Context**

- Measured: C with `-M`: only the total (1228); Rust: total (455) and
  `cpu clocks (export): 8 (1 calls)`.  Without `-M` both print both lines.

**Design of the change (2026-11-15, written for the implementer).**

*File:* `rust/src/bin/rsoftflowd.rs`, the end of `main` (`if tracker.param.gauge_clock {`).

*What C does* (`softflowd.c:535-545`): it prints `cpu clocks: N`, and then, if `-M` is given, the line `cpu clocks (export): n/a with threaded export`; without `-M` it prints `cpu clocks (export): N (K calls)`.  The Rust version accepts `-M` (`args.use_thread`) but exports in the calling thread, and always prints the number.

*Change:* in the `if tracker.param.gauge_clock` block, print `cpu clocks (export): n/a with threaded export` when `args.use_thread` is true, and the existing line otherwise.  Do not change anything else (keep `eprintln!`; the stream is not part of this item).

*Tests:* an integration test in `rust/tests/integration_tests.rs`: run `rsoftflowd -r <pcap> -g -M -n 127.0.0.1:<port>`; stderr contains `cpu clocks (export): n/a with threaded export` and no `calls)`; without `-M` it contains `calls)`.  It fails on the old code.

*Gate:* delete the entry `D27` of `tools/gate_expected.json`; the compat items "cpu clocks of -g -M" (and "live on lo, cpu clocks of -g -M") are MATCHED; "cpu clocks of -g" stays MATCHED.  Set the row of D27 to `fixed` in both documents.


### D28. Control socket replies and signals (measured on 2026-11-02, partly re-measured) - FIXED (2026-11-15)

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

**Design of the change (2026-11-15, written for the implementer).**  Six small edits; each one is a line or a few lines.  After each edit run the compat items named below.

1. *`timeouts` reply* (`rust/src/control.rs`, the code that writes `tcp = 3600 ...`): write the eight lines of C (`stats.c:258-267`), exactly (`%d` is the value in seconds; the text before it is padded with spaces to the right edge):
```
           TCP timeout: 3600s
  TCP post-RST timeout: 120s
  TCP post-FIN timeout: 300s
           UDP timeout: 300s
          ICMP timeout: 300s
       General timeout: 3600s
      Maximum lifetime: 604800s
       Expiry interval: 60s
```
   The reply starts with `softflowd[PID]: Printing timeouts:` and the pid; that is already so.  The program name stays what the harness expects.
2. *`shutdown` command*: delete the log line `Shutdown command received.` (`rsoftflowd.rs`, near line 363).  C logs only `Shutting down on user request` (WARNING), once, at the end.
3. *`exit` command*: delete `Exit command received.`; where the program leaves at once, log `Exiting immediately on user request` with `log::warn!` (C: `softflowd.c:493`).
4. *The last line*: delete `log::info!("Shutting down complete, exiting.")` (`rsoftflowd.rs`, near line 521).  C writes nothing there.
5. *SIGHUP*: the text is `SIGHUP received (config reload not implemented)` (C: `softflowd.c:388`); Rust has `SIGHUP received, re-opening logs (not implemented yet)`.
6. *SIGUSR1* (a real bug): Rust does not handle it, so the default action ends the process.  Register it as the others are (`signal_hook::flag::register(SIGUSR1, ...)`, `rsoftflowd.rs` near line 60) and, in the main loop, when the flag is set, log `stats: tracked=<flows in the table> total_packets=<packets>` at info level (C: `softflowd.c:377-384`; `%u` and `%llu`).

*Tests:* (a) a unit test of the `timeouts` text; (b) an integration test: start `rsoftflowd -d -r <fifo or file> ...`, send SIGUSR1, and check that the process is still alive and the log has `stats: tracked=`; (c) the compat items "control replies ending with shutdown / exit", "the log of the shutdown command", "the log of the exit command", "live on lo, SIGINT / SIGTERM".  Add to the harness (see "Tests to add" below) an item for SIGUSR1 and SIGHUP.

*Gate:* delete the three entries `D28`.  Set the row of D28 to `fixed`.

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

### D30. Flows left in the table were not exported at shutdown (measured, a Rust bug)

**Goal**

At SIGINT, SIGTERM and `softflowctl shutdown`, every flow in the table is
exported before the program exits, as in C.

**Acceptance Criteria**

1. The compat item "live on lo, burst over -m 10" exports 60 of 60 flows, once
   each, with `-m 10` and with a larger `-m`.
2. The log still has `Shutting down on user request` once.

**Context**

- Measured: with `-m 100` and 60 flows, 0 records were exported (50 with
  `-m 10`): only the flows that a full table had pushed out left.
- Cause: commit `75afd87` added a check at the top of the main loop that
  clears the shutdown flag and breaks.  The code that exports all flows is at
  the end of the loop and was never reached.  The check is removed; the end of
  the loop handles the request.  The extra line `Signal received, shutting
  down.` goes away with it (see D28).

### D31. Both ends with the same address (measured, source not read yet)

**Goal**

Packets of both directions between the same address (for example `127.0.0.1`
port 53 and `127.0.0.1` port 40000) are one Biflow, as in C (RFC 5103).

**Acceptance Criteria**

1. The compat pcap `loopback` gives the same datagrams as C for `-v 1`, `-v 5`,
   `-v 9` and `-v 10`, also with `-b`, `-m 5` and `-t maxlife=1 -m 7`.
2. The `-D` log of `loopback` is identical to C.
3. A unit test with two packets (port 53 to 40000 and back, same address)
   that gives one flow with both directions.

**Context**

- Measured (`loopback -v 9 -a -D -m 5`): C `EXPIRED: [127.0.0.1]:53 <>
  [127.0.0.1]:40000 octets>:177 packets>:4 octets<:177 packets<:4`; Rust has
  two flows with `octets<:0`.
- The flow key of Rust does not decide the direction when the addresses are
  equal; C does (the same-address Biflow of the C and C++ versions).
- The datagram counts of the `loopback` cases differ because of this, not
  because of D22.

### D32. The option data record of IPFIX ignores `-e` (measured)

**Goal**

`-e ADDRESS` is written to the option data record of IPFIX, as in C: `exporterIPv4Address` (130) and `originalExporterIPv4Address` (403) for an IPv4 address; `exporterIPv6Address` (131) and `originalExporterIPv6Address` (404) for an IPv6 address; the other fields are zero.

**Acceptance Criteria**

1. The compat items `-v 10 -a -e 192.0.2.1` are identical to C for all pcaps (the PID excepted).
2. A new compat item `-e 2001:db8::1` (IPv6) is identical to C; first run C with it and decode the option record (`analysis-tools/dec.py`) to confirm which of the four fields get the address.
3. A unit test of the option data record with `exporter_ip` set (v4 and v6) and not set; it fails on the old code.
4. The entry `D32` of `tools/gate_expected.json` is deleted.

**Context**

- Measured (`http.cap -v 10 -a -e 192.0.2.1`): bytes 380-383 and 400-403 of the first datagram: C `c0 00 02 01`, Rust zeros.
- Source: `rust/src/exporter/export.rs`, `send_ipfix_flows()`: after the interface name the record gets `packet.extend_from_slice(&[0u8; 40]);` (4 + 16 + 4 + 16 bytes).  `enc_exporterAddress()` (line 253) already knows how to write the address and is not used here.  C: `enc_exporterAddress()` in `export.c` writes the first address of the right family.
- *Change:* replace the 40 zero bytes by four fields in the order of the option template (130/4, 131/16, 403/4, 404/16), each filled by the rule above.


### D33. `-b` with `-H` and `-T ether` (measured, not analyzed)

**Goal**

Find and remove the differences of the Biflow with `-H` and `-T ether`.

**Acceptance Criteria**

1. The cause of each of the two differences below is written here.
2. The compat items `-b -T ether -H 02:00:00:00:00:01` for v9 and IPFIX are identical to C, or a difference that stays is written down as accepted with its reason (then it gets an entry of kind "accepted" in `tools/gate_expected.json`).
3. The entry `D33` of the gate is deleted or turned into "accepted".

**Context**

- v9 (`smoke -v 9 -a -b -T ether -H 02:00:00:00:00:01`): datagrams of the same size; bytes differ at one byte per record (offsets 505, 621, ...: the distance is the record length, 116): C `00`, Rust `02` in the last byte of the MAC address field of the reverse direction (template 1024, fields `sourceMacAddress` and the field 57).  It looks like the address given by `-H` is used for a direction where C writes zeros, or the reverse.
- IPFIX (`-v 10 -a -b -T ether -H ...`): the sizes of the datagrams differ in both directions (C 1384, Rust 1428; C 1368, Rust 1412; C 1364, Rust 1416): different templates or records.  Part of it can be D21 (the ICMP templates), which is fixed; check the template sets first (`dec.py`).
- Not yet read: how `-H` (`--direction-mac`) chooses the direction in C (`packet.c`, `flow.c`) and in Rust.  Claude should do this item.


### D34. Command line grammar and numbers (measured; fixed, the numbers on 2026-11-26)

**Goal**

Every command line that C accepts is accepted by the Rust version with the same effect, except where the Rust version is stricter on purpose.

**Acceptance Criteria**

1. The 20 grammar cases of `PARITY_CLI_ERROR_CASES` give the same acceptance or rejection as C.
2. The numbers: both programs read the argument of `-B`, `-C`, `-I`, `-L`, `-m`, `-R`, `-s`, `-v` and `-x` as a whole decimal number (an optional `+`, digits, nothing else; `-L` also `-0`) and refuse anything else with the same text and status; `-I` takes one of `d h m s` after the digits, and `-v` a plain number.  Before 2026-11-26 C read `5x` as 5 and `abc` as 0 (`atoi`), and the difference was accepted.

+**Context**

- Found by the cases: (a) a unique prefix of a long option (`--rea FILE`): C accepts, clap did not; fixed with `infer_long_args`.  (b) the filter before the options (`udp -r FILE -n ...`): C permutes the arguments, clap took everything after the first word as the filter; fixed by removing `trailing_var_arg`.  (c) `-n` twice: C uses the last one, clap refused; fixed with `overrides_with`.  (d) the sloppy numbers: first not copied (the same decision as for `-I abc`); then, on 2026-11-26, the maintainer decided to make C (and C++) strict, and the Rust version stays as it was, except for the texts, the bound of `-B` and `-C`, and the empty value.
- `-n` may also take a comma-separated list in C (`options.c`); not tested here.


### D35. A run that is accepted: log and statistics on standard error (measured, not analyzed)

**Goal**

A run that reads a file in the foreground writes the same lines to standard error as C.

**Acceptance Criteria**

1. The 18 cases of D35 in the gate (accepted runs of the grammar and option cases) are identical to C.
2. The entries `D35` of the gate are deleted.

**Context**

- Measured: `softflowd -r FILE -n 127.0.0.1:9` writes `softflowd v1.1.1 starting data collection`, `Exporting flows from ...`, `Shutting down after pcap EOF` and `Shutting down on user request` to standard error without `-d`; `rsoftflowd` writes nothing.  The first different line of the other cases is in the statistics block (`Accumulated statistics since ...` against `Number of active flows`).
- Not read yet: the default log level of the Rust version (`env_logger` or the syslog setup in `rsoftflowd.rs`) and where C decides that the foreground logs to standard error (`log.c`).  Claude should do this item first, because it decides what D26 will look like.


### D36. Idle expiry on a live capture (measured, not analyzed)

**Goal**

A flow that is idle is exported at the same time as in C (to the second that the compat item allows).

**Acceptance Criteria**

1. The compat item "live on lo, idle expiry (-t expint=3)" is MATCHED in 20 runs out of 20.
2. The gate entry `D36` (marked flaky) is deleted.

**Context**

- Measured, 6 runs: `A at 3.0 s, B at 2.3 s`; `A 4.0, B 3.2`; `A 3.0, B 2.2`; MATCHED in some runs (`A 5.0, B 4.9`).  A is always a whole second, B is earlier by a part of a second.
- Not the cause: the periodic scan of the main loop (removed in the same patch, as C scans only when `next_expire() == 0`).  To read: the clock that C uses in `next_expire()` and `check_expired()` (`expire.c`), against `next_expire_is_now()` and `scan_expiries()` in `rust/src/expire.rs`, and the clustering of expiries by `-t expint`.  Claude should do this item.

## Quality gate and tests (2026-11-15)

### The gate: `tools/softflowd_test_suite.py gate`

One command that says whether a patch is acceptable:

```
tools/softflowd_test_suite.py gate --rust-dir rust -- \
    --a ./softflowd --b rust/target/release/rsoftflowd \
    --ctl-a ./softflowctl --ctl-b rust/target/release/rsoftflowctl \
    --skip-build --skip-cpp --skip-rust --skip-static --skip-direct --skip-psamp \
    --collector python --no-benchmark --no-gauge-clock
```

It runs `softflowd_test.py --strict`, then `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test` in `rust/`, and prints one last line, `GATE: PASS ...` or `GATE: FAIL ...`.  `--from-log FILE` judges a saved output; `--report FILE` writes JSON.  The rules, in `tools/softflowd_test_gate.py` and `tools/gate_expected.json`:

| Class | Meaning | Gate |
|---|---|---|
| accepted | a difference that is kept on purpose | passes |
| open | a known difference that is tracked here (D12) | passes |
| UNEXPECTED | any other difference or failure | **fails** |
| STALE | an entry that no line matched: the difference is gone | **fails**: the patch that fixed it must delete the entry |
| DOCS | an entry whose row here is missing or is `fixed` | **fails** |

So a patch that fixes an item must: delete its entry from `gate_expected.json`, set the row of the item to `fixed` in **both** documents, and add a test that fails on the old code.  A patch that breaks something else gives an UNEXPECTED line.  Claude's review of a patch is: (1) `git am` applies; (2) `GATE: PASS` with the entries of the item deleted; (3) only the files named in the design were changed, and the diff is small; (4) the new test fails when `src/` is reverted (`git stash -- rust/src`); (5) the rows of both documents are updated; (6) the commit message says what and why.

### Tests to add (proposals, in the order of value)

1. **Corpus of garbage** (finds bugs like D25): a script makes pcaps from `http.cap`, `v6-http.cap` and `vlan` by cutting every packet at every length from 0 to its size, and by flipping bits with a fixed seed; both binaries read them with `-v 5`, `-v 9` and `-v 10`; the exported records and the final statistics must be identical, and the exit status of Rust must not be 101 (a panic).  Add as a compat step, `--fuzz N`.
2. **Shutdown and signals** (finds bugs like D30): live on `lo` with `-m 10`, `-m 100` and the default: send 60 flows, then stop with SIGINT, SIGTERM, `softflowctl shutdown` and `exit`: records exported must equal C for each (`exit`: C exports nothing).  Add SIGUSR1 (the process must stay alive) and SIGHUP.
3. **Privilege and start order** (finds the regression of D29): as root, `-i lo` must capture; `-i nonexistent0` must exit with status 1 before it daemonizes; the first four log lines of `-d` are in the order of C, repeated 50 times (a race).
4. **Golden datagrams**: before a patch, save the datagrams of all pcaps and options of the compat matrix; after it, compare.  A patch that is not about the format must not change one byte.  (`--save-golden DIR` and `--check-golden DIR`.)
5. **Speed guard**: `softflowd_test_suite.py bench` on a pcap of 300 000 packets; fail when Rust takes more than 5 times the time of C (it is about 1.05 to 1.07 times now, measured as the CPU time of 31 interleaved runs of `gen_ci_smoke_pcap.py -n 50000`: 0.088 s against 0.082 s; it was 2.6 times).  A change that moves work to another thread, as D25 did, is then measured.
6. **`-e`, `-H`, `-b` option matrix**: run all pcaps with every combination of `-b`, `-H`, `-T`, `-e` (v4 and v6), `-s`, `-A`; D32 and D33 were found only because the matrix had these options.
7. **CLI table**: the 94 cases of `CLI-PARITY-CASES.md` are compared with the whole of standard output, standard error and exit status since D26 (done).
8. **Document check** (done in the gate): every entry has a row that is open or accepted.

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
