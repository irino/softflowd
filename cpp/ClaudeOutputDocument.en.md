# softflowd-cpp

A staged rewrite of [irino/softflowd](https://github.com/irino/softflowd) (a C
flow-monitoring / NetFlow-export daemon) into modern C++, following the
memory-safety practices described in
[this article](https://mecanik.dev/ja/posts/c++-vs-rust-memory-safety-practical-examples-with-modern-c++/)
(Japanese).

(日本語版: [README.ja.md](README.ja.md))

## Progress

| Stage | Content | Status |
|---|---|---|
| Stage 1 | Project scaffolding + core flow tracking (replacing `freelist.c` + `sys-tree.h`) | ✅ Done |
| Stage 2 | Packet capture (RAII wrapper over libpcap) + packet parsing (IPv4/IPv6/TCP/UDP/ICMP) | ✅ Done |
| Stage 3 | NetFlow v1/v5/v9, IPFIX, PSAMP export | ✅ Done |
| Stage 4 | Daemonization, signal handling, `softflowctl`-equivalent CLI control, full CLI compatibility with the original softflowd | ✅ Done |
| Stage 5 | Real implementations of MPLS (`-x`), all absolute time formats (`-A`), TCP/SCTP export (`-P`), IPFIX biflow (`-b`), and PSAMP receive mode (`-R`) | ✅ Done |
| Stage 6 | Corrected the `softflowctl` command set to exactly match the real manual, plus multi-line response support | ✅ Done |
| Stage 7 | Verified softflowctl's own CLI grammar (already correct) + hardened `-R`'s template bookkeeping to be scoped per sender | ✅ Done (partial; see below) |
| Stage 8 | Followed the current C version: PSAMP and ntopng in the C format, control socket with `-r`, expiry interval, `-t icmp`, `-s`, snaplen, live capture in batches; byte for byte comparison with the C build | ✅ Done (open items below) |

## Stage 8: following the current C version

The C++ version was brought up to the current C version in small patches. The
C build is the reference: `tools/softflowd_test_collector.py compat --a
./softflowd --b ./cpp/build/softflowd+ --strict --psamp` compares the exported
datagrams byte for byte, the control replies, the expiry lines of the `-D` log
and the flows that a live capture on `lo` exports (Step 5). Not covered: the
compatibility code of the C version (`--enable-legacy`,
`--enable-compat-export`) and the JSON export for ntopng 5.x and earlier.
The executables are `softflowd+` and `softflowctl+`.

### PSAMP (replaces the PSAMP descriptions of Stages 3, 5 and 7)

PSAMP uses the format of the C version. A message carries one captured packet:
its position in the sequence of sampled packets, its capture time, the number
of octets of the frame that are exported and the frame itself. Every data
message has the size of a full export packet, the template ID is 3072 and the
template is sent again after 16 data messages.

`-R receive_port` works without `-i`: nothing is captured and the frames that
are received are Ethernet frames. Only the data records that softflowd itself
exports are decoded, so the per-sender template bookkeeping of Stage 7 no
longer exists. The flows that are received take their times from the
observation time of the messages, and with `-a` the first message is the boot
time, as in the C version.

### ntopng

`-v ntopng` sends the flows in the TLV format of ntopng 6.0 and later (a
36-octet header and the nDPI serializer format) over a ZeroMQ PUB socket that
connects to the `-n` destination. The sink that sends the messages is built
with `-DSOFTFLOW_NTOPNG=ON` and needs libzmq (found with pkg-config); the
JSON format of ntopng 5.x and earlier is not implemented. As in the C version,
the statistics line `Flows exported` stays 0 for ntopng.

```sh
cmake -S cpp -B /tmp/build-zmq -DSOFTFLOW_NTOPNG=ON && cmake --build /tmp/build-zmq -j
/tmp/build-zmq/softflowd+ -i eth0 -v ntopng -n 127.0.0.1:5556
```

### Control socket while reading a file

`-c` is accepted together with `-r`, so that `softflowctl+` can be used while
softflowd waits for a FIFO or reads a file (the pcap file descriptor and the
control socket are polled together at the batch boundaries). The replies, the
usage and the exit codes of the control commands are the same as those of the C
version.

### Other changes

| Item | Behavior |
|---|---|
| Timeouts | `-t icmp=` is accepted and `-t general=0` is rejected. `-t expint=` (default 60 s) clusters the expiry of flows into fewer, larger export packets |
| Expiry | The order and the reasons of the expired flows, and the lines of the `-D` log, follow the C version; a flow table that holds more than `-m` flows is checked once per `max_flows` packets |
| Live capture | The default snaplen is 96 bytes (160 when IPv6 flows are tracked; `-C` changes it). The capture handle is non-blocking and the packets are taken in units of `pcap_dispatch (max_flows)`. A snaplen of 65535 made libpcap drop many packets in a burst |
| `-s` | The sampling rate is written into the sampling_interval of the NetFlow v5 header (it used to be 0) |
| Flow sequence | `flow_seq` is a monotonic counter (it used to be the number of tracked flows, so numbers repeated) |
| `-F hash`, `-F hash-tree` | The number of buckets and the capacity follow the C version: a power of two, at most 2^24 |
| Times of a live capture | The flow times are the libpcap timestamps of the packets (`phdr->ts`), not the time at which they are read. With `-a` the first packet is the boot time and the time of the last packet is the current time (poll timeout, expiry, final expiry, `expire-all`), as in the C version |
| Command line errors | The messages, the usage (the C text, with the options of this project after it) and the exit status 1 are those of the C version, and so are its rules: `-L` 0 to 255, `-s`, `-B`, `-C` and `-R` read by `atoi ()`, names of `-T`, `-P` and `-A` that are not case sensitive, a later `-n` replaces the earlier, at most 16 destinations, each resolved when the option is read, `-t` parsed by `convtime ()` |
| Errors of the start | The capture, its filter and the control socket are set up before the process forks, so that their errors are seen and the exit status is 1 (they were lost with the standard error of the daemon). The texts are those of the C version (`pcap_activate: ...`, `pcap_compile("..."): ...`, `unix domain bind("...") error: ...`) |
| `-T port` | Tracks the ports and exports no ToS, between `proto` and `full`. `-T full-tos` of this project is kept |
| `-i idx:interface` | The index is put in the input and output interface of NetFlow v1 and v5, in the ingress and egress interface of v9 and IPFIX, and in the scope of their options. Without it, the index of the interface is looked up when the daemon starts if there is a destination |
| `-c none` | No control socket |
| No destination | Without `-n` the packets are made and counted as exported, as in the C version |
| Statistics of the packets | "Packets processed" and "Ignored packets" (non-IP, too short) count as the C version does, also with `-v psamp` and `-s` |
| Log | `logit ()` as in the C version: to the standard error in the foreground, to syslog (LOG_DAEMON, with the PID) for a daemon. The start, the end (`Shutting down on user request`, `Exiting immediately on user request`), the debug lines of the expiry and `-g` use the texts and the levels of the C version; the lines `[softflowd] ...` that were written to the standard output are gone |
| Privileges | A daemon (no `-d`) changes its root to `/var/empty` and its user to `nobody` once it has opened the capture, the sockets and the files (`PRIVDROP_CHROOT_DIR`, `PRIVDROP_USER`), with the messages of the C version; it needs root and `/var/empty`. Its pid file and control socket are left when it stops, as with the C version |
| Same address at both ends | The packets of both directions of a conversation with one address at both ends (a loopback interface) are one Biflow (RFC 5103): the endpoint with the lower port is the first one. The C version, which compared the address only, was changed to do so too |
| `-b` | The statistics count one record for each flow |
| `-g` | The cpu clocks are reported when the daemon stops, for a capture file and for a live capture: to the standard error, or to syslog for a daemon; with `-M` the clocks of the export are "n/a". The measurements of compat use an optimized build, as the default build has the sanitizers |

### Known differences and open items

- The `Flow table:` line (in use, max depth, collisions) differs, because the
  hash function is another one.
- Command lines in which the C version is wrong are not matched:
  `-I abc` and an unknown host of `-e` (it prints the text of an errno that
  the call did not set), the port of `-n` (cut to 16 bits by the C version; the
  C++ version shows it as written), a time of `-t` that does not fit an int
  (cut by the C version, rejected here), the file name of `-r` in
  "Exporting flows from" (cut to 15 characters by the C version), and the ToS
  of an IPv6 packet (the C version exports 0 because of a byte order mistake in
  its mask).
- Live capture was checked on `lo` only, not on a physical NIC or on BSD.
  `--enable-ifname` and the interfaceName of the option records are not
  implemented.
- The number of export packets of a forced expiry in a live capture depends on
  how libpcap hands over the packets (the C version varies between runs too)
  and is not matched.

## Stage 7: softflowctl CLI grammar check + hardening -R's template bookkeeping

- Checked softflowctl's own command-line grammar (`-c ctl_sock command`)
  against the original manual page: **already correct, no change needed**.
- `PsampReceiver`'s template bookkeeping is now scoped by (sender
  address:port, template ID) instead of template ID alone. Since template
  IDs only need to be unique *per exporter*, not globally, two different
  PSAMP exporters could previously corrupt each other's decoded data by
  coincidentally reusing the same template ID for different record
  layouts. The `-i` live-capture loop now uses `recvfrom()` instead of
  `recv()` to obtain the sender's address for this purpose. A test
  reproduces two independent exporters using the same template ID and
  confirms they no longer interfere with each other.
- Real-world SCTP testing and broader live-capture test coverage remain
  open items, limited by this development environment (no SCTP kernel
  module available).

## Stage 6: correcting the softflowctl command set

While planning Stage 6, re-checking the original softflowd(8) manual page
for the "configuration file loading" item planned at the end of Stage 5
revealed that **there is no `-f` option in upstream softflowd at all** --
that was based on a mistaken assumption. What actually exists is an
OpenWrt package's UCI configuration wrapper, which translates its own
config options into plain command-line arguments before invoking
softflowd; it isn't a feature of softflowd itself. That item has been
dropped from the plan. While correcting this, the real `softflowctl(8)`
command set was checked too, and it turned out this project's earlier
implementation (`shutdown`/`exit`/`expire-all`/`delete-all`/`statistics`/
`stop`/`start`) had both a naming mistake and several missing commands.

### Corrected command names

- `stop` -> `stop-gather`, `start` -> `start-gather` (matching the
  original's actual names)

### Newly implemented commands

- `debug+`/`debug-`: raise/lower the daemon's debug verbosity (reflected
  in `statistics`' output too)
- `dump-flows`: report details on every currently tracked flow (using a
  new, non-destructive `FlowTable::snapshot()` method -- unlike
  `expire_flows()`/`force_expire_oldest()`, this removes nothing)
- `timeouts`: report the configured flow timeout values
- `send-template`: force the NetFlow v9 template to be resent before the
  next export (a new `Netflow9Exporter::force_template_resend()`;
  correctly reports "no effect" for other export formats)

### Multi-line control-protocol responses

While implementing `dump-flows`, the existing control protocol
(`read_line`/`write_line`) turned out to only be able to read **a single
line**, silently truncating any multi-line response at its first embedded
newline. The fix was a new `read_until_eof()` on the `ControlClient` side
(reading until the server closes the connection), with `send_command()`
switched over to it. The server side keeps using `read_line()` to read
the incoming command (which is correctly single-line), and already closes
the connection right after writing its response -- the two sides now
agree on the same framing. Verified end-to-end with a real tracked flow,
confirming `dump-flows` now returns every line.

## Stage 5: turning Stage 4's simplified/unimplemented options into real implementations

All five options that Stage 4 accepted but only partially implemented now have real implementations.

### `-x number_of_mpls_labels` (MPLS label stack parsing)

The packet-parsing layer (in `softflowd.cpp`) now detects the MPLS
EtherTypes (`0x8847`/`0x8848`) and walks the label stack to find the IP
header regardless of how many labels are on the stack. Up to `-x`'s
requested count are stored in `Flow::mpls_labels` and exported as NetFlow
v9/IPFIX `mplsLabelStackSection1`-`10` fields (IANA IEs 70-79). Verified
end-to-end against a real MPLS-encapsulated pcap file, confirming both the
label values and the bottom-of-stack bit are exported correctly.

### `-A sec|milli|micro|nano` (all absolute time formats)

All four IPFIX/PSAMP timestamp formats are now implemented: `sec`/`milli`
are plain integers, and `micro`/`nano` use RFC 7011's 64-bit NTP format
(32-bit seconds since 1900, plus a 32-bit fraction) -- documented honestly
that `micro` and `nano` only differ in which Information Element numbers
are used, since both share the same 32-bit fraction field's actual
precision.

### `-P udp|tcp|sctp` (transport selection)

`ExportDestination` now takes a transport kind; UDP and TCP are both fully
implemented (verified against a real TCP listener). SCTP is attempted only
where `IPPROTO_SCTP` is available, falling back to UDP automatically (with
a warning) if the connection fails, since SCTP support depends on kernel
module availability.

### `-b` (IPFIX biflow, RFC 5103)

A real (not simplified) biflow encoding: both directions of a flow are
combined into a single record, with the reverse direction's octet count,
packet count, and TCP flags encoded as RFC 5103 Reverse Information
Elements (Private Enterprise Number 29305).

### `-R receive_port` (PSAMP receive mode)

A new `PsampReceiver` class generically decodes IPFIX-framed Template Sets
and Data Sets (fields it doesn't recognize are skipped by their declared
length, so it can decode more than just this project's own wire format).
It's wired into the `-i` live-capture loop as a fourth polled file
descriptor; received PSAMP samples are fed into
`FlowTable::record_packet()` exactly like locally captured packets.
Verified end-to-end between two `softflowd+` instances (one exporting
`-v psamp -n`, the other receiving via `-R`).

### An environment-specific issue found and fixed during development

While validating `-R`, the live-capture loop turned out to rely on
**libpcap's internal read timeout being reliable, which it is not in every
environment**: in this project's test environment, a first packet would be
retrieved successfully, but a second `next_packet()` call would block
indefinitely instead of honoring its configured 100ms timeout. The fix was
to stop relying on that internal timeout altogether: the packet-draining
loop now does an explicit zero-timeout `poll()` check immediately before
each `next_packet()` call after the first, only calling it when a packet
is actually known to be waiting. This is a more robust design on top of
the existing per-cycle batch limit (32 packets), independent of how
reliably any given platform's libpcap honors its own timeout.

## Stage 4: Daemonization + full CLI compatibility with the original softflowd

`daemon.hpp/cpp` (original: `daemon.c`) implements `PidFile` (RAII),
`daemonize()`, and `SignalPipe` (safe signal handling via the self-pipe
trick). `softflowctl.hpp/cpp` (original: `softflowctl.c`) implements the
control protocol (newline-delimited text commands over a Unix domain
socket) and the client itself. `softflowd.cpp` gained a live-capture event
loop (`poll()` across the signal pipe, control socket, and pcap file
descriptor simultaneously) for `-i`.

### Command-line options now exactly match the original softflowd

Through Stage 3 this project used its own long-option names (`--backend`,
`--export`, `--live`, etc.). Stage 4 replaces those with **the exact same
getopt-based single-letter option grammar as the original `softflowd(8)`**,
so existing deployment scripts, init files, and muscle memory keep working
unchanged.

```sh
# Exactly the same invocations as the original softflowd
softflowd+ -i eth0 -n 10.1.0.2:4432 -m 65536 -t udp=1m30s
softflowd+ -i eth0 -l -n 10.1.0.2:4432,10.1.0.3:4432
softflowd+ -v 9 -i eth0 -n 224.0.1.20:4432 -L 64
softflowd+ -i eth0 -p /var/run/sfd.pid.eth0 -c /var/run/sfd.ctl.eth0
```

Options implemented with the same meaning and syntax as the original:

| Option | Meaning |
|---|---|
| `-i [if_ndx:]interface` | Interface to capture live from |
| `-r pcap_file` | Read from a pcap file instead (doesn't fork; prints statistics on exit) |
| `-n host:port[,host:port...]` | Real UDP export destination(s) for NetFlow/IPFIX/PSAMP |
| `-N` | Don't set promiscuous mode |
| `-l` | Load-balance across multiple `-n` destinations (round-robin per packet) |
| `-L hoplimit` | TTL/hop limit on exported packets |
| `-e exporter_ip_address` | Source address for export packets |
| `-S send_interface_name` | Outgoing interface (`SO_BINDTODEVICE`) |
| `-p pidfile` / `-c ctlsock` | Pidfile / control socket paths |
| `-m max_flows` | Maximum concurrent flows (default 8192) |
| `-t timeout_name=time` | Set a timeout (`general`/`tcp`/`tcp.rst`/`tcp.fin`/`udp`/`maxlife`/`expint`); supports time specs like `10m` or `1h30m` |
| `-d` | Run in the foreground (don't daemonize) |
| `-6` | Force tracking of IPv6 flows |
| `-D` | Debug mode (implies `-d` and `-6`, plus extra logging) |
| `-T track_level` | `ip`/`proto`/`full` (default)/`vlan`/`ether` |
| `-v netflow_version` | `1`/`5` (default)/`9`/`10` (IPFIX)/`psamp` |
| `-s sampling_rate` | Systematic 1-in-N sampling |
| `-C capture_length` | Snaplen |
| `-B size_bytes` | libpcap buffer size (implemented via `pcap_create`/`pcap_activate`) |
| `-h` | Print usage |
| trailing arguments | Concatenated as a BPF filter expression |

### Options that used to be partially implemented -> now fully implemented in Stage 5

As of Stage 4, the following were simplified or unimplemented. **Stage 5
implements all of them for real** (see the Stage 5 section above for
details). Only `-P sctp` still has an environment-dependent fallback:
where the kernel's SCTP module isn't available, it automatically falls
back to UDP at run time.

| Option | Status |
|---|---|
| `-P transport_protocol` | udp and tcp implemented; sctp depends on the environment (falls back to udp automatically if unavailable) |
| `-A time_format` | sec/milli/micro/nano all implemented |
| `-b` | Real RFC 5103 biflow encoding implemented |
| `-x number_of_mpls_labels` | MPLS label stack parsing implemented (NetFlow v9/IPFIX) |
| `-R receive_port` | PSAMP receive mode implemented (only meaningful together with `-i`) |

### This project's own additions (not part of the original softflowd)

These use GNU-style long options specifically so they can't collide with
any of the original's single-letter flags:

| Option | Meaning |
|---|---|
| `--export-out=PATH` | Also write export packets to a file, each prefixed with a 4-byte big-endian length |
| `--max-runtime=SECONDS` | Shut down automatically after SECONDS (mainly for testing/demos) |

### Options that follow the C version

The short options of the original have the long names of the C version
(`--max-flows`, `--timeout`, ...; see `softflowd -h`). These follow the C
version's current behavior:

| Option | Meaning |
|---|---|
| `-F`, `--flow-lookup tree\|hash\|hash-tree` | Flow table: `tree` is a `std::map`, `hash-tree` (the default) a `std::unordered_map` that keeps colliding flows, `hash` has one slot per bucket and exports the flow that a collision evicts. Replaces `--backend` |
| `-f`, `--full-transport-header-check` | Require the whole transport header; by default only the bytes that are read are required (`--icmp-typecode-only` is accepted and does nothing) |
| `-H`, `--direction-mac` | MAC address that decides flowDirection (with `-T ether`; the capture interface's address by default) |
| `-M`, `--multithread` | Export from another thread and, in a live capture, process packets in another thread |
| `-m`, `-x` | `-m` is 1 or more and `-x` is 1 to 10 |

`-T vlan` and `-T ether` track 802.1Q VLAN IDs and Ethernet addresses and
export them as vlanId, postVlanId, sourceMacAddress and
postDestinationMacAddress. NetFlow v9 is exported by the IPFIX exporter, as in
the C version, so there is no separate `netflow9` file. NetFlow v1 packets
hold at most 24 records. With `-l` and several destinations the templates are
sent to all of them in a packet of their own.

### `-a` (adjusting pcap file timestamps)

When reading a pcap file with `-r`, `-a` uses the packets' actual capture
timestamps (`pcap_pkthdr.ts`) as the reference time for flow tracking
(without it, flow timing is based on how fast this process reads the
file instead). This required adding a `wall_timestamp` field (libpcap's
own recorded time) to the `CapturedPacket` that `PcapHandle::next_packet()`
returns.

### `main()` and softflowctl as separate executables

As in the original, `softflowctl` is its own standalone executable
(`softflowctl+`). `softflowctl.cpp` contains both the shared
control-protocol helpers (`read_line`/`write_line`/`ControlClient`) and
`softflowctl+`'s own `main()` (guarded by `#ifndef SOFTFLOW_NO_MAIN`).
`softflowd+`'s control-socket *server* side lives in `softflowd.cpp`
itself (matching the original, where `softflowd.c` owned the
listening/accepting code), linking only against softflowctl.cpp's shared
protocol helpers.

## Stage 3: NetFlow/IPFIX/PSAMP export

Unlike Stage 1/2, Stage 3's files (`netflow1`/`netflow5`/`netflow9`/`ipfix`/
`psamp`) are **not** folded into `softflowd.hpp`/`softflowd.cpp`. These were
genuinely separate files in the original project too, so that boundary is
kept as-is:

```
include/softflow/
  export.hpp         The exporters of NetFlow v1 (fixed-length records, no templates),
                     v5 (adds a flow_sequence counter), v9 (RFC 3954) and
                     IPFIX (RFC 7011, absolute timestamps)
  export_common.hpp  What they share: NTP time, uptime/epoch time, Set padding,
                     the address of -e, template IDs
  ipfix.hpp          The types of IPFIX and NetFlow v9
  netflow.hpp        The sizes of the NetFlow v1 and v5 packets
  psamp.hpp          PSAMP (RFC 5477, per-packet sampling, IPFIX framing)
src/
  export.cpp / export_common.cpp / psamp.cpp
```

Each exporter builds actual wire-format byte buffers from the list of
`ExportRecord` values (a `FlowKey` + `Flow` pair) returned by
`FlowTable::expire_flows()`/`force_expire_oldest()`, using `ByteWriter`
(defined in `softflowd.hpp` -- the one utility genuinely shared across all
five files). None of them perform any network I/O themselves, which is
what makes them deterministically unit-testable without a real network.

**Differences from / simplifications versus the original:**
- Uses `ByteWriter`'s explicit big-endian writes (bounds-checked, and
  structurally immune to alignment violations or a missed byte-order
  conversion) instead of the original's `__packed` struct +
  `htons()`/`htonl()` approach
- NetFlow v9/IPFIX support exactly two fixed templates (one for IPv4, one
  for IPv6) rather than the original's more dynamic template management
- PSAMP, being fundamentally about per-packet sampling, takes its own
  `SampledPacket` type as input rather than `FlowTable`'s output. Fields
  RFC 5477 defines for selector identification and packet hashes are
  omitted in favor of a practically useful subset (timestamp, addresses,
  ports, protocol, observed length)
- Try it directly from the `softflowd+` executable via
  `--export=netflow1|netflow5|netflow9|ipfix|psamp` (see below)

```sh
./build/softflowd+ --export=netflow9 --export-out=out.bin path/to/capture.pcap
```

The output file concatenates each export packet with a 4-byte big-endian
length prefix (a framing convention specific to this project's demo
output, not part of the NetFlow/IPFIX specifications themselves).

## Design rationale: why everything lives in softflowd.hpp / softflowd.cpp

The original softflowd centered on `softflowd.c`/`softflowd.h`: `main()`,
packet parsing (`ipv4_to_flowrec`/`ipv6_to_flowrec`/`transport_to_flowrec`),
and the calls into flow-expiry management all lived in `softflowd.c`, while
the flow/expiry struct definitions lived in `softflowd.h`. `freelist.c` /
`treetype.h` / `sys-tree.h` existed as supporting files implementing
`struct FLOWTRACK` (the flow set plus its expiry bookkeeping).

This project follows that same monolithic layout as closely as possible,
to the extent it doesn't conflict with the goal of using modern C++:

- **`include/softflow/softflowd.hpp`**: every public type --
  `Flow`/`FlowKey`/`FlowTable`/`PacketParser`/`PcapHandle`, etc. -- is
  declared here (equivalent to the original `softflowd.h` + `common.h` +
  `freelist.h`/`treetype.h`/`sys-tree.h`)
- **`src/softflowd.cpp`**: every implementation, plus `main()` (equivalent
  to the original `softflowd.c` + `freelist.c`)

Packet parsing (formerly `packet_parser.*`) and pcap capture (formerly
`capture.*`) have no corresponding standalone file in the original project
-- that logic lived directly inside `softflowd.c`. An earlier revision of
this project split them into separate files; per feedback, they have been
folded back into `softflowd.hpp`/`softflowd.cpp`.

The "manage the flow set" responsibility that the original spread across
three files (`freelist.c` + `treetype.h` + `sys-tree.h`) is consolidated
into a single class, `FlowTable` (with a selectable backend data structure,
described below), which likewise lives in `softflowd.hpp`/`softflowd.cpp`.

### Reconciling `main()` with unit tests

`softflowd.cpp` contains `main()`, but the test executables
(`test_flow_table`, `test_packet_parser`) each supply their own `main()`
too -- linking the same `.cpp` into both would be a duplicate-symbol error.
To avoid this, the `main()` inside `softflowd.cpp` is wrapped in
`#ifndef SOFTFLOW_NO_MAIN`, and `CMakeLists.txt` compiles the same source
file two different ways:

- the `softflowd+` executable: `softflowd.cpp` compiled as-is (`main()` included)
- `softflow_core` (an object library used only by the tests): `softflowd.cpp`
  compiled with `-DSOFTFLOW_NO_MAIN` (`main()` compiled out), so each test
  can supply its own `main()`

## Selectable flow-tracking data structure (tree or hash)

The original softflowd tracked flows in a red-black tree implemented via
`sys-tree.h`. In this project, `FlowTable` is a template class, and
`FlowIndexBackend` selects which container backs it:

- `FlowIndexBackend::Hash` -> `std::unordered_map<FlowKey, Flow>` (a hash
  table, average O(1) lookup)
- `FlowIndexBackend::Tree` -> `std::map<FlowKey, Flow>` (actually
  implemented as a red-black tree in libstdc++/libc++ -- the closest modern
  equivalent of the original's `sys-tree.h`)

**Compile-time selection** (a template parameter, zero runtime overhead):

```cpp
softflow::FlowTable<softflow::FlowIndexBackend::Tree> table(65536);
```

**Run-time selection** (via `FlowTableRuntime`, a `std::variant`-based wrapper):

```cpp
softflow::FlowTableRuntime table(softflow::FlowIndexBackend::Tree, 65536);
```

The `softflowd+` executable can switch the flow table at run time via
`-F hash-tree` / `-F tree` / `-F hash` (see below).

## Building

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Dependency: `libpcap-dev`. With `CMAKE_BUILD_TYPE=Debug` (the default),
AddressSanitizer / UndefinedBehaviorSanitizer are enabled automatically.

```sh
# Process a pcap file and print statistics (-r, same as the original)
./build/softflowd+ -r path/to/capture.pcap

# Use the red-black tree (std::map) flow table
./build/softflowd+ -r path/to/capture.pcap -F tree

# Actually export NetFlow v5 to a collector (same as the original)
./build/softflowd+ -i eth0 -n 10.1.0.2:4432 -m 65536 -t udp=1m30s

# Live capture, controlled via softflowctl
./build/softflowd+ -i eth0 -d -c /tmp/sf.ctl &
./build/softflowctl+ -c /tmp/sf.ctl statistics
./build/softflowctl+ -c /tmp/sf.ctl shutdown
```

## Memory-safety mapping (article principle -> where it's applied)

| C pitfall from the article | Where it appeared in the original | How this project addresses it |
|---|---|---|
| Ownership spread across raw pointers; double free / use-after-free | `freelist.c` (a hand-rolled free list), the mutual `FLOW*` <-> `EXPIRY*` raw pointers | The associative container inside `FlowTable` is the sole owner. Expiry bookkeeping only ever holds a *key* (`std::multimap<TimePoint, FlowKey>`) |
| Broken iterator invariants from copying | (no original equivalent -- the original design simply wasn't copyable at all) | `FlowTable` deletes its copy constructor/assignment and allows only moves; the reason is documented in a comment |
| Fixed-size buffer + separate length variable, missing bounds checks | `mplsLabels[10]` + `mplsLabelStackDepth`; the extension-header walk in `ipv6_to_flowrec()` | `std::vector`/`std::span` tie length and storage into a single value |
| Type punning via casts (a strict-aliasing violation) | Casting raw byte buffers onto structs, e.g. `(const struct ip *) pkt` | Only byte-at-a-time reads from `std::span<const std::uint8_t>` are used |
| Forgetting to release a manually-managed resource | Manual `pcap_close()` on `pcap_t*` (missed on at least one exit path) | RAII via `std::unique_ptr<pcap_t, PcapCloser>` |
| Raw integers with an implicit, easy-to-mismatch unit (seconds vs. milliseconds, etc.) | All timeout values were plain `int` (seconds) | `std::chrono::seconds` etc. embed the unit in the type |
| Integer sentinel values for errors (`-1`, `PP_BAD_PACKET`, etc.) going unchecked | `process_packet()`'s `int` return value | `std::optional<ParsedPacket>` / exceptions (`PcapError`) encode failure in the type |
| The underlying data structure is hard-coded behind raw-pointer machinery | `sys-tree.h`'s red-black tree, fixed at compile time | `FlowIndexBackend` allows the choice at compile time (template) or run time (`FlowTableRuntime`) |

## Real bugs found in the original code during the rewrite

While studying the original C code, the following potential issues were
found (see the source comments for details):

1. In `ipv6_to_flowrec()`, `eh6 = (const struct ip6_ext *) pkt + size;` --
   due to the cast binding tighter than `+`, this advances by `size *
   sizeof(struct ip6_ext)` bytes rather than `size` bytes as intended.
2. `transport_to_flowrec()`'s ICMP/ICMPv6 branch has no `caplen` check
   (unlike TCP/UDP), leaving a potential out-of-bounds read on a runt
   packet.

Both are fixed in `softflowd.cpp`, and `tests/test_packet_parser.cpp`
includes regression tests for them.

## Directory layout

```
include/softflow/
  softflowd.hpp        Every core public type: Flow / FlowKey /
                        FlowTable<Backend> / FlowTableRuntime /
                        PacketParser / PcapHandle / ByteWriter /
                        ExportDestination(Set) / TransportKind, etc.
                        (original: softflowd.h + common.h +
                         freelist.h/treetype.h/sys-tree.h)
  daemon.hpp             PidFile / daemonize() / SignalPipe (original: daemon.h)
  softflowctl.hpp        Control protocol definitions / ControlClient
                        (original: softflowctl itself)
  export.hpp              Exporters of NetFlow v1/v5/v9 and IPFIX + MPLS/biflow (RFC 5103)/
                        all 4 absolute time formats (original: export.c)
  export_common.hpp       NTP time, uptime/epoch time, Set padding, -e address, template IDs
                        (original: export_common.h)
  ipfix.hpp               Types of IPFIX and NetFlow v9 (original: ipfix.h)
  netflow.hpp             Sizes of the NetFlow v1/v5 packets (original: netflow.h)
  psamp.hpp                  PSAMP + PsampReceiver (the -R receive-mode
                        decoder; original: psamp.h)
src/
  softflowd.cpp            main() + every core implementation + the live-capture
                        event loop + the control-socket server + the PSAMP
                        receive socket (original: softflowd.c + freelist.c)
  daemon.cpp                (original: daemon.c)
  softflowctl.cpp            Control protocol implementation + softflowctl+'s
                        own main() (original: softflowctl.c)
  export.cpp / export_common.cpp / psamp.cpp
tests/
  test_flow_table.cpp / test_packet_parser.cpp
  test_netflow1.cpp / test_netflow5.cpp
  test_ipfix.cpp           Includes biflow / absolute-time-format / MPLS tests
  test_psamp.cpp           Includes PsampReceiver round-trip tests
  test_daemon.cpp          Tests for PidFile/SignalPipe
  test_softflowctl.cpp     Tests for the control protocol (a std::thread plays
                        the server role, so no process needs to be spawned)
```

Building produces two executables: `softflowd+` (the daemon itself) and
`softflowctl+` (the control client).

## Open items

- A CI job with ZeroMQ (`-DSOFTFLOW_NTOPNG=ON`)
- Live capture on a physical NIC and on BSD; `--enable-ifname`
- Real-world SCTP testing (the development environment has no SCTP kernel
  module, so only the udp fallback has been exercised)
