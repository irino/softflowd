# softflowd

Welcome to softflowd, a flow-based network monitor.

## Introduction

softflowd listens promiscuously on a network interface and semi-statefully
tracks network flows. These flows can be reported using NetFlow version 1, 5
or 9 datagrams. softflowd is fully IPv6 capable: it can track IPv6 flows and
export to IPv6 hosts.

More details about softflowd's function and usage may be found in the
softflowd wiki in following URLs:

- <https://github.com/irino/softflowd/wiki/softflowd>
- <https://github.com/irino/softflowd/wiki/softflowctl>

PDF manpages can be built with:

```
man -t ./softflowd.8 | ps2pdf - softflowd.pdf
man -t ./softflowctl.8 | ps2pdf - softflowctl.pdf
```

HTML manpages can be built with:

```
groff -mandoc -Thtml softflowd.8 > softflowd.html
groff -mandoc -Thtml softflowctl.8 > softflowctl.html
```

Markdown manpages (which are published in wiki pages) can be built
from above HtML manpages:

```
pandoc -s softflowd.html -o softflowd.md
pandoc -s softflowctl.html -o softflowctl.md
```

You can view those pages prior to installation using:

```
/usr/bin/nroff -c -mandoc softflowd.8 | less
/usr/bin/nroff -c -mandoc softflowctl.8 | less
```

If you are in need of a NetFlow collector, you may be interested in
softflowd's companion project "flowd" (http://www.mindrot.org/projects/flowd/).
flowd is a NetFlow collector that is maintained in parallel with
softflowd and includes a few handy features, such as the ability
to filter flows it receives as well as Perl and Python APIs to its
storage format. NB. You don't have to use flowd: any NetFlow compatible
collector should work with softflowd. An example Python collector for
testing purposes is included as "tools/softflowd_test_collector.py collect"
(the default when no subcommand is given); it decodes NetFlow v1, v5, v9
and IPFIX. The old Perl collector,
tools/deprecated/collector.pl, is deprecated: it only supports NetFlow v1
and v5.

## Installing

Building softflowd should be as simple as typing:

```
autoreconf -if # instead of "aclocal && autoheader && automake --add-missing && autoconf"
./configure
make
make install
```

softflowd uses the xxHash library to hash flows (see "Flow Table Lookup"
below). It is not bundled: ./configure uses the system library when both
`xxhash.h` and `libxxhash` are found (on Ubuntu, install `libxxhash-dev`).
Use `--without-xxhash` to never use it, or `--with-xxhash` to fail if it is
not found. Without xxHash a built-in FNV-1a hash is used, so all flow lookup
modes work either way.

The multithreaded operation (`-M`) is built when `pthread.h` and `libpthread`
are found. Use `--disable-pthread` to never build it, or `--enable-pthread` to
fail if they are not found.

Unfortunately some systems like to make life complicated. Things work
fine on the systems that I develop and test on (OpenBSD and Linux).
There is peliminary support for Solaris 9 (i.e. it compiled), but no
testing on this platform has been performed.

## Flow Table Lookup

By default softflowd hashes the active flows into buckets, each holding a
tree. The `-F` / `--flow-lookup` option selects how the active flows are
looked up:

| Mode        | Buckets                                         | What a bucket holds             | Different flows in the same bucket     |
|-------------|-------------------------------------------------|---------------------------------|----------------------------------------|
| `tree`      | 1                                               | the root of a tree of all flows | all kept in the one tree               |
| `hash-tree` | a power of two, at least `max_flows`            | the root of a tree of its flows | kept side by side in the bucket's tree (default) |
| `hash`      | a power of two, at least twice `max_flows`      | one flow                        | the resident flow is expired at once   |

`tree` is the same as `hash-tree` with a single bucket. The number of
buckets is fixed at start-up, after the options are parsed, from
`max_flows` (`-m`, default 8192) and is limited to 16777216 (2^24). A bucket
costs one pointer (8 bytes on a 64-bit system), for example 64 KiB for
`hash-tree` and 128 KiB for `hash` with the default `max_flows`. The flows
themselves are allocated as before.

In `hash` mode a flow that hashes to an occupied bucket does not wait for a
timeout: the flow already there is taken out of the table and exported by
the next expiry scan (reason "collision"), and the new flow takes its place.
A flow may therefore be exported as several records. The `collision`
counter in the statistics counts these flows; they are not counted as
forced expiries.

The hash covers the fields softflowd uses to tell flows apart at the
selected tracking level (`-T`); the TOS and the TCP flags are not part of it.
It is computed with xxHash (XXH64) when softflowd was built with it, and
with a built-in FNV-1a otherwise.

With `-D`, softflowd prints at start-up how the table was allocated:

```
Flow table: mode=hash-tree buckets=8192 (max_flows=8192)
Flow table: bucket array 65536 bytes (8 bytes/bucket), +65528 bytes vs tree mode
Flow table: flows at max_flows: 2162688 bytes (FLOW 216 + EXPIRY 48 each)
```

In `hash-tree` and `hash` mode the statistics (`softflowctl statistics`, and
at exit) have one more line, for example:

```
Flow table: hash, 16384 buckets (128 KiB), 0 in use, max depth 0, 244 collisions
```

`in use` is the number of non-empty buckets and `max depth` the most flows
in one bucket, both at the time the statistics are printed.

## Source Layout

The sources in the top-level directory are always built. compat/ holds
the sources that the default build does not need; they are kept for
backward compatibility and for systems that lack the functions they
provide.

- `compat/ipfix.c`, `compat/netflow1.c`, `compat/netflow5.c`, `compat/netflow9.c`
  Separate NetFlow v1, v5 and v9 exporters. By default export.c exports
  NetFlow v1, v5 and v9 as well as IPFIX and none of these files are
  built. With ./configure --enable-compat-export=static, the encoder-based
  exporters in export.c are left out and netflow5.c exports the fixed
  formats (v1 and v5), while ipfix.c exports the template formats (v9 and
  IPFIX) using fixed templates and data records; export.c still provides
  the packet framing shared with ipfix.c. With
  --enable-compat-export=static-separate (or --enable-legacy) all four
  are built and ipfix.c exports IPFIX only.
  If both options are given, --enable-compat-export takes precedence.

- `compat/bsd/strlcpy.c`, `compat/bsd/strlcat.c`, `compat/bsd/closefrom.c`
  Copies of the OpenBSD functions that libbsd also provides. Each is
  compiled only when neither the C library nor libbsd has the function.

- `compat/bsd/sys-tree.h`
  The OpenBSD tree macros (RB_* and SPLAY_*). It is used only when
  `<bsd/sys/tree.h>` from libbsd is not available.

./configure looks for libbsd by default. Use --without-libbsd to always
use the copies in compat/bsd/, or --with-libbsd to fail if libbsd is
not found. daemon.c in the top-level directory is not provided by libbsd;
it is compiled only when the C library lacks daemon(3). See LICENSE for
the copyright of the files that come from OpenBSD.

## Benchmarking and Compatibility Testing

tools/softflowd_test_collector.py bench compares the NetFlow/IPFIX export build
variants (see --enable-compat-export in ./configure --help)
across one or more pcap files and NetFlow/IPFIX versions, using
hyperfine for timing. Optional flags add callgrind instruction counts
(-C) and softflowd's own -g cpu-clock counters (-g) to the comparison.
Run tools/softflowd_test_collector.py bench -h for details.

tools/softflowd_test_collector.py compat (formerly run_compat_suite.py) is a
regression test suite that replays sample pcap files, and any pcap files
given on the command line, through two softflowd builds (e.g. a stable
release and a development build) and diffs their NetFlow/IPFIX output as
captured by nfdump/nfcapd, or by a built-in Python collector if nfdump is
not installed, to catch unintended changes in exported flow data. It also
records the -g cpu clock counters and the run time (time or hyperfine) of
both builds in the same run, which needs no extra tool; --no-gauge-clock
and --no-benchmark turn this off, and --callgrind and/or --perf add the
callgrind instruction counts and perf stat.
Run tools/softflowd_test_collector.py compat --help for details.

The old shell script tools/deprecated/benchmark_export.sh is deprecated: it
is only a thin wrapper of the bench subcommand.

## Licensing

Softflowd is licensed under a two-term BSD license (see the source
files for details). The code in compat/bsd/sys-tree.h is Copyright
Niels Provos \<provos@citi.umich.edu\> and comes straight from OpenBSD CVS,
convtime.c comes is Copyright Kevin Steves and comes from OpenSSH
(misc.c). Both of these files are licensed under two-term BSD licenses
too. compat/bsd/strlcpy.c, compat/bsd/strlcat.c and compat/bsd/closefrom.c
also come from OpenBSD CVS and are Copyright Todd C. Miller. Please refer
to the LICENSE file for full details.

## Reporting Bugs

Please report bugs in softflowd (https://github.com/irino/softflowd/)
to <https://github.com/irino/softflowd/issues>

Following descriptions are historical information:
Please report bugs in softflowd to <http://bugzilla.mindrot.org/> If you
find a security bug, please report it directly by email. If you have any
feedback or questions, please email me:

## Contributing

Softflowd has an extensive TODO list of interesting features, large and
small, that are waiting to be implemented. If you are interested in
helping, please contact me.

The latest source code may be obtained from Github:
<https://github.com/irino/softflowd/>  
(This repository was forked from <http://code.google.com/p/softflowd/>)

Original creator:  
Damien Miller <djm@mindrot.org>

Current maintainer:  
Hitoshi Irino <irino@sfc.wide.ad.jp>
