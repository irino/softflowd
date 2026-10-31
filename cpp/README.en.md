# softflowd+

A rewrite of [irino/softflowd](https://github.com/irino/softflowd) (a C
flow-monitoring / NetFlow-export daemon) into modern C++ with memory-safety
practices. The executables are `softflowd+` and `softflowctl+`.

The C version in the parent directory is the reference: the C++ version
follows it, command line, exported datagrams, control socket, logs and
statistics, and is compared with it byte for byte. See
[ClaudeOutputDocument.en.md](ClaudeOutputDocument.en.md) for the design and for
what was changed in each stage (Stage 8 is the following of the current C
version).

## Build

```sh
cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Debug
cmake --build cpp/build -j
```

Dependency: libpcap. The default build type is `Debug`, which enables
AddressSanitizer and UndefinedBehaviorSanitizer (`-DSOFTFLOW_ENABLE_SANITIZERS=OFF`
turns them off). Measure the speed with `-DCMAKE_BUILD_TYPE=Release`.

`-DSOFTFLOW_NTOPNG=ON` builds the export to ntopng (`-v ntopng`, the TLV format of
ntopng 6.0 and later over ZeroMQ). It needs libzmq.

## API documentation

```sh
cmake --build cpp/build --target doc      # HTML in cpp/build/doc/html
```

Needs Doxygen (and Graphviz for the diagrams). The comments of the sources are
Doxygen comments: they describe what the C++ code does, and `@original` keeps
the note about the function or the variable of the C version that it follows
and about how it differs.

## Test

```sh
ctest --test-dir cpp/build --output-on-failure      # unit tests
```

The comparison with the C version is `tools/softflowd_test_collector.py compat`.
Build the C version first (`autoreconf -if && ./configure && make`; add
`--enable-ntopng` to compare ntopng):

```sh
python3 tools/gen_ci_smoke_pcap.py /tmp/pc/http.cap
python3 tools/softflowd_test_collector.py compat --a ./softflowd --b ./cpp/build/softflowd+ \
  --ctl-a ./softflowctl --ctl-b ./cpp/build/softflowctl+ --strict --psamp --pcap-dir /tmp/pc \
  --no-benchmark --no-gauge-clock --no-cache
```

The live checks use the loopback interface `lo` and need root (the daemon
checks also need `/var/empty`); without them they are skipped. Do not run two
of them at the same time. `.github/scripts/cpp-test.sh [ntopng]` runs the whole
sequence, and the job `cpp-test` of `.github/workflows/build.yml` runs it.

## Known differences from the C version

- The version is `v0.0.1` (the C version: `v1.1.1`).
- The `Flow table:` line of the statistics differs (another hash function).
- Not implemented: `--enable-ifname` (the interfaceName of the option records),
  the compatibility code (`--enable-legacy`, `--enable-compat-export`) and the
  JSON export for ntopng 5.x and earlier.
- Checked on `lo` only, not on a physical NIC or on BSD.
- A daemon leaves its pid file and control socket when it stops (the same as the
  C version: it is in a chroot as the user `nobody`).
