#!/bin/sh
# Builds the C version and the C++ version (cpp/), runs the unit tests of the
# C++ version, and compares the two with tools/softflowd_test_collector.py
# compat: the exported datagrams, the control replies, the logs, the errors of
# the command line, and, as root, a live capture on lo.  The C++ version is
# built with AddressSanitizer and UndefinedBehaviorSanitizer (the build type
# Debug of cpp/CMakeLists.txt), so that an error of memory aborts the run.
#
# usage: cpp-test.sh [ntopng]
#   ntopng: build the C++ version with -DSOFTFLOW_NTOPNG=ON (it needs libzmq)
#           and compare the ntopng messages of the two versions as well.
set -eu

NTOPNG=off
[ "${1:-}" = ntopng ] && NTOPNG=on

SUDO=
[ "$(id -u)" -ne 0 ] && SUDO="sudo -E"

# The C version, the reference.  With ntopng it has the ntopng support too, as
# the usage of the C++ version tells of it and the texts are compared.
autoreconf -if
if [ "$NTOPNG" = on ]; then
    ./configure --enable-ntopng
else
    ./configure
fi
make -j"$(nproc)"

# The C++ version.
if [ "$NTOPNG" = on ]; then
    cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Debug -DSOFTFLOW_NTOPNG=ON
else
    cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Debug
fi
cmake --build cpp/build -j"$(nproc)"
ctest --test-dir cpp/build --output-on-failure

# Sample captures, so that the job does not depend on downloading them.
mkdir -p pcaps
python3 tools/gen_ci_smoke_pcap.py -n 20 pcaps/http.cap
python3 tools/gen_ci_smoke_pcap.py -6 -n 20 pcaps/v6-http.cap

# The daemon check needs /var/empty (the chroot of a daemon); it is skipped
# where /dev/log exists, as it is on a runner with journald.
$SUDO mkdir -p /var/empty

# softflowd vs softflowd+.  Root, for the live capture on lo.
$SUDO env "PATH=$PATH" python3 tools/softflowd_test_collector.py compat \
    --a ./softflowd --b ./cpp/build/softflowd+ \
    --ctl-a ./softflowctl --ctl-b ./cpp/build/softflowctl+ \
    --strict --psamp --pcap-dir pcaps --no-benchmark --no-gauge-clock --no-cache

if [ "$NTOPNG" = on ]; then
    # The C version built above has the ntopng support (it needs libzmq); its
    # messages are compared with those of the C++ version built above.
    $SUDO env "PATH=$PATH" python3 tools/softflowd_test_collector.py compat \
        --a ./softflowd --b ./cpp/build/softflowd+ \
        --ctl-a ./softflowctl --ctl-b ./cpp/build/softflowctl+ \
        --skip-parity --skip-psamp --skip-ctl --ntopng \
        --ntopng-bin ./softflowd --ntopng-cpp-bin ./cpp/build/softflowd+ \
        --pcap-dir pcaps --no-benchmark --no-gauge-clock --no-cache
fi
