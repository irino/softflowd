#!/bin/sh
# Compile-checks softflowd on Linux the way the OpenBSD job of the GitHub CI
# sees it, before pushing:
#  - struct pcap_pkthdr has a struct bpf_timeval ts member, not a
#    struct timeval (OpenBSD's libpcap), and
#  - the diagnostics that recent clang releases treat as errors
#    (incompatible pointer types, implicit function declarations, ...) are
#    errors here too.
# Every --enable-compat-export layout is built out of tree in a temporary
# directory.  Needs clang (or CC), autoconf/automake and the libpcap headers.
#
# usage: tools/check-bsd-compat.sh [configure options...]

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)
cc=${CC:-clang}
work=$(mktemp -d "${TMPDIR:-/tmp}/softflowd-bsd-compat.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

pcap_h=${PCAP_H:-/usr/include/pcap/pcap.h}
if [ ! -f "$pcap_h" ]; then
  echo "$pcap_h not found; set PCAP_H to the pcap/pcap.h of libpcap" >&2
  exit 2
fi

# pcap.h with the OpenBSD definition of the time stamp.
mkdir -p "$work/shim/pcap"
awk '/^struct pcap_pkthdr \{$/ {
       print "struct bpf_timeval {\n\tunsigned int tv_sec;\n\tunsigned int tv_usec;\n};"
       inhdr = 1
     }
     inhdr && /struct timeval ts;/ {
       sub(/struct timeval ts;/, "struct bpf_timeval ts;")
       inhdr = 0
     }
     { print }' "$pcap_h" > "$work/shim/pcap/pcap.h"
if ! grep -q 'struct bpf_timeval ts;' "$work/shim/pcap/pcap.h"; then
  echo "could not patch $pcap_h" >&2
  exit 2
fi
echo '#include "pcap/pcap.h"' > "$work/shim/pcap.h"

if [ ! -x "$top/configure" ]; then
  # No -f: it would overwrite the INSTALL file of the source tree.
  (cd "$top" && autoreconf -i)
fi

werror="-Werror=incompatible-pointer-types -Werror=incompatible-function-pointer-types \
-Werror=implicit-function-declaration -Werror=implicit-int -Werror=int-conversion"

fail=0
for layout in default static static-separate; do
  args=""
  if [ "$layout" != default ]; then
    args="--enable-compat-export=$layout"
  fi
  echo "== layout: $layout"
  mkdir "$work/build-$layout"
  # $args and the options of the caller are meant to be split into words.
  if (cd "$work/build-$layout" &&
      "$top/configure" CC="$cc" CPPFLAGS="-I$work/shim" CFLAGS="-g -O1 $werror" $args "$@" > configure.log 2>&1 &&
      make > make.log 2>&1); then
    echo "   ok"
  else
    fail=1
    echo "   FAILED"
    grep -E 'error:' "$work/build-$layout/make.log" | sed 's/^/   /'
  fi
done
exit $fail
