#!/bin/sh
# Compare the expiry statistics of the stable softflowd and of this tree.
#
# Usage: compare_expiry_stats.sh STABLE_SOFTFLOWD DEV_SOFTFLOWD PCAP...
#
# Every pcap is replayed with a flow table of only 4 flows (-m 4), so that
# nearly every flow is expired by force.  Which flows are chosen depends on
# the order of the expiry events, which the flow sets exported by the compat
# test (tools/softflowd_test_collector.py compat) do not show, because that
# test only sees what is left at the end.  The statistics of both binaries
# must be the same: the number of flows expired and exported, and the flow
# bytes and packets.  The tail of the "Flows exported" line (datagrams and
# send failures) depends on the transport and is left out.
#
# The development binary is run once per flow lookup mode.

stable=$1
dev=$2
shift 2
if [ $# -eq 0 ] || [ ! -x "$stable" ] || [ ! -x "$dev" ]; then
  echo "usage: $0 STABLE_SOFTFLOWD DEV_SOFTFLOWD PCAP..." >&2
  exit 2
fi

stats() {
  bin=$1
  pcap=$2
  shift 2
  "$bin" -r "$pcap" -n 127.0.0.1:9 -v 5 -m 4 "$@" 2>&1 |
    sed -n -e 's/^\(Flows exported: .*records)\) in .*/\1/p' \
      -e '/^Flows expired:/p' \
      -e '/^ *Flow \(bytes\|packets\):/p'
}

status=0
for pcap in "$@"; do
  want=$(stats "$stable" "$pcap")
  if [ -z "$want" ]; then
    echo "FAILED: no statistics from $stable on $pcap" >&2
    exit 1
  fi
  for mode in tree hash-tree; do
    got=$(stats "$dev" "$pcap" --flow-lookup "$mode")
    if [ "$got" = "$want" ]; then
      echo "OK: $pcap (-m 4, --flow-lookup $mode)"
    else
      echo "FAILED: $pcap (-m 4, --flow-lookup $mode): statistics differ" >&2
      printf '%s\n' "$want" >/tmp/expiry_stats.stable.$$
      printf '%s\n' "$got" >/tmp/expiry_stats.dev.$$
      diff -u /tmp/expiry_stats.stable.$$ /tmp/expiry_stats.dev.$$ >&2
      rm -f /tmp/expiry_stats.stable.$$ /tmp/expiry_stats.dev.$$
      status=1
    fi
  done
done
exit $status
