#!/usr/bin/env bash
#
# benchmark_export.sh -- compare softflowd's NetFlow/IPFIX export
# implementations (legacy / default / --enable-unified-export) across
# one or more pcap files and NetFlow/IPFIX versions.
#
# Usage:
#   ./benchmark_export.sh [options] pcap1.pcap [pcap2.pcap ...]
#
# Options:
#   -v VERSIONS   comma-separated NetFlow/IPFIX versions to test
#                 (default: 1,5,9,10)
#   -b BUILDS     comma-separated build variants to compare:
#                 default,legacy,unified (default: default,unified)
#   -w WARMUP     hyperfine --warmup count (default: 3)
#   -m MIN_RUNS   hyperfine --min-runs count (default: 10)
#   -M MAX_RUNS   hyperfine --max-runs count (optional, unset = no cap)
#   -o OUTFILE    combined CSV output path (default: benchmark_results.csv)
#   -p            also run `perf stat` once per combination (needs perf)
#   -s SRCDIR     softflowd source directory (default: .)
#   -j JOBS       parallel `make` jobs when building (default: 2)
#   -k            keep/reuse already-built variant binaries (skip rebuild
#                 if softflowd-<variant> already exists in SRCDIR)
#   -P PORT       destination UDP port used for -n 127.0.0.1:PORT
#                 (default: 2055)
#   -h            show this help
#
# Requires: hyperfine (falls back to a plain `time`-based loop if
# missing), python3 (only used to parse hyperfine's --export-json
# output; skipped in the fallback path). `perf` is optional (-p).
#
# What this does for each (pcap, build variant, version) combination:
#   1. Builds (once per variant, reused across pcaps/versions) a
#      dedicated softflowd-<variant> binary via autoreconf/configure/make.
#   2. Starts a local UDP sink on 127.0.0.1:PORT so packets are
#      actually received and discarded, rather than bouncing ICMP
#      port-unreachable errors back at the sender.
#   3. Runs the binary via hyperfine (which itself performs the
#      requested number of warmup runs -- naturally pulling the pcap
#      into the page cache before the timed runs -- and reports
#      wall/user/system time with min-runs repetitions), or falls back
#      to a manual N-iteration `time` loop if hyperfine is not
#      installed.
#   4. Appends one row per combination to OUTFILE (mean/stddev/median
#      wall time, plus user/system time when hyperfine is used).
#   5. With -p, also runs `perf stat` once per combination and prints
#      instructions/branches/branch-misses alongside the timing.

set -euo pipefail

VERSIONS="1,5,9,10"
BUILDS="default,unified"
WARMUP=3
MIN_RUNS=10
MAX_RUNS=""
OUTFILE="benchmark_results.csv"
RUN_PERF=0
SRCDIR="."
JOBS=2
REUSE_BUILDS=0
PORT=2055

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

while getopts "v:b:w:m:M:o:ps:j:kP:h" opt; do
  case "$opt" in
    v) VERSIONS="$OPTARG" ;;
    b) BUILDS="$OPTARG" ;;
    w) WARMUP="$OPTARG" ;;
    m) MIN_RUNS="$OPTARG" ;;
    M) MAX_RUNS="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    p) RUN_PERF=1 ;;
    s) SRCDIR="$OPTARG" ;;
    j) JOBS="$OPTARG" ;;
    k) REUSE_BUILDS=1 ;;
    P) PORT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 1 ]; then
  echo "error: at least one pcap file is required" >&2
  usage
  exit 1
fi
PCAPS=("$@")
for f in "${PCAPS[@]}"; do
  [ -r "$f" ] || { echo "error: cannot read pcap: $f" >&2; exit 1; }
done

IFS=',' read -r -a VERSION_LIST <<< "$VERSIONS"
IFS=',' read -r -a BUILD_LIST <<< "$BUILDS"

HAVE_HYPERFINE=0; command -v hyperfine >/dev/null 2>&1 && HAVE_HYPERFINE=1
HAVE_PERF=0; command -v perf >/dev/null 2>&1 && HAVE_PERF=1
HAVE_PY3=0; command -v python3 >/dev/null 2>&1 && HAVE_PY3=1

if [ "$RUN_PERF" -eq 1 ] && [ "$HAVE_PERF" -ne 1 ]; then
  echo "warning: -p requested but 'perf' not found; skipping perf stat" >&2
  RUN_PERF=0
fi
if [ "$HAVE_HYPERFINE" -ne 1 ]; then
  echo "note: hyperfine not found; falling back to a plain time(1) loop" >&2
  echo "      (install hyperfine for warmup control, stats and JSON export)" >&2
fi

WORKDIR="$(mktemp -d)"
trap 'cleanup' EXIT

SINK_PID=""
start_sink () {
  # Local UDP sink so export packets are actually received, instead of
  # eliciting ICMP port-unreachable back at softflowd for every packet.
  if [ "$HAVE_PY3" -eq 1 ]; then
    python3 - "$PORT" >"$WORKDIR/sink.log" 2>&1 <<'PYEOF' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    s.recvfrom(65536)
PYEOF
    SINK_PID=$!
  elif command -v socat >/dev/null 2>&1; then
    socat -u UDP-RECVFROM:"$PORT",fork,reuseaddr /dev/null >"$WORKDIR/sink.log" 2>&1 &
    SINK_PID=$!
  elif command -v nc >/dev/null 2>&1; then
    nc -u -l -k "$PORT" >/dev/null 2>&1 &
    SINK_PID=$!
  else
    echo "warning: no python3/socat/nc found for a UDP sink;" >&2
    echo "         softflowd will see ICMP port-unreachable for every packet." >&2
    SINK_PID=""
  fi
  [ -n "$SINK_PID" ] && sleep 0.3
}

stop_sink () {
  if [ -n "$SINK_PID" ] && kill -0 "$SINK_PID" 2>/dev/null; then
    kill "$SINK_PID" 2>/dev/null || true
    wait "$SINK_PID" 2>/dev/null || true
  fi
  SINK_PID=""
}

cleanup () { stop_sink; rm -rf "$WORKDIR"; }

configure_flags_for () {
  case "$1" in
    default) echo "" ;;
    legacy)  echo "--enable-legacy" ;;
    unified) echo "--enable-unified-export" ;;
    *) echo "error: unknown build variant '$1' (expected default|legacy|unified)" >&2
       exit 1 ;;
  esac
}

build_variant () {
  local variant="$1" bin="$SRCDIR/softflowd-$1"
  if [ "$REUSE_BUILDS" -eq 1 ] && [ -x "$bin" ]; then
    echo "== reusing existing $bin (-k given) ==" >&2
    return
  fi
  echo "== building '$variant' (configure $(configure_flags_for "$variant")) ==" >&2
  ( cd "$SRCDIR" \
    && autoreconf -fi >/dev/null 2>&1 \
    && ./configure $(configure_flags_for "$variant") >/dev/null 2>&1 \
    && make -j"$JOBS" >/dev/null 2>&1 )
  cp "$SRCDIR/softflowd" "$bin"
}

echo "== building requested variants: ${BUILD_LIST[*]} ==" >&2
for variant in "${BUILD_LIST[@]}"; do
  build_variant "$variant"
done

echo "pcap,build,version,mean_s,stddev_s,median_s,user_s,system_s,runs,method" > "$OUTFILE"

warm_pagecache () { cat "$1" > /dev/null 2>&1 || true; }

run_hyperfine_case () {
  local pcap="$1" variant="$2" version="$3" bin="$SRCDIR/softflowd-$variant"
  local json="$WORKDIR/hf.json"
  local extra=()
  [ -n "$MAX_RUNS" ] && extra+=(--max-runs "$MAX_RUNS")

  hyperfine \
    --warmup "$WARMUP" \
    --min-runs "$MIN_RUNS" \
    "${extra[@]}" \
    --export-json "$json" \
    --command-name "$variant/v$version/$(basename "$pcap")" \
    "$bin -r $pcap -n 127.0.0.1:$PORT -v $version" \
    1>&2

  if [ "$HAVE_PY3" -eq 1 ]; then
    python3 - "$json" "$pcap" "$variant" "$version" <<'PYEOF' >> "$OUTFILE"
import json, sys, csv
path, pcap, variant, version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path) as f:
    d = json.load(f)
r = d["results"][0]
w = csv.writer(sys.stdout, lineterminator="\n")
w.writerow([pcap, variant, version,
            f'{r["mean"]:.6f}', f'{r["stddev"]:.6f}', f'{r["median"]:.6f}',
            f'{r.get("user", 0):.6f}', f'{r.get("system", 0):.6f}',
            len(r["times"]), "hyperfine"])
PYEOF
  else
    echo "$pcap,$variant,$version,,,,,,,hyperfine(no-python3-for-csv)" >> "$OUTFILE"
  fi
}

run_fallback_case () {
  local pcap="$1" variant="$2" version="$3" bin="$SRCDIR/softflowd-$variant"
  local n="$MIN_RUNS" times=()
  echo "== $variant / v$version / $(basename "$pcap"): $n runs (plain time loop) ==" >&2
  for ((i = 0; i < n; i++)); do
    local t0 t1
    t0=$(date +%s.%N)
    "$bin" -r "$pcap" -n "127.0.0.1:$PORT" -v "$version" >/dev/null 2>&1
    t1=$(date +%s.%N)
    times+=("$(echo "$t1 - $t0" | bc)")
  done
  local IFS=$'\n'
  local sorted=($(sort -n <<< "${times[*]}"))
  unset IFS
  local sum=0
  for t in "${times[@]}"; do sum=$(echo "$sum + $t" | bc); done
  local mean; mean=$(echo "scale=6; $sum / $n" | bc)
  local median="${sorted[$((n / 2))]}"
  echo "$pcap,$variant,$version,$mean,,$median,,,$n,time-loop" >> "$OUTFILE"
}

start_sink

for pcap in "${PCAPS[@]}"; do
  echo "== warming page cache for $pcap ==" >&2
  warm_pagecache "$pcap"
  for variant in "${BUILD_LIST[@]}"; do
    for version in "${VERSION_LIST[@]}"; do
      if [ "$HAVE_HYPERFINE" -eq 1 ]; then
        run_hyperfine_case "$pcap" "$variant" "$version"
      else
        run_fallback_case "$pcap" "$variant" "$version"
      fi
      if [ "$RUN_PERF" -eq 1 ]; then
        echo "== perf stat: $variant / v$version / $(basename "$pcap") ==" >&2
        perf stat -r 5 \
          -e instructions,branches,branch-misses,cycles \
          "$SRCDIR/softflowd-$variant" -r "$pcap" -n "127.0.0.1:$PORT" -v "$version" \
          >/dev/null 2>>"$OUTFILE.perf.log" || true
      fi
    done
  done
done

stop_sink

echo "== done. Results: $OUTFILE ==" >&2
[ "$RUN_PERF" -eq 1 ] && echo "== perf stat details: $OUTFILE.perf.log ==" >&2

if [ "$HAVE_PY3" -eq 1 ]; then
  python3 - "$OUTFILE" <<'PYEOF'
import csv, sys
from collections import defaultdict
rows = list(csv.DictReader(open(sys.argv[1])))
if not rows:
    sys.exit(0)
print()
print(f'{"pcap":<24}{"build":<10}{"ver":<5}{"mean(s)":>10}{"stddev":>10}{"user(s)":>10}{"sys(s)":>10}')
for r in rows:
    try:
        mean = f'{float(r["mean_s"]):.4f}'
        stddev = f'{float(r["stddev_s"]):.4f}' if r["stddev_s"] else "-"
        user = f'{float(r["user_s"]):.4f}' if r["user_s"] else "-"
        sysv = f'{float(r["system_s"]):.4f}' if r["system_s"] else "-"
    except ValueError:
        mean = stddev = user = sysv = "-"
    print(f'{r["pcap"][:23]:<24}{r["build"]:<10}{r["version"]:<5}{mean:>10}{stddev:>10}{user:>10}{sysv:>10}')
PYEOF
fi
