#!/usr/bin/env bash
#
# benchmark_export.sh -- compare softflowd's NetFlow/IPFIX export
# implementations (static-separate / static / dynamic, see --enable-compat-export)
# across one or more pcap files and NetFlow/IPFIX versions.
#
# Usage:
#   ./benchmark_export.sh [options] pcap1.pcap [pcap2.pcap ...]
#
# Options:
#   -v VERSIONS   comma-separated NetFlow/IPFIX versions to test
#                 (default: 1,5,9,10)
#   -b BUILDS     comma-separated build variants to compare:
#                 static-separate,static,dynamic (default: static,dynamic);
#                 see --enable-compat-export in ./configure --help
#   -w WARMUP     hyperfine --warmup count (default: 3)
#   -m MIN_RUNS   hyperfine --min-runs count (default: 10)
#   -M MAX_RUNS   hyperfine --max-runs count (optional, unset = no cap)
#   -o OUTFILE    combined CSV output path (default: benchmark_results.csv)
#   -p            also run `perf stat` once per combination (needs perf)
#   -C            also run callgrind once per combination (needs valgrind
#                 and callgrind_annotate); writes instruction counts to
#                 OUTFILE.callgrind.csv and per-function profiles to
#                 OUTFILE.callgrind/. Callgrind is ~50x slower than a
#                 native run, so use a small pcap with this option.
#   -T TOPN       number of functions shown per callgrind profile
#                 (default: 15)
#   -g            also run once per combination with softflowd's own -g
#                 flag and record its "cpu clocks" (total) and
#                 "cpu clocks (export)" (time inside the export call)
#                 counters in OUTFILE.gauge.csv
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
# output; skipped in the fallback path). `perf` is optional (-p),
# valgrind/callgrind_annotate are optional (-C). -g relies on softflowd's
# own -g flag, so it needs no extra tool.
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
#   6. With -C, also runs callgrind once per combination and records the
#      total instruction count (Ir) and the self Ir spent in the exporter
#      sources (ipfix.c, netflow*.c, psamp.c), then prints the Ir ratio of
#      each build relative to the first build in -b.
#   7. With -g, also runs the binary once per combination with -g and
#      records the "cpu clocks" and "cpu clocks (export)" lines it
#      prints in OUTFILE.gauge.csv.

set -euo pipefail

VERSIONS="1,5,9,10"
BUILDS="static,dynamic"
WARMUP=3
MIN_RUNS=10
MAX_RUNS=""
OUTFILE="benchmark_results.csv"
RUN_PERF=0
RUN_CALLGRIND=0
TOPN=15
RUN_GAUGE=0
SRCDIR="."
JOBS=2
REUSE_BUILDS=0
PORT=2055

usage() { sed -n '2,69p' "$0" | sed 's/^# \{0,1\}//'; }

while getopts "v:b:w:m:M:o:pCT:gs:j:kP:h" opt; do
  case "$opt" in
    v) VERSIONS="$OPTARG" ;;
    b) BUILDS="$OPTARG" ;;
    w) WARMUP="$OPTARG" ;;
    m) MIN_RUNS="$OPTARG" ;;
    M) MAX_RUNS="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    p) RUN_PERF=1 ;;
    C) RUN_CALLGRIND=1 ;;
    T) TOPN="$OPTARG" ;;
    g) RUN_GAUGE=1 ;;
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
if [ "$RUN_CALLGRIND" -eq 1 ]; then
  if ! command -v valgrind >/dev/null 2>&1 \
     || ! command -v callgrind_annotate >/dev/null 2>&1; then
    echo "warning: -C requested but valgrind/callgrind_annotate not found; skipping callgrind" >&2
    RUN_CALLGRIND=0
  fi
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
    dynamic) echo "" ;;
    static|static-separate) echo "--enable-compat-export=$1" ;;
    *) echo "error: unknown build variant '$1' (expected static-separate|static|dynamic)" >&2
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

CG_CSV="$OUTFILE.callgrind.csv"
CG_DIR="$OUTFILE.callgrind"
if [ "$RUN_CALLGRIND" -eq 1 ]; then
  mkdir -p "$CG_DIR"
  echo "pcap,build,version,total_ir,exporter_self_ir" > "$CG_CSV"
fi

GAUGE_CSV="$OUTFILE.gauge.csv"
if [ "$RUN_GAUGE" -eq 1 ]; then
  echo "pcap,build,version,cpu_clocks_total,cpu_clocks_export,export_calls" > "$GAUGE_CSV"
fi

# Run once with softflowd's own -g and record the "cpu clocks" /
# "cpu clocks (export)" lines it prints on exit (see softflowd.c).
run_gauge_case () {
  local pcap="$1" variant="$2" version="$3" bin="$SRCDIR/softflowd-$variant"
  local log="$WORKDIR/gauge.log"
  "$bin" -g -r "$pcap" -n "127.0.0.1:$PORT" -v "$version" >/dev/null 2>"$log" || true
  local total export calls
  total=$(sed -n 's/^cpu clocks: \([0-9]*\)/\1/p' "$log" | tail -1)
  export=$(sed -n 's/^cpu clocks (export): \([0-9]*\).*/\1/p' "$log" | tail -1)
  calls=$(sed -n 's/^cpu clocks (export): [0-9]* (\([0-9]*\) calls)/\1/p' "$log" | tail -1)
  if [ -z "$total" ]; then
    echo "warning: no 'cpu clocks' output for $variant/v$version/$(basename "$pcap") (see $log)" >&2
    return
  fi
  # export is empty (n/a) for threaded export (-M); leave the CSV field blank.
  echo "$pcap,$variant,$version,$total,${export:-},${calls:-}" >> "$GAUGE_CSV"
}

# Run callgrind once for one (pcap, variant, version) combination.
# Records total Ir and the self Ir of exporter sources (ipfix.c,
# netflow*.c, psamp.c) in CG_CSV, and keeps the annotated profile.
run_callgrind_case () {
  local pcap="$1" variant="$2" version="$3" bin="$SRCDIR/softflowd-$variant"
  local tag; tag="$(basename "$pcap" .pcap)_${variant}_v${version}"
  local out="$CG_DIR/$tag.out" txt="$CG_DIR/$tag.txt"
  echo "== callgrind: $variant / v$version / $(basename "$pcap") ==" >&2
  valgrind --tool=callgrind --callgrind-out-file="$out" \
    "$bin" -r "$pcap" -n "127.0.0.1:$PORT" -v "$version" \
    >/dev/null 2>"$CG_DIR/$tag.log" || true
  if [ ! -s "$out" ]; then
    echo "warning: no callgrind output for $tag (see $CG_DIR/$tag.log)" >&2
    return
  fi
  callgrind_annotate --auto=no --threshold=100 "$out" > "$txt" 2>/dev/null || true
  local total; total=$(awk '/^totals:/ {print $2; exit}' "$out")
  # Self Ir per function line: "1,234 (12.3%)  path/file.c:func [obj]".
  # Only the file:function table is summed (auto-annotation is off).
  local exp; exp=$(awk '
    /file:function/ { f = 1; next }
    f && /%\)/ && $0 ~ /(ipfix|netflow[0-9]+|psamp)\.c:/ {
      gsub(",", "", $1); sum += $1
    }
    END { printf "%d", sum }' "$txt")
  echo "$pcap,$variant,$version,$total,$exp" >> "$CG_CSV"
  echo "-- top $TOPN functions ($tag) --" >&2
  awk -v n="$TOPN" '/file:function/ {f=1; next} f && /%\)/ {print; c++} c>=n {exit}' "$txt" >&2
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
      if [ "$RUN_CALLGRIND" -eq 1 ]; then
        run_callgrind_case "$pcap" "$variant" "$version"
      fi
      if [ "$RUN_GAUGE" -eq 1 ]; then
        run_gauge_case "$pcap" "$variant" "$version"
      fi
    done
  done
done

stop_sink

echo "== done. Results: $OUTFILE ==" >&2
if [ "$RUN_CALLGRIND" -eq 1 ]; then
  echo "== callgrind results: $CG_CSV (profiles in $CG_DIR/) ==" >&2
fi
if [ "$RUN_GAUGE" -eq 1 ]; then
  echo "== gauge (-g) results: $GAUGE_CSV ==" >&2
fi
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

if [ "$RUN_CALLGRIND" -eq 1 ] && [ "$HAVE_PY3" -eq 1 ]; then
  python3 - "$CG_CSV" "${BUILD_LIST[0]}" <<'PYEOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
base = sys.argv[2]
if not rows:
    sys.exit(0)
ref = {(r["pcap"], r["version"]): r for r in rows if r["build"] == base}
print()
print(f"callgrind Ir (ratio vs '{base}')")
print(f'{"pcap":<24}{"build":<10}{"ver":<5}{"total Ir":>16}{"ratio":>8}{"exporter Ir":>16}{"ratio":>8}')
for r in rows:
    b = ref.get((r["pcap"], r["version"]))
    def ratio(k):
        try:
            return f'{float(r[k]) / float(b[k]):.3f}x'
        except (TypeError, ValueError, ZeroDivisionError):
            return "-"
    print(f'{r["pcap"][:23]:<24}{r["build"]:<10}{r["version"]:<5}'
          f'{int(r["total_ir"]):>16,}{ratio("total_ir"):>8}'
          f'{int(r["exporter_self_ir"]):>16,}{ratio("exporter_self_ir"):>8}')
PYEOF
fi

if [ "$RUN_GAUGE" -eq 1 ] && [ "$HAVE_PY3" -eq 1 ]; then
  python3 - "$GAUGE_CSV" "${BUILD_LIST[0]}" <<'PYEOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1])))
base = sys.argv[2]
if not rows:
    sys.exit(0)
ref = {(r["pcap"], r["version"]): r for r in rows if r["build"] == base}
print()
print(f"-g cpu clocks (ratio vs '{base}')")
print(f'{"pcap":<24}{"build":<10}{"ver":<5}{"total":>14}{"ratio":>8}{"export":>14}{"ratio":>8}{"calls":>8}')
for r in rows:
    b = ref.get((r["pcap"], r["version"]))
    def ratio(k):
        try:
            return f'{float(r[k]) / float(b[k]):.3f}x'
        except (TypeError, ValueError, ZeroDivisionError):
            return "-"
    exp = r["cpu_clocks_export"] or "n/a"
    print(f'{r["pcap"][:23]:<24}{r["build"]:<10}{r["version"]:<5}'
          f'{int(r["cpu_clocks_total"]):>14,}{ratio("cpu_clocks_total"):>8}'
          f'{exp:>14}{ratio("cpu_clocks_export") if r["cpu_clocks_export"] else "-":>8}'
          f'{r["export_calls"] or "-":>8}')
PYEOF
fi
