#!/usr/bin/env python3
"""
softflowd_test_gate.py -- quality gate of the Rust version (and any --a/--b pair).

Standard library only.  Runs `softflowd_test.py --strict` (or reads a saved log) and sorts
every difference it reports:

  accepted  a difference that is kept on purpose (gate_expected.json, status "accepted")
  open      a known difference that is tracked in rust/doc/DIFFERENCES-FROM-C.*.md
  UNEXPECTED anything else: the gate fails
  STALE     an entry of gate_expected.json that no line matched: the difference is fixed,
            so the patch that fixed it has to delete the entry (the gate fails)

The last line is `GATE: PASS` or `GATE: FAIL ...`, and --report writes the same as JSON,
so that a person or a model can decide with one line.

Usage:
  tools/softflowd_test_suite.py gate [GATE OPTIONS] [-- COMPAT OPTIONS]
  tools/softflowd_test_gate.py       [GATE OPTIONS] [-- COMPAT OPTIONS]

Gate options:
  --expected FILE   accepted/open differences (default: gate_expected.json next to this script)
  --from-log FILE   read the output of an earlier run instead of running the suite
  --report FILE     write a JSON report
  --rust-dir DIR    also run cargo fmt --check, clippy -D warnings and cargo test in DIR
  --docs FILE       the differences document that the entries are checked against (default:
                    rust/doc/DIFFERENCES-FROM-C.en.md; "none" skips the check)
  --allow-stale     a stale entry is a warning, not a failure

Compat options are passed to softflowd_test.py; --strict is added.  Example (Rust against C):
  tools/softflowd_test_suite.py gate --rust-dir rust -- --a ./softflowd --b rust/target/release/rsoftflowd \\
      --ctl-a ./softflowctl --ctl-b rust/target/release/rsoftflowctl --skip-build --skip-cpp --skip-rust \\
      --skip-static --skip-direct --skip-psamp --collector python --no-benchmark --no-gauge-clock
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A line that reports a difference or a failure
FINDING = re.compile(r"DIFFER|differs|FAILED|\bFAIL\b")


def split_args(argv):
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def parse_gate_args(argv):
    opts = {"expected": os.path.join(HERE, "gate_expected.json"), "from_log": None,
            "report": None, "rust_dir": None, "allow_stale": False,
            "docs": os.path.join(HERE, "..", "rust", "doc", "DIFFERENCES-FROM-C.en.md")}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--allow-stale":
            opts["allow_stale"] = True
        elif a in ("--expected", "--from-log", "--report", "--rust-dir", "--docs") and i + 1 < len(argv):
            opts[a[2:].replace("-", "_")] = argv[i + 1]
            i += 1
        else:
            raise SystemExit(f"gate: unknown option {a}")
        i += 1
    return opts


def run_compat(compat_args):
    cmd = [sys.executable, os.path.join(HERE, "softflowd_test.py"), "--strict"] + compat_args
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return ANSI.sub("", p.stdout)


def run_rust_checks(rust_dir):
    results = []
    for name, cmd in (("cargo fmt --check", ["cargo", "fmt", "--check"]),
                      ("cargo clippy -D warnings", ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"]),
                      ("cargo test", ["cargo", "test"])):
        try:
            p = subprocess.run(cmd, cwd=rust_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            results.append({"check": name, "ok": p.returncode == 0})
        except FileNotFoundError:
            results.append({"check": name, "ok": False, "note": "cargo not found"})
    return results


def check_docs(entries, path):
    """An entry of the gate needs a row of the document whose status is open or accepted:
    an entry for a difference that the document calls fixed is a mistake, and so is a missing row."""
    status = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            c = [x.strip() for x in line.split("|")]
            if len(c) > 5 and re.fullmatch(r"D\d+", c[1]):
                status[c[1]] = c[4]
    problems = []
    for e in entries:
        if e["id"] == "SUM":
            continue
        s = status.get(e["id"])
        if s is None:
            problems.append(f"{e['id']}: no row in {os.path.basename(path)}")
        elif s not in ("open", "accepted", "未解消", "許容"):
            problems.append(f"{e['id']}: the document says '{s}' but the gate still accepts it")
    return sorted(set(problems))


def classify(text, entries):
    hits = {i: 0 for i in range(len(entries))}
    rows = []
    for raw in text.splitlines():
        line = raw.strip()
        if not FINDING.search(line):
            continue
        for i, e in enumerate(entries):
            if re.search(e["pattern"], line):
                hits[i] += 1
                rows.append((e["status"], e["id"], line))
                break
        else:
            rows.append(("UNEXPECTED", "-", line))
    stale = [entries[i] for i, n in hits.items() if n == 0]
    return rows, stale


def gate_main():
    gate_argv, compat_argv = split_args(sys.argv[1:])
    opts = parse_gate_args(gate_argv)
    with open(opts["expected"], encoding="utf-8") as f:
        entries = json.load(f)["entries"]
    if opts["from_log"]:
        with open(opts["from_log"], encoding="utf-8") as f:
            text = ANSI.sub("", f.read())
    else:
        text = run_compat(compat_argv)
    rows, stale = classify(text, entries)
    rust = run_rust_checks(opts["rust_dir"]) if opts["rust_dir"] else []
    doc_problems = [] if opts["docs"] == "none" else check_docs(entries, opts["docs"])
    for d in doc_problems:
        print(f"DOCS        {d}")

    counts = {k: sum(1 for r in rows if r[0] == k) for k in ("accepted", "open", "UNEXPECTED")}
    for status, did, line in rows:
        if status == "UNEXPECTED":
            print(f"UNEXPECTED  {line[:200]}")
    for e in stale:
        print(f"STALE       {e['id']} {e['pattern']}  -> the difference is fixed: delete this entry")
    for r in rust:
        print(f"{'ok  ' if r['ok'] else 'FAIL'}        {r['check']}")
    reasons = []
    if counts["UNEXPECTED"]:
        reasons.append(f"unexpected={counts['UNEXPECTED']}")
    if stale and not opts["allow_stale"]:
        reasons.append(f"stale={len(stale)}")
    if doc_problems:
        reasons.append(f"docs={len(doc_problems)}")
    bad_rust = [r["check"] for r in rust if not r["ok"]]
    if bad_rust:
        reasons.append("rust=" + ",".join(bad_rust))
    if not re.search(r"MATCHED|PASSED", text):
        reasons.append("no result lines (did the suite run?)")
    ok = not reasons
    summary = (f"GATE: {'PASS' if ok else 'FAIL'} unexpected={counts['UNEXPECTED']} "
               f"open={counts['open']} accepted={counts['accepted']} stale={len(stale)}"
               + ("" if ok else "  (" + "; ".join(reasons) + ")"))
    print(summary)
    if opts["report"]:
        with open(opts["report"], "w", encoding="utf-8") as f:
            json.dump({"pass": ok, "counts": counts, "stale": stale, "rust": rust, "docs": doc_problems,
                       "findings": [{"status": s, "id": i, "line": l} for s, i, l in rows]},
                      f, indent=2, ensure_ascii=False)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(gate_main())
