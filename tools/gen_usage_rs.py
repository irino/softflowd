#!/usr/bin/env python3
"""
gen_usage_rs.py -- make rust/src/usage.txt, the usage text of the C version (options.c, usage()).

  tools/gen_usage_rs.py [--c ./softflowd] [--out rust/src/usage.txt]

The text is what `softflowd -h` writes to standard error.  The program name and the version are
replaced by {prog} and {version}; the Rust version fills them in (rust/src/usage.rs).  The text is
that of the C version of the default configuration: the lines of an optional feature (ntopng) are
not in it, and a C version that is built with the feature writes more lines.
"""

import argparse
import os
import re
import subprocess
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="make the usage text of the Rust version from the C version")
    ap.add_argument("--c", default="./softflowd", help="the C softflowd (default: ./softflowd)")
    ap.add_argument("--out", default=os.path.join("rust", "src", "usage.txt"), help="the file to write")
    args = ap.parse_args()

    r = subprocess.run([args.c, "-h"], capture_output=True, text=True, timeout=10)
    if r.returncode != 0 or not r.stderr.startswith("Usage: "):
        print(f"{args.c} -h did not write a usage text to standard error", file=sys.stderr)
        return 1
    text = r.stderr
    prog = text.split()[1]                      # "Usage: softflowd [options] [bpf_program]"
    text, n1 = re.subn(rf"^Usage: {re.escape(prog)} ", "Usage: {prog} ", text, count=1)
    text, n2 = re.subn(rf"^This is {re.escape(prog)} version \d+\.\d+\.\d+\.", "This is {prog} version {version}.",
                       text, count=1, flags=re.M)
    if n1 != 1 or n2 != 1:
        print("the first two lines of the usage text have an unexpected form", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {args.out}: {len(text.splitlines())} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
