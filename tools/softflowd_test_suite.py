#!/usr/bin/env python3
"""
softflowd_test_suite.py -- test, benchmark and collector tools for softflowd.

Standard library only.  One entry point for the three tools of this directory
(formerly softflowd_test_collector.py):

  tools/softflowd_test_suite.py compat  [options] [PCAP...]       backward compatibility and variants (default)
  tools/softflowd_test_suite.py test    [options] [PCAP...]       the same as compat
  tools/softflowd_test_suite.py bench   [options] PCAP...         export benchmark
  tools/softflowd_test_suite.py collect [-p PORT] [-b ADDR] [-6]  flow collector

Each subcommand is also a script of its own, which takes the same options:

  compat / test  tools/softflowd_test.py
  bench          tools/softflowd_bench.py
  collect        tools/softflowd_collector.py

Options after the subcommand belong to that subcommand; `-h` after a
subcommand shows its help.  Without a subcommand the arguments go to compat,
so the former run_compat_suite.py usage is `softflowd_test_suite.py [options]`.
See tools/README.md for the files and their dependencies.
"""

import os
import sys

from softflowd_bench import bench_main
from softflowd_collector import collect_main
from softflowd_test import compat_main

SUBCOMMANDS = {
    "compat": compat_main,
    "test": compat_main,  # alias of compat
    "bench": bench_main,
    "collect": collect_main,
}
DEFAULT_SUBCOMMAND = "compat"


def main() -> int:
    argv = sys.argv
    if len(argv) >= 2 and argv[1] in SUBCOMMANDS:
        name, rest = argv[1], argv[2:]
    elif len(argv) == 1 or argv[1].startswith("-"):
        name, rest = DEFAULT_SUBCOMMAND, argv[1:]
    else:
        print(f"unknown subcommand '{argv[1]}' "
              f"(expected: {', '.join(SUBCOMMANDS)})", file=sys.stderr)
        return 2
    sys.argv = [f"{os.path.basename(argv[0])} {name}"] + rest
    result = SUBCOMMANDS[name]()
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    sys.exit(main())
