#!/bin/sh
#
# benchmark_export.sh -- deprecated wrapper.
#
# The benchmark is now `tools/softflowd_test_collector.py bench`; the options
# are unchanged.  Nothing in the tree uses this wrapper any more; it only stays
# (moved to tools/deprecated/) for command lines that call it by its new path.
exec python3 "$(dirname "$0")/../softflowd_test_collector.py" bench "$@"
