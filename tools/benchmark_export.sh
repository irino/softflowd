#!/bin/sh
#
# benchmark_export.sh -- deprecated wrapper.
#
# The benchmark is now `tools/softflowd_test_collector.py bench`; the options
# are unchanged.  This wrapper is kept so that existing command lines keep working.
exec python3 "$(dirname "$0")/softflowd_test_collector.py" bench "$@"
