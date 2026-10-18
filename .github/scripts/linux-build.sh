#!/bin/sh
# Builds softflowd inside the container of the "linux" job of build.yml
# with every --enable-compat-export variant.  All variants are tried even if
# one of them fails.
#
# Run from the top of the source tree.  Environment:
#   LIBBSD  "with" to build with libbsd, anything else without it

set -u

export DEBIAN_FRONTEND=noninteractive

apt-get update || exit 1
apt-get install -y --no-install-recommends \
  build-essential libpcap-dev autoconf automake libtool pkg-config || exit 1

libbsd_arg=""
if [ "${LIBBSD:-without}" = with ]; then
  apt-get install -y --no-install-recommends libbsd-dev || exit 1
  libbsd_arg="--with-libbsd"
fi

autoreconf -if || exit 1

fail=0
for ce in default static static-separate; do
  echo "::group::compat-export=$ce"
  args=""
  if [ "$ce" != default ]; then
    args="--enable-compat-export=$ce"
  fi
  mkdir "build-$ce"
  # $args and $libbsd_arg are meant to be split into words.
  # shellcheck disable=SC2086
  (cd "build-$ce" && ../configure --enable-gcc-warnings $args $libbsd_arg && make) || fail=1
  echo "::endgroup::"
done
exit $fail
