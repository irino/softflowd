#!/bin/sh
# Builds the RPM packages inside the Fedora container of release.yml.
# Run from the directory that holds the softflowd-*.tar.gz of the "dist" job;
# the packages are copied there.

set -eu

dnf install -y rpm-build rpmdevtools libpcap-devel \
  autoconf automake libtool gcc make

rpmdev-setuptree
tar xzf softflowd-*.tar.gz --wildcards '*/softflowd.spec' \
  '*/softflowd.init' '*/softflowd.sysconfig' --strip-components=1
cp softflowd-*.tar.gz ~/rpmbuild/SOURCES/
cp softflowd.init softflowd.sysconfig ~/rpmbuild/SOURCES/
cp softflowd.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/softflowd.spec
find ~/rpmbuild/RPMS ~/rpmbuild/SRPMS -name '*.rpm' -exec cp {} . \;
