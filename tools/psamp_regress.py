#!/usr/bin/env python3
"""PSAMP regression test for softflowd (send_psamp() and recv_psamp() in psamp.c).

usage:
  tools/psamp_regress.py NEW_BUILD_DIR                 check the behavior of one build
  tools/psamp_regress.py BASE_BUILD_DIR NEW_BUILD_DIR  compare two builds, then check NEW
  tools/psamp_regress.py -h                            full description

A build directory is the directory that holds the built softflowd and softflowctl
(the top directory of an in-tree build, or the directory where an out-of-tree
./configure was run).  Only the Python 3 standard library is used; no nfdump and
no root privileges are needed.  All traffic stays on 127.0.0.1.
"""
import argparse
import os
import struct
import sys
import tempfile
import time

DESCRIPTION = __doc__

EPILOG = """\
What is tested
  compare (two build directories)
    send       softflowd -r PCAP -v psamp: the data messages (the template
               messages and the IPFIX message header are left out, so that the
               result does not depend on the template interval, the sequence
               number and the export time) must be byte-identical.
    roundtrip  sender (-v psamp) -> receiver (-R) -> collector.  The receiver
               exports NetFlow v5, v9 and IPFIX; the flows decoded from them must
               be identical (the wall-clock columns ts and te are ignored).
               A short datagram wakes the receiver of a build that still blocks
               in recv(); that receiver may also crash at the exit, which is
               ignored for BASE.
  check (NEW build directory only; what the build must do)
    template   the template message comes first and again every 16 data
               messages (IPFIX_DEFAULT_TEMPLATE_INTERVAL).
    sequence   the sequence number of a message is the number of the data
               records sent before it (RFC 7011 section 3.1); the first one is 0.
    time       the export time is the current time, or the capture time of the
               packet with -a.
    receiver   the receiver exports the flows and exits without a datagram that
               wakes it, answers softflowctl statistics, and survives a runt
               datagram and a frame section shorter than its stated length.

Tools used (all in the same repository)
  softflowd, softflowctl   from the build directories; softflowd runs with -d (no
                           daemon), so run it as a normal user.
  tools/softflowd_test_collector.py
                           psamp_send(), psamp_roundtrip() and psamp_compare() run
                           the daemons and compare them: the compat command runs
                           the same comparison as its step 4 for the C development
                           pairs.  datagrams_to_csv() decodes the v5/v9/IPFIX
                           datagrams of the receiver.
  tools/gen_ci_smoke_pcap.py
                           makes the IPv4 and IPv6 sample pcaps; the first 50
                           packets are used, because more datagrams can overflow the
                           UDP receive buffer of the receiver and make the result vary.
  Another pcap made here has packets of 60..1514 bytes, around the largest
  frame section (1390 bytes) a PSAMP packet can carry.

Examples
  # in-tree build of the working tree; BASE is a build of origin/master
  git worktree add ../base origin/master
  (cd ../base && autoreconf -fi && ./configure && make)
  autoreconf -fi && ./configure && make
  tools/psamp_regress.py ../base .

  # another configure variant, in a separate directory (out-of-tree)
  mkdir -p /tmp/b/direct && (cd /tmp/b/direct && $OLDPWD/configure --enable-direct-copies && make)
  tools/psamp_regress.py ../base /tmp/b/direct

Exit status: 0 if every test passed, 1 if one failed, 2 on a usage error.
Run it before a change to psamp.c / psamp.h / the PSAMP part of softflowd.c, and
again after, with BASE built from the code before the change.  A change that is
meant to alter the output (a new template interval, for instance) makes the
check part fail until the check is changed too, which is the point of it.
"""

# IPFIX_DEFAULT_TEMPLATE_INTERVAL in ipfix.h.
TEMPLATE_INTERVAL = 16

_results = {"failed": 0}


def report(ok, text):
    print("%-4s %s" % ("OK" if ok else "FAIL", text))
    if not ok:
        _results["failed"] += 1
    return ok


def check(new, new_ctl, pcaps, c):
    """What the build must do; c is the softflowd_test_collector module."""
    print('== check: NEW=%s' % new)
    # template and sequence number
    m = c.psamp_messages(c.psamp_send(new, pcaps['v4s']))
    kinds = ''.join(k for k, _, _, _ in m)
    expect = ''.join('T' + 'D' * TEMPLATE_INTERVAL for _ in range(len(kinds)))[:len(kinds)]
    report(bool(m) and kinds == expect,
           'template   first, then every %d data messages (%d messages, %d templates)'
           % (TEMPLATE_INTERVAL, len(m), kinds.count('T')))
    records = 0
    bad = None
    for i, (k, seq, _, _) in enumerate(m):
        if seq != records and bad is None:
            bad = (i, seq, records)
        records += k == 'D'
    report(bool(m) and bad is None, 'sequence   number of the data records before the message'
           + ('' if bad is None else ' (message %d has %d, expected %d)' % bad))
    # export time
    now = time.time()
    t = [et for k, _, et, _ in c.psamp_messages(c.psamp_send(new, pcaps['sizes'])) if k == 'D']
    report(bool(t) and all(abs(x - now) < 60 for x in t), 'time       current time without -a (%s)' % t[:2])
    t = [et for k, _, et, _ in c.psamp_messages(c.psamp_send(new, pcaps['sizes'], ['-a'])) if k == 'D']
    report(bool(t) and t == [1000 + i for i in range(len(t))], 'time       capture time with -a (%s)' % t[:3])
    # receiver: no wake-up datagram, statistics, exit
    out, stat, rc, hung = c.psamp_roundtrip(new, new_ctl, pcaps['v4s'], 5, wake=False, stats=True)
    report(bool(c.psamp_flows(out)),
           'receiver   exports the flows without a datagram that wakes it (%d datagrams)' % len(out))
    report(not hung and rc is not None and rc >= 0,
           'receiver   exits after shutdown (status %s%s)' % (rc, ', hung' if hung else ''))
    report(stat is not None and 'Packets processed' in stat, 'receiver   answers statistics')
    # receiver: bad input must not stop it
    eth = bytes.fromhex('00112233445566778899aabb0800')
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28, 1, 0, 64, 17, 0, b'\x0a\0\0\x01', b'\x0a\0\0\x02')
    bad_input = (b'x', c.psamp_datagram(b'\0' * 10, c.PSAMP_MAX_FRAME),
                 c.psamp_datagram(eth + ip, c.PSAMP_MAX_FRAME))
    out, _, rc, hung = c.psamp_roundtrip(new, new_ctl, pcaps['v4s'], 5, wake=False, inject=bad_input)
    report(not hung and rc is not None and rc >= 0 and bool(c.psamp_flows(out)),
           'receiver   survives a runt datagram and short frame sections (status %s)' % rc)


def main():
    ap = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 usage='%(prog)s [--tools DIR] [BASE_BUILD_DIR] NEW_BUILD_DIR')
    ap.add_argument('build', nargs='+', metavar='BUILD_DIR',
                    help='NEW_BUILD_DIR, or BASE_BUILD_DIR NEW_BUILD_DIR')
    ap.add_argument('--tools', default=os.path.dirname(os.path.abspath(__file__)),
                    help='directory of gen_ci_smoke_pcap.py and softflowd_test_collector.py '
                         '(default: the directory of this script)')
    args = ap.parse_args()
    if len(args.build) > 2:
        ap.error('at most two build directories')
    for b in args.build:
        for exe in ('softflowd', 'softflowctl'):
            if not os.access(os.path.join(b, exe), os.X_OK):
                ap.error('%s/%s not found; build softflowd first' % (b, exe))
    sys.path.insert(0, args.tools)
    import softflowd_test_collector as c

    pcaps = c.psamp_make_pcaps(tempfile.mkdtemp(prefix='psamp_regress_'))
    daemon = lambda b: os.path.join(b, 'softflowd')
    ctl = lambda b: os.path.join(b, 'softflowctl')
    if len(args.build) == 2:
        base, new = args.build
        print('== compare: BASE=%s NEW=%s' % (base, new))
        c.psamp_compare(daemon(base), daemon(new), ctl(base), ctl(new), pcaps, report)
    new = args.build[-1]
    check(daemon(new), ctl(new), pcaps, c)
    print('failed: %d' % _results['failed'])
    return 1 if _results['failed'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
