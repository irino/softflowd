#!/usr/bin/env python3
"""PSAMP regression test: compare two softflowd builds (e.g. origin/master vs. a patched tree).

usage: psamp_regress.py BASE_BUILD_DIR NEW_BUILD_DIR [--tools DIR]

  BASE_BUILD_DIR / NEW_BUILD_DIR   build directories holding softflowd and softflowctl
  --tools DIR                      repository tools/ directory (gen_ci_smoke_pcap.py,
                                   softflowd_test_collector.py); default: ../tools of this file

1. send   : softflowd -r PCAP -v psamp  -> the PSAMP datagrams must be byte-identical.
2. roundtrip: sender (-v psamp) -> receiver (-R) -> collector. The flows decoded from the
   receiver's v5/v9/IPFIX export must be identical (wall-clock columns ts/te are ignored).
Only the standard library is used. Run it for every configure variant you care about
(default, --enable-direct-copies, ...).
"""
import os, signal, socket, struct, subprocess, sys, tempfile, time

def pcap_record(ts, data):
    return struct.pack('<IIII', ts, 0, len(data), len(data)) + data

def head(src, n):
    d = open(src, 'rb').read(); out = bytearray(d[:24]); off = 24
    for _ in range(n):
        if off + 16 > len(d): break
        l = struct.unpack('<I', d[off + 8:off + 12])[0]; out += d[off:off + 16 + l]; off += 16 + l
    return bytes(out)

def sized_pcap(sizes):
    eth = bytes.fromhex('00112233445566778899aabb0800')
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, n in enumerate(sizes):
        pl = b'U' * (n - 42)
        udp = struct.pack('>HHHH', 1234, 53, 8 + len(pl), 0) + pl
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton('10.0.0.1'), socket.inet_aton('10.0.0.2'))
        out += pcap_record(1000 + i, eth + ip + udp)
    return out

def collect(sock):
    out = []
    try:
        while True: out.append(sock.recv(65535))
    except socket.timeout: pass
    return out

def udp_listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', port)); s.settimeout(0.3); return s

def send_run(build, pcap, port):
    s = udp_listener(port)
    subprocess.run([build + '/softflowd', '-d', '-r', pcap, '-v', 'psamp', '-n', '127.0.0.1:%d' % port,
                    '-p', pcap + '.pid', '-c', pcap + '.ctl'], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    out = collect(s); s.close(); return out

def roundtrip(build, pcap, ver, port_r, port_c):
    col = udp_listener(port_c); ctl = pcap + '.rx.ctl'
    if os.path.exists(ctl): os.unlink(ctl)
    rx = subprocess.Popen([build + '/softflowd', '-d', '-R', str(port_r), '-n', '127.0.0.1:%d' % port_c, '-v', ver,
                           '-t', 'general=86400', '-t', 'tcp=86400', '-t', 'tcp.rst=86400', '-t', 'tcp.fin=86400',
                           '-t', 'udp=86400', '-t', 'icmp=86400', '-t', 'maxlife=86400', '-t', 'expint=86400',
                           '-p', pcap + '.rx.pid', '-c', ctl], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(0.5)
    subprocess.run([build + '/softflowd', '-d', '-r', pcap, '-v', 'psamp', '-n', '127.0.0.1:%d' % port_r,
                    '-p', pcap + '.tx.pid', '-c', pcap + '.tx.ctl'], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    time.sleep(1.0)
    # The receiver blocks in recv() after the last datagram (see the notes); a runt datagram wakes it up.
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('127.0.0.1', port_r))
    time.sleep(0.8)
    try: subprocess.run([build + '/softflowctl', '-c', ctl, 'shutdown'], capture_output=True, timeout=3, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired: pass
    try: rx.wait(timeout=5)
    except subprocess.TimeoutExpired: rx.kill()
    out = collect(col); col.close(); return out

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    tools = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools')
    if '--tools' in sys.argv: tools = sys.argv[sys.argv.index('--tools') + 1]; args.remove(tools)
    base, new = args[:2]
    sys.path.insert(0, tools)
    import softflowd_test_collector as t
    tmp = tempfile.mkdtemp(prefix='psamp_regress_')
    pcaps = {}
    for name, flags in (('v4', []), ('v6', ['-6'])):
        p = os.path.join(tmp, name + '.pcap')
        subprocess.run([sys.executable, os.path.join(tools, 'gen_ci_smoke_pcap.py')] + flags + [p], check=True, capture_output=True)
        q = os.path.join(tmp, name + 's.pcap'); open(q, 'wb').write(head(p, 50))  # small: no UDP receive-buffer loss
        pcaps[name + 's'] = q
    p = os.path.join(tmp, 'sizes.pcap')  # frame-section clamp: 1390 is the largest captured size
    open(p, 'wb').write(sized_pcap([60, 1389, 1390, 1391, 1392, 1514])); pcaps['sizes'] = p
    bad = 0; port = 28000
    for name, p in pcaps.items():
        a, b = send_run(base, p, port), send_run(new, p, port + 1); port += 2
        ok = bool(a) and a == b; bad += not ok
        print('send      %-6s datagrams %3d %3d  %s' % (name, len(a), len(b), 'OK' if ok else 'DIFF'))
    norm = lambda o: sorted(','.join(r.split(',')[2:]) for r in
                            t.datagrams_to_csv([(d, 'x') for d in o]).splitlines()[1:])
    for name in ('v4s', 'v6s'):
        for ver in ('5', '9', '10'):
            a = norm(roundtrip(base, pcaps[name], ver, port, port + 1))
            b = norm(roundtrip(new, pcaps[name], ver, port + 2, port + 3)); port += 4
            ok = a == b; bad += not ok
            print('roundtrip %-6s v%-2s flows %3d %3d  %s' % (name, ver, len(a), len(b), 'OK' if ok else 'DIFF'))
    print('mismatches:', bad); return 1 if bad else 0

if __name__ == '__main__':
    sys.exit(main())
