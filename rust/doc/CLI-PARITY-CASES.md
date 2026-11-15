# CLI parity cases (generated 2026-11-15) / コマンドライン比較ケース

Generated from `PARITY_CLI_ERROR_CASES` of `tools/softflowd_test_parity_live.py` with `softflowd` (C) and `rsoftflowd` (Rust) at upstream 5506a82. `PROG` is the program name; `{pcap}` is a capture file. "stream" is where the first line was written. / 上記のケースを C と Rust で実行した結果。1 行目のみ。

| args | C exit | C stream | C first line | Rust exit | Rust stream | Rust first line | same |
|---|---|---|---|---|---|---|---|
| `(no arguments)` | 1 | stderr | -i, -r or -R option not specified. | 1 | stderr | Must specify a packet source (-i or -r). | NO |
| `-h` | 0 | stderr | Usage: PROG [options] [bpf_program] | 0 | stdout | Traffic flow monitoring daemon rewritten in Rust | NO |
| `--help` | 0 | stderr | Usage: PROG [options] [bpf_program] | 0 | stdout | PROG is a software implementation of a flow-based network traffic monitor. | NO |
| `-z` | 1 | stderr | ./PROG: invalid option -- 'z' | 2 | stderr | error: unexpected argument '-z' found | NO |
| `--bogus` | 1 | stderr | ./PROG: unrecognized option '--bogus' | 2 | stderr | error: unexpected argument '--bogus' found | NO |
| `-i` | 1 | stderr | ./PROG: option requires an argument -- 'i' | 2 | stderr | error: a value is required for '--interface <[idx:]interface>' but none was supplied | NO |
| `-r` | 1 | stderr | ./PROG: option requires an argument -- 'r' | 2 | stderr | error: a value is required for '--read <pcap_file>' but none was supplied | NO |
| `-t` | 1 | stderr | ./PROG: option requires an argument -- 't' | 2 | stderr | error: a value is required for '--timeout <timeout=time>' but none was supplied | NO |
| `-X` | 1 | stderr | ./PROG: invalid option -- 'X' | 2 | stderr | error: unexpected argument '-X' found | NO |
| `-i lo -r {pcap}` | 1 | stderr | Packet source already specified. | 2 | stderr | error: the argument '--interface <[idx:]interface>' cannot be used with '--read <pcap_file | NO |
| `-r {pcap} -i lo` | 1 | stderr | Packet source already specified. | 2 | stderr | error: the argument '--read <pcap_file>' cannot be used with '--interface <[idx:]interface | NO |
| `-r {pcap} -r {pcap}` | 1 | stderr | Packet source already specified. | 2 | stderr | error: the argument '--read <pcap_file>' cannot be used multiple times | NO |
| `-i ` | 1 | stderr | Wrong interface is specified. | 1 | stderr | Wrong interface is specified. | yes |
| `-i :` | 1 | stderr | Wrong interface is specified. | 1 | stderr | Wrong interface is specified. | yes |
| `-i 1:` | 1 | stderr | Wrong interface is specified. | 1 | stderr | Wrong interface is specified. | yes |
| `-r /nonexistent/x.pcap -n 127.0.0.1:9` | 1 | stderr | pcap_open_offline(/nonexistent/x.pcap): /nonexistent/x.pcap: No such file or directory | 1 | stderr | PCAP capture error: libpcap error: /nonexistent/x.pcap: No such file or directory | NO |
| `-r /etc/passwd -n 127.0.0.1:9` | 1 | stderr | pcap_open_offline(/etc/passwd): unknown file format | 1 | stderr | PCAP capture error: libpcap error: unknown file format | NO |
| `-r {pcap} -n 127.0.0.1:9 this is not a filter` | 1 | stderr | pcap_compile("this is not a filter"): can't parse filter expression: syntax error | 1 | stderr | PCAP capture error: libpcap error: can't parse filter expression: syntax error | NO |
| `-T bogus -r {pcap}` | 1 | stderr | Unknown flow tracking level | 2 | stderr | error: invalid value 'bogus' for '--track <level>' | NO |
| `-P bogus -r {pcap}` | 1 | stderr | Unknown transport layer protocol | 2 | stderr | error: invalid value 'bogus' for '--export-protocol <protocol>' | NO |
| `-F bogus -r {pcap}` | 1 | stderr | Invalid flow lookup mode | 2 | stderr | error: invalid value 'bogus' for '--flow-lookup <mode>' | NO |
| `-A bogus -r {pcap}` | 1 | stderr | Unknown time format | 2 | stderr | error: invalid value 'bogus' for '--absolute-time <format>' | NO |
| `-v 99 -r {pcap}` | 1 | stderr | Invalid NetFlow version | 2 | stderr | error: invalid value '99' for '--netflow-version <version>' | NO |
| `-v abc -r {pcap}` | 1 | stderr | Invalid NetFlow version | 2 | stderr | error: invalid value 'abc' for '--netflow-version <version>' | NO |
| `-v 0 -r {pcap}` | 1 | stderr | Invalid NetFlow version | 2 | stderr | error: invalid value '0' for '--netflow-version <version>' | NO |
| `-m 0 -r {pcap}` | 1 | stderr | Invalid maximum flows | 1 | stderr | Invalid maximum flows | yes |
| `-m abc -r {pcap}` | 1 | stderr | Invalid maximum flows | 2 | stderr | error: invalid value 'abc' for '--max-flows <max_flows>': invalid digit found in string | NO |
| `-m -5 -r {pcap}` | 1 | stderr | Invalid maximum flows | 2 | stderr | error: unexpected argument '-5' found | NO |
| `-x 0 -r {pcap}` | 1 | stderr | Invalid number of MPLS label (1 to 10) | 1 | stderr | Invalid number of MPLS label (1 to 10) | yes |
| `-x 11 -r {pcap}` | 1 | stderr | Invalid number of MPLS label (1 to 10) | 1 | stderr | Invalid number of MPLS label (1 to 10) | yes |
| `-L 300 -r {pcap}` | 1 | stderr | Invalid hop limit | 1 | stderr | Invalid hop limit | yes |
| `-L -1 -r {pcap}` | 1 | stderr | Invalid hop limit | 2 | stderr | error: unexpected argument '-1' found | NO |
| `-H zz -r {pcap}` | 1 | stderr | Invalid MAC address zz | 1 | - | (no output) | NO |
| `-n no.such.host.invalid:99 -r {pcap}` | 1 | stderr | No addresses found for [no.such.host.invalid]:99 | 1 | stderr | No addresses found for no.such.host.invalid:99: failed to lookup address information: Name | NO |
| `-n  -r {pcap}` | 1 | stderr | Invalid -n argument. | 1 | stderr | Invalid -n argument. | yes |
| `-n 127.0.0.1 -r {pcap}` | 1 | stderr | Invalid -n argument. | 1 | stderr | Invalid -n argument. | yes |
| `-n 127.0.0.1:abc -r {pcap}` | 1 | stderr | No addresses found for [127.0.0.1]:abc | 1 | stderr | No addresses found for 127.0.0.1:abc: invalid port value | NO |
| `-n 127.0.0.1: -r {pcap}` | 1 | stderr | Invalid -n argument. | 1 | stderr | Invalid -n argument. | yes |
| `-n :9 -r {pcap}` | 1 | stderr | No addresses found for []:9 | 1 | stderr | Invalid -n argument. | NO |
| `-t bogus -r {pcap}` | 1 | stderr | Invalid -t option "bogus". | 1 | stderr | Invalid -t option "bogus". | yes |
| `-t bogus=1 -r {pcap}` | 1 | stderr | Invalid -t name. | 1 | stderr | Invalid -t name. | yes |
| `-t general=0 -r {pcap}` | 1 | stderr | "general" flow timeout must be greater than zero | 1 | stderr | "general" flow timeout must be greater than zero | yes |
| `-t udp=abc -r {pcap}` | 1 | stderr | Invalid -t timeout. | 1 | stderr | Invalid -t timeout. | yes |
| `-t udp= -r {pcap}` | 1 | stderr | Invalid -t option "udp=". | 1 | stderr | Invalid -t option "udp=". | yes |
| `-t udp=-1 -r {pcap}` | 1 | stderr | Invalid -t timeout. | 1 | stderr | Invalid -t timeout. | yes |
| `-t expint=abc -r {pcap}` | 1 | stderr | Invalid -t timeout. | 1 | stderr | Invalid -t timeout. | yes |
| `-t tcp -r {pcap}` | 1 | stderr | Invalid -t option "tcp". | 1 | stderr | Invalid -t option "tcp". | yes |
| `-I 5x -r {pcap}` | 0 | stderr | PROG vX starting data collection | 1 | stderr | No digits were found in boot_time_reinit | NO |
| `-s abc -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 2 | stderr | error: invalid value 'abc' for '--sampling-rate <rate>': invalid digit found in string | NO |
| `-B abc -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 2 | stderr | error: invalid value 'abc' for '--pcap-buffer-size <bytes>': invalid digit found in string | NO |
| `-C abc -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 2 | stderr | error: invalid value 'abc' for '--snaplen <capture_length>': invalid digit found in string | NO |
| `-R abc -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 2 | stderr | error: invalid value 'abc' for '--psamp-port <receive_port>': invalid digit found in strin | NO |
| `-r {pcap}` | 0 | stderr | PROG vX starting data collection | 0 | stdout | Accumulated statistics since 1970-01-12T13:46:40 UTC: | NO |
| `-n 127.0.0.1:9` | 1 | stderr | -i, -r or -R option not specified. | 1 | stderr | Must specify a packet source (-i or -r). | NO |
| `-T port -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 0 | stdout | Accumulated statistics since 1970-01-12T13:46:40 UTC: | NO |
| `-T ICMP -r {pcap}` | 1 | stderr | Unknown flow tracking level | 2 | stderr | error: invalid value 'ICMP' for '--track <level>' | NO |
| `-c none -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 0 | stdout | Accumulated statistics since 1970-01-12T13:46:40 UTC: | NO |
| `-c /nonexistent/dir/ctl -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 1 | stderr | Failed to start control server: No such file or directory (os error 2) | NO |
| `-r {pcap} -c /nonexistent/dir/ctl -n 127.0.0.1:9` | 1 | stderr | unix domain bind("/nonexistent/dir/ctl") error: No such file or directory | 1 | stderr | Failed to start control server: No such file or directory (os error 2) | NO |
| `-i nonexistent0 -n 127.0.0.1:9` | 1 | stderr | pcap_activate: No such device exists | 1 | stderr | PCAP capture error: libpcap error: No such device exists | NO |
| `-d -i nonexistent0 -n 127.0.0.1:9` | 1 | stderr | pcap_activate: No such device exists | 1 | stderr | PCAP capture error: libpcap error: No such device exists | NO |
| `-i lo -n 127.0.0.1:9 -c {ctl} this is not a filter` | 1 | stderr | pcap_compile("this is not a filter"): can't parse filter expression: syntax error | 1 | stderr | PCAP capture error: libpcap error: can't parse filter expression: syntax error | NO |
| `-i lo -n 127.0.0.1:9 -c /nonexistent/dir/ctl` | 1 | stderr | unix domain bind("/nonexistent/dir/ctl") error: No such file or directory | 1 | stderr | Failed to start control server: No such file or directory (os error 2) | NO |
| `-i lo -n 127.0.0.1:9 -c /tmp/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | 1 | stderr | control socket path too long | 1 | stderr | Failed to start control server: path must be shorter than SUN_LEN | NO |
| `-R 0 -c /nonexistent/dir/ctl` | 1 | stderr | unix domain bind("/nonexistent/dir/ctl") error: No such file or directory | 1 | stderr | Must specify a packet source (-i or -r). | NO |
| `-I abc -r {pcap}` | 1 | stderr | No digits were found in boot_time_reinit | 1 | stderr | No digits were found in boot_time_reinit | yes |
| `-I 99999999999999999999 -r {pcap}` | 1 | stderr | strtol: Numerical result out of range | 1 | stderr | No digits were found in boot_time_reinit | NO |
| `-e no.such.host.invalid -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | getaddrinfo: Name or service not known | 0 | stdout | Accumulated statistics since 1970-01-12T13:46:40 UTC: | NO |
| `-n 127.0.0.1:65536 -r {pcap}` | 1 | stderr | Invalid -n argument. | 1 | stderr | Invalid -n argument. | yes |
| `-n 127.0.0.1:99999 -r {pcap}` | 1 | stderr | Invalid -n argument. | 1 | stderr | Invalid -n argument. | yes |
| `-n 127.0.0.1:99999999999999999999 -r {pcap}` | 1 | stderr | Invalid -n argument. | 1 | stderr | No addresses found for 127.0.0.1:99999999999999999999: invalid port value | NO |
| `-n 127.0.0.1:65535 -r {pcap}` | 0 | stderr | PROG vX starting data collection | 0 | stdout | Accumulated statistics since 1970-01-12T13:46:40 UTC: | NO |
| `-t maxlife=99999999999 -r {pcap}` | 1 | stderr | Invalid -t timeout. | 1 | stderr | Invalid -t timeout. | yes |
| `-R 99999 -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | Invalid -R port, using the default 4739. | 2 | stderr | error: invalid value '99999' for '--psamp-port <receive_port>': 99999 is not in 0..=65535 | NO |
| `-R -1 -n 127.0.0.1:9 -r {pcap}` | 0 | stderr | Invalid -R port, using the default 4739. | 2 | stderr | error: unexpected argument '-1' found | NO |
