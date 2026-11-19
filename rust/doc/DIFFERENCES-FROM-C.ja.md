# rsoftflowd と C 版の差分

`rust/` の現状を、この木の C 版と比べた記録です。各項目に、どう確認したかを付けます。

- **実測**: 両方のバイナリを動かして確認した。
- **ソース**: ソースやリポジトリを読んで確認した。実行はしていない。
- **未測定**: 確認していないと分かっている。

## 測定時点

| | |
|---|---|
| 測定日 | 2026-11-02 |
| 基準 | 上流 `3281d94`。このパッチ系列のパッチを当てる前(挙動は変えないパッチです) |
| 環境 | Rust 1.85.1、debug ビルド、内蔵 Python コレクタ |
| C バイナリ | 同じコミットの開発版 C ビルド |

下の「発見」と「修正パッチ」の番号は、2026-11-02 に始めたパッチ系列の番号です
(`0001` がこの文書を追加したパッチ)。パッチを当てるとコミットのハッシュは
変わるので、パッチの件名を確かなキーとして書きます。

## 状態表

| ID | 内容 | 発見 | 状態 | 修正パッチ | 確認 |
|----|------|------|------|------------|------|
| D1 | NetFlow v9: 追加要素が違う | 2026-11-02 | 解消 | 0011 Use the same templates for NetFlow v9 as for IPFIX | 2026-11-02、compat `--strict` の C と Rust の比較で、IPv4・IPv6 の pcap とも NetFlow v9 が MATCHED (各 24 レコード)。`tests/netflow9_templates.rs` は旧コードで失敗する |
| D2 | IPFIX の flowEndReason の値が誤り | 2026-11-02 | 解消 | 0007 Fix the flowEndReason values of the Rust version | 2026-11-02、compat `--strict` の C と Rust の比較で、IPv4・IPv6 の pcap とも IPFIX が MATCHED (各 24 レコード) |
| D3 | コマンドラインのエラー: 75 件中 47 件が違う | 2026-11-02 | 解消 | Exit with status 1 for a wrong command line, and accept the getopt_long grammar | 2026-11-15、`test_d3_wrong_command_line_exits_1` と `test_d3_help_exits_0` (旧コードで失敗)。compat の 94 ケースで、D34 の 11 件を除き `exit status` の差がない |
| D4 | ntopng がない | 2026-11-02 | 解消 | ntopng へのエクスポート (-v ntopng) をオプションの Cargo 機能として追加 | 2026-11-02、統合テストが成功 (機能有効時); -v ntopng-json は未移植 |
| D5 | プログラム名とバージョンが揃っていない | 2026-11-02 | 解消 | 0016 別名バイナリを削除 | 2026-11-02、cargo build で rsoftflowd と rsoftflowctl のみ生成されることを確認 |
| D6 | ログ | 2026-11-02 | 解消 | C版に合わせた syslog および標準エラー出力のログ出力とメッセージの実装 | 2026-11-02、標準エラー出力をキャプチャして最初の 4 行を C の文言と比較する統合テスト |
| D7 | PSAMP メッセージヘッダ（シーケンス番号とエクスポート時刻）が C と異なる | 2026-11-02 | 解消 | psamp.rs における PSAMP のシーケンス番号とエクスポート時刻の修正 | 2026-11-07, 120 パケットの pcap に対する最初の 20 メッセージのシーケンス番号を統合テストで検証 |
| D8 | compat のステップ 6 に未到達 (未測定) | 2026-11-02 | 解消 | 0011 Use the same templates for NetFlow v9 as for IPFIX | 2026-11-02、ステップ 6 が初めて動いた(結果は D12) |
| D9 | 最大寿命: C は `>`、Rust は `>=` で比較 | 2026-11-02 | 解消 | 0014 Compare the maximum lifetime with > as the C version does | 2026-11-02、単体テスト maximum_lifetime_expiry_boundary が成功 (旧コードでは失敗) |
| D10 | 過負荷での追い出し: C は前の flowEndReason のまま、Rust は lack of resources | 2026-11-02 | 解消 | Expire the flows over -m in a batch after the packets, as C does | 2026-11-15、過負荷で追い出したフローは C と同じく flowEndReason を変えない (`-m` のケースのデータグラムが C と同一) |
| D11 | NetFlow v9 のオプションテンプレート: C は interfaceName (IE 82) を持ち、Rust は持たない | 2026-11-02 | 解消 | 0015 Add interfaceName to the NetFlow v9 option template | 2026-11-02、NetFlow v9 のオプションテンプレートに interfaceName が含まれることを確認する単体テストが成功 (旧コードでは失敗) |
| D12 | compat のステップ 6: バイト単位の比較の大半が違う (本文を参照) (まとめの項目。2026-11-15 に再測定、原因は D19、D20、D22〜D28) | 2026-11-02 | 未解消 | | |
| D13 | コマンドライン (D3 の一部): 不正な `-t` を受理し、大きな時間で panic する | 2026-11-02 | 解消 | 0012 Reject the wrong -t options as the C version does | 2026-11-02、D3 の 75 件を再実行: `-t` の件は C と同じになった(終了ステータスが違うのは 38 件、以前は 47 件)。`parse_duration` と `apply_timeouts` の単体テスト |
| D14 | コマンドライン (D3 の一部): `-T port` が panic する。C は受理する | 2026-11-02 | 解消 | 0013 Accept -T port in the Rust version | 2026-11-02、D3 の 75 件を再実行: panic は残っていない(終了ステータスが違うのは 37 件、以前は 38 件)。レベル名のテスト |
| D15 | 過負荷での追い出し: Rust は追い出したフローを破棄していた (D12 の一部) | 2026-11-02 | 解消 | evict_oldest_flow() で追い出したフローのエクスポートを追加 | 2026-11-02、単体テスト test_flow_eviction_exports が成功 (旧コードでは失敗) |
| D16 | NetFlow v5 の flow_sequence が C 版の2倍の速さで増加する (D12 の一部) | 2026-11-07 | fixed | export_build_flow_header() の NetFlow v5 における flow_sequence を修正 | 2026-11-07, NetFlow v5 のシーケンス番号に関するテストが通過 (旧コードでは失敗) |
| D17 | コマンドライン (D3 の一部): 起動順序や `-n`、`-I`、インターフェイス、BPF フィルタ、制御ソケットの検証が C 版と違う | 2026-11-02 | 解消 | Check options and open capture before daemonizing, and reject bad -n and -I | 2026-11-07, `parse_boot_time_reinit` の単体テスト、デーモン化せずに終了ステータス 1 になる統合テスト |
| D18 | 無視されたパケットの統計: Rust が non-IP および too short パケットを数えていなかった (D12 の一部) | 2026-11-10 | 解消 | parse_packet() およびキャプチャループで non-IP と too short パケットをカウントするよう修正 | 2026-11-10、parse_packet() の単体テストおよびカウンタのテストが通過 |
| D19 | NetFlow v9 の option template: scope type が Rust は 1 (System)、C は 2 (Interface) | 2026-11-15 | 解消 | Use the Interface scope type in the NetFlow v9 option template | 2026-11-15、`http.cap` と `v6-http.cap` (`-v 9 -a`) で option template flowset が C と同一。`test_netflow_v9_option_template_has_interface_name` が scope type 2 を期待するようになり、旧コードで失敗する |
| D20 | option レコードの interfaceName が、`-r` のとき Rust は空、C はファイル名 | 2026-11-15 | 解消 | Write the capture file name to the interfaceName of the option records with -r | 2026-11-15、`http.cap` と `v6-http.cap` (`-v 9 -a`、`-v 10 -a`) で option data レコードが PID を除いて C と同一。`interface_name_field()` の単体テスト、統合テスト `test_d20_option_record_interface_name_is_file_name` (旧コードで失敗) |
| D21 | biflow (`-b`) の ICMP テンプレート: C は逆方向の icmpTypeCode を持ち、Rust は持たない | 2026-11-15 | 解消 | ICMP は biflow にしない: C、C++、Rust は ICMP のフローを片方向の ICMP テンプレートと、方向ごとに 1 レコードで出力する (逆方向のフィールドなし)。C と C++ は 1.1.1 と違いが出る | 2026-11-19、C、C++、Rust: `http.cap` と `v6-http.cap` の `-v 10 -b` (`-T full`、`-A micro` も) のテンプレートセットとデコードしたレコードが同じ。ICMP は `-b` の有無でも同じ。ゲートの項目は削除。1.1.1 との差は `tools/softflowd_test.py` で許容する |
| D22 | 過負荷の追い出し (`-m`): C は dispatch の後にまとめて追い出し、Rust は 1 フローずつ追い出して 1 フロー 1 データグラムで送る (D12 の一部) | 2026-11-15 | 解消 | Expire the flows over -m in a batch after the packets, as C does | 2026-11-15、`smoke`、`smoke6`、`vlan`、`slow`、`many` の全ての `-m` と `-t maxlife=1 -m 7` のケース (`-v 1`、`5`、`9`、`10`) で、データグラムと `-D` ログが C と同一 (D23 を除く)。live の "burst over -m 10" が MATCHED。`test_flow_eviction_exports` と `tests/expire_modes.rs`。バッチは 1 回 `-m` パケット (`-r` では揃うまで待つ)。`next_expire_is_now()` は `next_expire() == 0` に相当 |
| D23 | データグラムの詰め方: C の方が早くデータグラムを閉じる (D12 の一部) | 2026-11-15 | 解消 | C: Pack the datagram by the records that are written, not for two per flow | 2026-11-15、C 側のこの変更で、`http.cap` と `v6-http.cap` の v9 と IPFIX のデータグラムが Rust と (PID を除き) バイト単位で一致。compat: 差のある実行が 134 件から 24 件 (残りは D21、D32、D33)。C++ 版 (`records_in_flow`) と旧 export の `compat/ipfix.c` にも同じ規則を入れた (C++ 版と静的ビルドを C ビルドとバイト単位で比較する CI のため) |
| D24 | expiry scan: モード、`<` と `<=`、"Forcing expiry" ログがない (D12 の一部) | 2026-11-15 | 解消 | Match the modes, the boundary and the log lines of the expiry scan to C | 2026-11-15、`ExpireMode` (0、-1、1)、`-r` は強制分のみをスキャン、`expires_at < now`。`smoke` と `smoke -m 100` の `-d` ログが C と同一。`tests/expire_modes.rs`。同じスキャンで C に合わせたもの: `Queuing flow` 行の reason は数値で flush の印を付ける前に出す、最大寿命は `>=` で数える、`sent N netflow packets` を `EXPIRED` 行の前に出す、送信失敗で `flows_dropped` を増やす。`-m` のケースの `-d` ログはまだ違う: D22 |
| D25 | パケット統計: non-IP と too short で `Packets processed` と `Ignored packets` が違う (D12 の一部) | 2026-11-15 | 解消 | Align packet statistics and capture loop counters with C | 2026-11-15、non-IP および too short パケットのカウンタの単体テスト、統合テストが通過 |
| D26 | コマンドライン: エラーと `-h`/`--help` の文言が違う (D12 の一部。終了ステータスは D3) | 2026-11-15 | 未解消 | | |
| D27 | `-g -M`: CPU clock の行が違う (D12 の一部) | 2026-11-15 | 解消 | Print n/a for the export clock with -M (gauge clock) | 2026-11-16、compat の "cpu clocks of -g -M" が MATCHED。ゲートの登録を削除 |
| D28 | control socket の応答とシグナル時のログが違う (D12 の一部) | 2026-11-15 | 解消 | Make the control socket replies, the signals and the final statistics like C | 2026-11-16、"control replies (21 commands, ending with shutdown / exit)"、shutdown と exit コマンドのログ、SIGINT、SIGTERM、SIGHUP、SIGUSR1 が MATCHED。最初の修正の追補: `timeouts` を 22 桁に右揃え、`statistics` の表サイズ (バケット数 x 8 バイト) と libpcap の行 (読み取りが 1 秒ごとにタイムアウト)、`dump-flows` を期限イベントの順にする (ハッシュ表の不定な順だった)、最終統計は C と同じく `-r` のときだけ、権限を落とすのはデーモンのときだけ (`-d` で root だと制御ソケットを消せなかった)、`ctl connect(...) error:` から " (os error N)" を除く。テスト `tests/control_text.rs` |
| D29 | 起動ログの順序が入れ替わることがある。`Dropped privileges to nobody` が余分 (`cargo test` で発見) | 2026-11-15 | 解消 | Log start-up messages before starting capture and drop extra privilege log | 2026-11-15、一般ユーザーで `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、`cargo test` (`test_d6_logging_stderr_first_four_lines` の 20 回連続実行を含む) が通過。追加修正: キャプチャ元を daemon 化と権限放棄の前に開く順序へ戻した (root での live capture、存在しない interface での終了ステータス 1)。キャプチャスレッドは起動ログの後に開始する。`test_d6_logging_stderr_first_four_lines` は 100 回中 100 回成功 |
| D32 | IPFIX の option data レコードが `-e` を無視する (exporter アドレスがゼロ) | 2026-11-15 | 解消 | rsoftflowd: fix to include the exporter address in the IPFIX option data record | 2026-11-16、compat の `-e 192.0.2.1` が MATCHED。ゲートの登録を削除 |
| D33 | `-b` と `-H` (と `-T ether`): v9 では逆方向の MAC アドレス、IPFIX ではサイズが違う | 2026-11-15 | 解消 | Use the RFC 7011 values of flowDirection (0 ingress, 1 egress) | 2026-11-16、v9 の `-b -T ether -H` が全 pcap で MATCHED。`tests/flow_direction.rs`。原因: Rust が ingress に 2 を書いていた。`-v 10 -b` で残るのは ICMP の biflow template のサイズ (D21、許容) |
| D34 | コマンドラインの文法: C (getopt_long) は長いオプションの省略形、フィルタの後のオプション、2 回の `-n`、あいまいな数値を受理するが、Rust は受理しなかった (D26 の一部) | 2026-11-15 | 許容 | Exit with status 1 for a wrong command line, and accept the getopt_long grammar (あいまいな数値は意図的に受理しない) | 2026-11-15、`test_d34_getopt_long_grammar` (旧コードで失敗)。あいまいな数値と不正な値の 11 ケースは終
了ステータスが違う (許容) |
| D35 | 受理される実行: C は前景で `-d` なしでも標準エラーにログを出すが、Rust は何も出さない。統計も違う (未分析) | 2026-11-15 | 解消 | Log to standard error for -r, and print the final statistics without the header | 2026-11-16、compat のコマンドライン項目の受理される 17 件で、標準出力と標準エラーが C と同一。`test_d35_file_run_logs_to_stderr_and_prints_statistics_without_header` |
| D36 | live キャプチャの idle expiry: Rust は C より 0.1〜0.8 秒早く export する (未分析。compat の項目が MATCHED になることもある) | 2026-11-16 | 解消 | Wait like poll() of C before the idle flows are looked at (next_expire) | 2026-11-16、compat の "live on lo, idle expiry (-t expint=3)" が 8 回中 8 回 MATCHED で C と同じ時刻 (6 回中 4 回で 0.1〜0.8 秒早かった)。`test_d36_next_expire_is_like_c` |
| D37 | fuzz スクリプト (G1) が見つけた: データリンクヘッダより長くないパケットを too short と数えていた、短い IPv6 パケットを `-6` なしで二重に数えていた、フローの ToS が最後のパケットのものだった (C は最初のパケット) (D25 の一部) | 2026-11-16 | 解消 | Match the classification of short packets and the ToS of a flow to C | 2026-11-16、`http.cap` と `v6-http.cap` の 320 回のパケット内容の変異と、先頭パケットの全長での切り詰めで、レコードとパケットのカウンタに差なし。`test_d37_*` |
| D38 | プロトコル別統計のプロトコル名: C はシステムに問い合わせる (`getprotobynumber`、`/etc/protocols`: `xns-idp (22)`)。Rust は短い表を持ち `Unknown (22)` になる | 2026-11-16 | 未解消 | | |
| D39 | 統計の平均 Duration が、一部のキャプチャで小数第 2 位で違う (C 0.04、Rust 0.05)。期限切れの順序は同じ。原因: C は 2 つの double (sec + usec / 1e6) を引いており、epoch の大きさでは約 1e-7 秒を失う。Rust (と C++) は秒とマイクロ秒を別々に引くので厳密 | 2026-11-16 | 解消 | Rust ではなく C を直す (stats.c の `update_statistics()`)。厳密な計算の方がよい | 2026-11-19、`fz3.py` (変異した `http.cap` と `v6-http.cap` を 60 個ずつ、オプション 2 組) の 240 回中 15 回でパッチ前は統計が違った。パッチ後は 5 回で、すべてプロトコル名 (D38) の違いであり、Duration の行の違いはない。C++ は元から厳密 (chrono) |
| D30 | シャットダウン (SIGINT、SIGTERM、`softflowctl shutdown`) 時に、テーブルに残ったフローが export されなかった | 2026-11-15 | 解消 | Export the flows left in the table at shutdown again | 2026-11-15、compat の "live on lo, burst over -m 10" で 60 件中 60 件 (修正前は 50 件以下) |
| D31 | 両端が同じアドレス (`lo` など): C は 1 つの Biflow にし、Rust は 2 つのフローにする | 2026-11-15 | 解消 | Handle same-address Biflow in FlowKey::canonical() using port comparison | 2026-11-15、統合テスト `test_d31_same_address_biflow` (旧コードで失敗) |
| R1 | `rust/AGENTS.md` がリポジトリの実態と合わない | 2026-11-02 | 解消 | 0006 Update AGENTS.md and the README of the Rust version to the current policy | 2026-11-02、リポジトリと照合 |
| R2 | CI に Rust のジョブがない | 2026-11-02 | 解消 | 0004 Add a CI job that checks the format, clippy and the tests of the Rust version | 2026-11-02、クリーンな checkout で同じコマンドをローカル実行 |
| R3 | `cargo fmt --check` が失敗する | 2026-11-02 | 解消 | 0002 Format the Rust version with cargo fmt | 2026-11-02、ローカル |
| R4 | `cargo clippy -D warnings` が失敗する (警告 20 件) | 2026-11-02 | 解消 | 0003 Fix the warnings of clippy in the Rust version | 2026-11-02、ローカル |
| R5 | `cargo doc -D warnings` が失敗する | 2026-11-02 | 解消 | rust/src/opts.rs のリンク未解決をエスケープ | 2026-11-11、cargo doc 通過 |
| R6 | デーモンの主処理がバイナリ側にある | 2026-11-02 | 解消 | main() を関数に分割 (targets, capture, signals, loop) | cargo test, fmt, clippy -D warnings 通過 |
| R6-1 | accumulate_stats() を stats.rs に移動 (R6 の一部) | 2026-11-11 | 解消 | Move accumulate_stats() to stats.rs | cargo test, fmt, clippy -D warnings 通過 |
| R6-2 | 有効期限切れ処理コードを expire.rs に移動 (R6 の一部) | 2026-11-12 | 解消 | Move expiry code to expire.rs | cargo test, fmt, clippy -D warnings 通過 |
| R6-3 | オプションヘルパーを opts.rs に移動 (R6 の一部) | 2026-11-13 | 解消 | Move option helpers to opts.rs | cargo test, fmt, clippy -D warnings 通過 |
| R6-4 | パケット処理を capture.rs に移動 (R6 の一部) | 2026-11-13 | 解消 | Move process_parsed_packet() to capture.rs | cargo test, fmt, clippy -D warnings 通過 |
| R6-5 | main() を関数に分割、targets と capture を移動 (R6 の一部) | 2026-11-14 | 解消 | Split main() into functions (targets, capture, signals, loop) | cargo test, fmt, clippy -D warnings 通過 |
| R7 | `unsafe`が 22 行にある | 2026-11-02 | 解消 | Replace static mut and raw pointer with safe code in export.rs and psamp.rs | cargo test, fmt, clippy -D warnings 通過 |
| R7-1 | clock() の呼び出しを安全な CPU クロックヘルパーに置き換え (R7 の一部) | 2026-11-14 | 解消 | clock() を nix の clock_gettime CPU クロックヘルパーに置き換え | cargo test, fmt, clippy -D warnings 通過 |
| R7-3 | 最後の unsafe コードの削除: シグナル、geteuid、SO_BINDTODEVICE (R7 の一部) | 2026-11-14 | 解消 | signal-hook と nix setsockopt を使用して最後の unsafe コードを削除し、#![forbid(unsafe_code)] を追加 | cargo test, fmt, clippy -D warnings 通過 |
| R8 | `rust/tests/run_compat_tests.py` と `rust/doc/test.ja.md` が tools と重複 | 2026-11-02 | 未解消 | `rust/tests/run_compat_tests.py` と `rust/doc/test.ja.md` を削除 | `rust/` 部分は解消; `rust/` 外の部分は未解消 |
| R9 | stable の Rust が新しくなると CI が失敗する: clippy の新しい lint (`collapsible_if`、`manual_is_multiple_of`) | 2026-11-02 (`rust` ジョブのログ) | 解消 | 0008 Fix the clippy findings of Rust 1.91 and require Rust 1.88; 0009 Pin the Rust version of the Rust version and let CI use it | 2026-11-02、Rust 1.91.1 で CI ジョブの 3 つの cargo コマンド: fmt、clippy、テスト 18 件が成功。CI のジョブ自体はまだ動かしていない |
| R10 | commit の前に Rust 版を検査するものがない | 2026-11-02 | 解消 | 0010 Add the checks of the Rust version to the pre-commit hook | 2026-11-02、作業用の clone で確認(R10 の本文を参照) |

「解消」は、パッチで直したことを表し、「確認」に確認方法を書きます。
解消した行は消さずに残します。履歴を残すことが目的です。

### この文書の更新のしかた

- 項目を直すパッチは、同じパッチで、その行を更新します。状態を「解消」にし、
  「修正パッチ」にパッチの番号と件名、「確認」に日付と実行した内容を書きます。
- 後から見つけた差分は、新しい ID の行として足します。ID は再利用しません。
- 測り直すときは「再現手順」のコマンドを実行し、「測定日」と「基準」と、
  結果が変わった項目の本文を更新します。

## 再現手順

```sh
# rustc/cargo 1.85 以上 (edition 2024) と libpcap-dev が必要です。
python3 tools/gen_ci_smoke_pcap.py -n 20 pcaps/http.cap
python3 tools/gen_ci_smoke_pcap.py -6 -n 20 pcaps/v6-http.cap
python3 tools/softflowd_test.py --skip-cpp \
    --collector python --pcap-dir pcaps --no-benchmark --no-gauge-clock
```

出力の最後の組 `A=softflowd vs B=rsoftflowd` が Rust です。
ほかのオプションは `tools/softflowd_test.py` を見てください。

## compat テストの結果 (実測)

| ステップ | 結果 |
|----------|------|
| 1 コマンドラインオプション | PASSED |
| 2 制御ソケット | PASSED |
| 3 NetFlow v1 (IPv4、IPv6 の pcap) | MATCHED (24 レコード) |
| 3 NetFlow v5 (IPv4、IPv6 の pcap) | MATCHED (24 レコード) |
| 3 NetFlow v9 (IPv4、IPv6 の pcap) | FAILED (D1) |
| 3 IPFIX (IPv4、IPv6 の pcap) | FAILED (D2) |
| 4 PSAMP | Rust では実行せず。PSAMP レコードが違うことは既知 (D7) |
| 5 バイト単位の比較、expiry ログ、-M、実キャプチャ | 到達せず (D8) |

失敗したテストでも、各レコードの先頭 13 列(時刻、アドレス、ポート、プロトコル、
フラグ、パケット数、バイト数)は全件一致です。違うのは追加の情報要素だけです。

## 差分

各項目の本文は「測定日」時点の状態です。その後に何を直したかは状態表に書きます。

### D1. NetFlow v9 の追加要素 (実測)

デコードした v9 レコードで、C は flowEndReason (136) と flowDirection (61) を
出します。Rust は icmpTypeCode (32、TCP/UDP のレコードにも出る) と vlanId (58)
を出し、136 と 61 は出しません。Rust の v9 テンプレートは 32 と 58 を持ち、
61 と 136 を持ちません(`src/exporter/export.rs` の `build_templates()`、
`version == 9` の分岐)。C の v9 テンプレートの中身は読み出していません。
比較したのはデコード後のレコードだけです。

### D2. IPFIX の flowEndReason の値 (実測、Rust の不具合)

値が IANA の IPFIX レジストリ(flowEndReason、IE 136)に沿っていません。
C は沿っています(`softflowd.h` の `IPFIX_flowEndReason_*`)。

| 理由 | C (正) | Rust |
|------|--------|------|
| idle timeout | 1 | 4 |
| active timeout | 2 | 1 |
| end of flow | 3 | 3 |
| lack of resources | 5 | 2 |

テストでは 20 フローのうち 12 が idle timeout で、C は 1、Rust は 4 です。
Rust は `src/bin/rsoftflowd.rs` の 785 行付近と 867〜893 行です。
C の処理は `softflowd.c` の `flow_update_expiry()` です。

### D3. コマンドラインのエラー (実測)

`PARITY_CLI_ERROR_CASES` の 75 件を両方で実行し、終了ステータスを比べました
(メッセージの文言は比べていません)。47 件が違います。

| 種類 | 件数 | 例 |
|------|------|----|
| C は 1、Rust は 2 (clap の usage エラー) | 20 | `-z`、`-v 99`、`-T bogus`、`-r X -r X` |
| C は拒否、Rust は受理 (1 に対して 0) | 18 | `-i ""`、`-n ""`、`-t bogus`、`-t udp=abc`、`-I abc`、`-i nonexistent0`、不正なキャプチャフィルタ、不正な制御ソケットのパス |
| C は受理、Rust は拒否 | 7 | `-s abc`、`-B abc`、`-C abc`、`-R abc`、`-R 99999`、`-R -1`、`-c /nonexistent/dir/ctl` |
| Rust が panic (終了 101) | 2 | `-T port`、`-t maxlife=99999999999` |

ここに挙げていない 28 件は終了ステータスが同じです。

パッチ 0012 の後 (D13、`-t` の件): 違うのは 38 件で、C が 1 で Rust が 2 が 20 件、
Rust が受理が 10 件、C が受理が 7 件、panic が 1 件(`-T port`)です。
パッチ 0013 の後 (D14、`-T port`): 違うのは 37 件で、panic はありません。
「Rust は受理」の群では、不正な入力がログに出るだけで、デーモンは動き続けるか
終了 0 で終わります。ほかの 2 群のうち、どれを揃えるか(clap の終了 2 と C の
終了 1)は不具合ではなく方針の判断です。

### D4. ntopng

ntopng へのエクスポート (`-v ntopng`) はオプションの Cargo 機能 `"ntopng"` として実装され、ZeroMQ PUB ソケットと nDPI シリアライザ TLV ペイロード (`zmq_msg_hdr_v4`) をサポートします (`-v ntopng-json` は未移植)。

### D5. プログラム名とバージョン (ソース)

`Cargo.toml` から `softflowd` と `softflowctl` の別名を削除しました。`rsoftflowd` と `rsoftflowctl` だけがビルドされます。

### D6. ログ (実測)

`-d` 指定時は、C と同様にタイムスタンプやレベルプレフィックスなしのプレーンテキストとして標準エラー出力に出力されます。`-d` がない場合は、C の呼び出しレベル（`LOG_DEBUG`, `LOG_INFO`, `LOG_WARNING`, `LOG_ERR`）で syslog（ident `rsoftflowd`、`LOG_DAEMON`、PID 付き）に出力されます。ログメッセージの文言、レベル、順序は C 版と一致します。

| C のメッセージ / フォーマット | C のログレベル | Rust のメッセージ / フォーマット | Rust のログレベル |
|---|---|---|---|
| `%s v%s starting data collection` | `LOG_NOTICE` | `rsoftflowd v0.1.0 starting data collection` | `log::info!` |
| `Exporting flows from %s to [%s]:%s` | `LOG_NOTICE` | `Exporting flows from {} to [{}]:{}` | `log::info!` |
| `Shutting down after pcap EOF` | `LOG_NOTICE` | `Shutting down after pcap EOF` | `log::info!` |
| `Shutting down on user request` | `LOG_WARNING` | `Shutting down on user request` | `log::warn!` |
| `Exiting immediately on user request` | `LOG_WARNING` | `Exiting immediately on user request` | `log::warn!` |
| `Exiting immediately on internal error` | `LOG_ERR` | `Exiting immediately on internal error` | `log::error!` |
| `SIGHUP received (config reload not implemented)` | `LOG_INFO` | `SIGHUP received (config reload not implemented)` | `log::info!` |
| `stats: tracked=%u total_packets=%llu` | `LOG_INFO` | `stats: tracked={} total_packets={}` | `log::info!` |
| `Exiting on poll: %s` | `LOG_ERR` | `Exiting on poll: {}` | `log::error!` |
| `Exiting on pcap_dispatch: %s` | `LOG_ERR` | `Exiting on pcap_dispatch: {}` | `log::error!` |
| `Fatal error - exiting immediately` | `LOG_WARNING` | `Fatal error - exiting immediately` | `log::warn!` |
| `Unable to export flows` | `LOG_WARNING` | `Unable to export flows` | `log::warn!` |
| `Starting expiry scan: mode %d` | `LOG_DEBUG` | `Starting expiry scan: mode {}` | `log::debug!` |
| `Queuing flow seq:%" PRIu64 " (%p) for expiry reason %d` | `LOG_DEBUG` | `Queuing flow seq:{} ({:p}) for expiry reason {}` | `log::debug!` |
| `Finished scan %d flow(s) to be evicted` | `LOG_DEBUG` | `Finished scan {} flow(s) to be evicted` | `log::debug!` |
| `EXPIRED: {} ({:p})` | `LOG_DEBUG` | `EXPIRED: {} ({:p})` | `log::debug!` |
| `Forcing expiry of %d flows` | `LOG_INFO` | `Forcing expiry of {} flows` | `log::info!` |
| `Out of memory while expiring flows - all flows expired` | `LOG_ERR` | `Out of memory while expiring flows - all flows expired` | `log::error!` |
| `Needed to expire %d flows, but only %d active` | `LOG_ERR` | `Needed to expire {} flows, but only {} active` | `log::error!` |
| `Control socket "%s"` | `LOG_DEBUG` | `Control socket "{}"` | `log::debug!` |
| `Control socket yielded no data` | `LOG_ERR` | `Control socket yielded no data` | `log::error!` |
| `process_packet: flow_get failed` | `LOG_ERR` | `process_packet: flow_get failed` | `log::error!` |
| `process_packet: expiry_get failed` | `LOG_ERR` | `process_packet: expiry_get failed` | `log::error!` |
| `ADD FLOW %s` | `LOG_DEBUG` | `ADD FLOW {}` | `log::debug!` |
| `COLLISION %s` | `LOG_DEBUG` | `COLLISION {}` | `log::debug!` |
| `Sending flow packet len = %d` | `LOG_DEBUG` | `Sending flow packet len = {}` | `log::debug!` |
| `packet len %d: %s` | `LOG_INFO` | `packet len {}: {}` | `log::info!` |
| `cpu clocks: %ld` | `LOG_INFO` | `cpu clocks: {}` | `log::info!` |
| `cpu clocks (export): %ld (%lu calls)` | `LOG_INFO` | `cpu clocks (export): {} ({} calls)` | `log::info!` |

### D7. PSAMP (修正済み)

PSAMP メッセージヘッダ（IPFIX メッセージヘッダのシーケンス番号およびエクスポート時刻）、テンプレートの `dataLinkFrameSection` フィールド長（C 版の `PSAMP_DATALINKFRAME_SIZE` に合わせて 1390 バイトに固定）、および `sectionExportedOctets`（実際のキャプチャフレーム長 `caplen` を 1390 バイト上限で報告）を C 版に合わせました。`observationTimeMicroseconds` では、C 版の非準拠な $+1\mu s$ オフセットのクィークに対し、Rust の RFC 準拠の NTP 小数部計算 `((tv_usec * 2^32) / 1,000,000)` を維持しています。

### D8. compat テストのステップ 6 (未測定)

バイト単位の比較はステップ 3 の失敗で止まるため、実行していません。
D1 と D2 を直してから測ります。

### D9. 最大寿命の比較 (ソース)

`maxlife` で期限切れになる条件が、C ではフローの経過時間が上限より大きいとき
(`softflowd.c` の `flow_update_expiry()`: `... > ft->param.maximum_lifetime`)、
Rust では上限以上のとき(`src/bin/rsoftflowd.rs`: `... >= param.maximum_lifetime`)
です。実行はしていません。影響は境界での 1 秒です。

### D10. 過負荷で追い出すときの flowEndReason (ソース)

テーブルが満杯でフローを期限切れにするとき(C の `R_OVERFLOWS`)、C は
flowEndReason を設定せず、フローは前の値のままです(`softflowd.c:1734` 付近)。
Rust は `evict_oldest_flow()` で lack of resources を書きます。C は、ハッシュの
衝突とバイト数超過では lack of resources を設定しています。どちらにするかは
判断が要ります。C が単に書き忘れた可能性があります。

### D11. NetFlow v9 のオプションテンプレート (ソース)

C の v9 オプションテンプレートは、スコープ(インターフェース)と 3 つの
オプションフィールドを持ちます: samplingInterval (34)、samplingAlgorithm (35)、
interfaceName (82、16 バイト) (`ipfix_fields.h` の `field_nf9option`)。
Rust は最初の 2 つだけを書きます(`put_templates()` の `version == 9` の分岐)。
v9 の最初のデータグラムの大きさにどれだけ影響するかは切り分けていません。
D12 を見てください。

### D12. バイト単位の比較、compat のステップ 6 (実測)

ステップ 6 は、0011 でステップ 3 が通るようになったため、2026-11-02 に初めて
動きました。コマンドは「再現手順」のものに `--a`、`--b`、`--strict` を付けた
もの(C と Rust の比較)です。原因は分析していません。見えたことを書きます。

- データグラム: 「エクスポートされるデータグラムは 140 実行中 125 が違う」。
  - `-m N`(テーブルの大きさで期限切れにするフロー)では、C は多数の
    データグラムを送り、Rust は 1 つを送ります。NetFlow v1、v5、v9、IPFIX
    のすべてです(例: `-v 5 -a -m 5` は C が 36 データグラム、Rust が 1)。
  - NetFlow v5: 2 番目のデータグラムの 19 バイト目が違います。v5 ヘッダの
    16〜19 バイト目はフローのシーケンス番号です。
  - NetFlow v9 と IPFIX: 最初のデータグラムの大きさが違います(`-v 9 -a`:
    C は 1360 バイト、Rust は 1388。`-v 10 -a -T ether`: C は 1312、Rust は
    1376)。v9 のオプションテンプレートの既知の差分が D11 で、残りは不明です。
- パケット統計(5 テスト): 4 テストで、IP でないパケットや短すぎるパケットを
  Rust は 0 と表示し、C は数えます。5 つ目(`-v psamp`、IP でない)では、
  読んだパケット数が違います(C は 240、Rust は 235)。
- コマンドライン: メッセージの文言まで比べると 75 件すべてが違います(D3 は
  終了ステータスだけを比べています)。`-t general=0`、`-t bogus=1`、`-t tcp`、
  `-t tcp=`、`-t tcp=xyz` は、Rust が終了 0、C が終了 1 です。
- ほかにも違います: `-g` の CPU クロック(2 テストと、ループバックでの 2 テスト)、
  デーモン(権限、syslog)、制御コマンド `exit` と `shutdown` の応答。
  ループバックのライブテストでは、これらのコマンドのログ行と、SIGHUP、
  SIGINT、SIGTERM、SIGUSR1 の挙動も違います。
- 一致したもの: `-M` の有無でデータグラムが同じこと、ファイル末尾での
  expire-all (`-a`)、idle の期限切れ (`-t expint=3`)、まとめて読んだパケット、
  ライブでの `-a` の統計。
- データグラムのパッキングに関する注記: C 版と Rust 版におけるデータグラムのレコードパッキング効率や分割境界の差異(例: C 版が 22 レコードのところ Rust 版が 23 レコードなど)は意図的なものであり、IPFIX (RFC 7011) に準拠しています。メッセージ長、セット長、4バイトのセットパディング、およびトランスポートのパケットサイズ制限(`IPFIX_SOFTFLOWD_MAX_PACKET_SIZE` = 1428 バイト。標準イーサネット MTU 1500 から IP および UDP/TCP ヘッダを差し引いた値)を遵守している限り、RFC 7011 は C 版との厳密なレコード数の一致を要求しません。(将来的な拡張: 送出インターフェースの MTU を動的に取得し、IP ヘッダサイズおよびトランスポートヘッダサイズ(UDP、TCP、SCTP、および最大 60 バイトの TCP オプションを含む)を差し引いて最大パケットサイズを動的に計算すること)。

## 2026-11-15 の再測定 (実測)

| | |
|---|---|
| 測定日 | 2026-11-15 |
| 基準 | 上流 `f7e921a` (`master`) |
| 環境 | Rust 1.91.1、release ビルド、内蔵 Python コレクタ、root で実行 (`daemon` の項目は `/var/empty` が必要で `/dev/log` があってはならないためスキップ) |
| C バイナリ | 同じコミットの C ビルド (`./configure && make`) |
| コマンド | `python3 tools/softflowd_test.py --a softflowd --b rust/target/release/rsoftflowd --ctl-a softflowctl --ctl-b rust/target/release/rsoftflowctl --strict --skip-build --skip-cpp --skip-rust --skip-static --skip-direct --skip-psamp --collector python --pcap-dir pcaps --no-benchmark --no-gauge-clock` |

結果: ステップ 1 と 2 は PASSED。ステップ 3 は NetFlow v1、v5、v9、IPFIX
(IPv4 と IPv6、各 24 レコード) が MATCHED で、D1 と D2 は解消のままです。
ステップ 6 は "exported datagrams: 134 of 168 runs differ" でした。原因を探すため、
両方のバイナリの生のデータグラムを UDP ソケットで取得してデコードしました
(`http.cap` と `v6-http.cap`、`-v 5/9/10 -a`、`-m 5` と `-b` 付き)。
`cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、
`cargo build --release` は通ります。`cargo test` は 1 件失敗します (D29)。

### D12. 2026-11-15 の更新: 原因を項目に分けた

**目的 (Goal)**

`rsoftflowd` を C 版と `--strict` で比べたとき、誰も説明していない差分がない
状態にする。すべての差分は、直すか、理由を付けて「許容」と書く。D12 は
まとめの項目で、子の項目がすべて閉じたときに閉じる。

**受け入れ基準 (Acceptance Criteria)**

1. 差分があった 134 件の原因が、D19、D20、D22〜D28 のどれかに属している
   (D21 は下記のとおり解消)。D12 の本文にだけ残る原因がない。
2. 上の「コマンド」の `--strict` 実行に、文書に「許容」と書かれていない
   `DIFFERENT` がない。許容する差分は、`tools/softflowd_test*.py` の明示的で
   文書化された規則で比較から外す (例: option レコードのプロセス ID)。比較全体を
   ゆるめて外してはならない。
3. ステップ 3 は 4 形式と両アドレスファミリで MATCHED のまま。
4. `cargo fmt --check`、`cargo clippy --all-targets -- -D warnings`、
   `cargo test` が通る。
5. 最後の子を閉じるパッチで、D12 の行を `解消` にし、日付と実行したコマンドを書く。

**背景 (Context)**

D12 は 2026-11-02 に「原因は分析していない」状態で書かれました。その後
D15、D16、D18 が「D12 の一部」として解消されています。今回も同じ規則で、
固有の原因がある項目には ID を付け「(D12 の一部)」と書きます。

2026-11-15 に見えたことと、その行き先:

| 見えたこと | 項目 |
|------------|------|
| 最初の v9 データグラム: option template の scope type (byte 303) | D19 |
| 最初の v9 と IPFIX のデータグラム: option data の interfaceName | D20 |
| `-b`: ICMP のテンプレートのサイズが違う | D21 (解消) |
| `-m N`: C 120、Rust 596 データグラム (`many`)。ヘッダの時刻も違う | D22 |
| v9 と IPFIX: C と Rust がデータグラムを閉じるレコードが違う | D23 |
| `Starting expiry scan: mode` と `EXPIRED` の行 | D24 |
| `Packets processed` / `Ignored packets` (2 件) | D25 |
| コマンドラインの文言 (75 件中 75 件) | D26 |
| `-g -M` | D27 |
| `exit` / `shutdown` の応答、`lo` の SIGINT の行 | D28 |

IPFIX メッセージヘッダのシーケンス番号の規則は両者で同じに見え、差が出るのは
D23 でレコード数が違う所だけです。option data レコードの PID
(`meteringProcessId`) はどの 2 回の実行でも違います (取得した組で 7885 と
7886)。ハーネスがこれをどうマスクしているかは確認しておらず、受け入れ基準 2 の
一部です。

### D19. NetFlow v9 option template: scope type (実測、Rust のバグ)

**目的 (Goal)**

NetFlow v9 の option template は、scope の値がインターフェース番号なので、
C 版と RFC 3954 のとおり scope を Interface (type 2) にする。

**受け入れ基準 (Acceptance Criteria)**

1. 最初の v9 データグラムの option template flowset の scope フィールドが
   type `0x0002`、長さ 4 で、続いて samplingInterval (34, 4)、
   samplingAlgorithm (35, 1)、interfaceName (82, 16) が並ぶ。
2. `http.cap` と `v6-http.cap` で、option template flowset
   (`http.cap -v 9 -a` の最初のデータグラムの byte 290〜325) が C と同一。
3. 組み立てた option template から scope type を読む単体テストが、旧コードで
   失敗し新コードで通る (`test_netflow_v9_option_template_has_interface_name` と
   同じ形式)。
4. IPFIX の option template は変えない。
5. ステップ 3 は MATCHED のまま。fmt、clippy、テストが通る。

**背景 (Context)**

- 実測: `http.cap -v 9 -a`、offset 303。C は `00 02`、Rust は `00 01`。
  option data レコードの値はどちらも `00 00 00 01` (インターフェース番号)。
- ソース: `src/exporter/export.rs:834` が `1u16` を書き、コメントは
  "scope: interface"。RFC 3954 6.1 節の scope type は 1 System、2 Interface、
  3 Line Card、4 NetFlow Cache、5 Template。C は
  `IPFIX_OPTION_SCOPE_INTERFACE` = 2 (`ipfix.h:56`、`ipfix_fields.h:231`) を使い、
  `ifidx` を書く (`export.c` の `enc_nf9OptionScopeInterface`)。
- Rust の値 1 (System) に 4 バイトの番号を付けるのはデータの意味と合わず、
  コレクタが番号を別の種類の scope として読むおそれがある。
- 関連: D11 がこの template に interfaceName を足したが、scope は比較していなかった。

### D20. option レコードの interfaceName (実測、ソース)

**目的 (Goal)**

option レコードの interfaceName は、C と同じく常にキャプチャ元にする。
`-i` ではインターフェース名、`-r` ではファイル名を 16 バイトで、
NetFlow v9 と IPFIX の両方で。(`--enable-ifname` は同じ値をデータレコードにも
足すだけ。)

**受け入れ基準 (Acceptance Criteria)**

1. `-r FILE` では、option data レコードの interfaceName はコマンドラインに
   書いた `FILE` のまま (ベース名にしない)。先頭 15 バイトで、0 で埋める
   (フィールドは 16 バイトで、末尾は NUL)。
2. `-i IF` では `IF`。
3. 15 バイト以上の名前は C と同じく 15 バイトで切り、フィールドは NUL で終わる
   (C は名前を 16 バイト (`IFNAMSIZ`) のバッファに `strlcpy` で持つので、
   16 バイト目は常に NUL)。
4. `-v 9` と `-v 10` で、`http.cap` と `v6-http.cap` の最初のデータグラムの
   option data レコードが、PID のフィールドを除いて C と同一。
5. インターフェース名とファイル名の option レコードの単体テスト。どちらも
   旧コードで失敗する。
6. `--enable-ifname` の機能が有効でない限り、データレコードに名前を入れない
   (従来どおり)。
7. fmt、clippy、テストが通る。ステップ 3 は MATCHED のまま。

**背景 (Context)**

- 実測: 最初のデータグラムの v9 byte 331〜344、IPFIX byte 364〜377。
  C は `pcaps/http.cap`、Rust はゼロ。
- ソース: `rsoftflowd.rs:177` は `capture_dev` が `Some` のとき、つまり `-i` の
  ときだけ `param.interface_name` を設定する。C は常に `option.interfaceName` を
  埋める (`export.c` の `enc_interfaceName` のコメント: "the capture interface,
  or the file name with -r")。
- メンテナの RFC 方針の決定: option レコードの interfaceName には常に正しい値を
  入れる (旧 compat static が正しく、`--enable-ifname` はデータレコードだけを
  制御する)。
- 関連: D6 (メッセージも同じ名前を使う)、D11。

### D21. biflow の ICMP テンプレート (実測、C、C++、Rust で解消)

**目的 (Goal)**

`-b` でも ICMP のフローは biflow にしない。応答 (echo reply) の type と code は
要求 (echo) と違うので、意味を持つ逆方向の icmpTypeCode はない。ICMP と ICMPv6 の
テンプレートに逆方向のフィールドはなく、ICMP のフローは `-b` なしと同じく、octets の
ある方向ごとに 1 レコードで出力する。biflow にするのは、ポートを持つプロトコル
(TCP、UDP、SCTP、DCCP) のフローだけである。C、C++、Rust は同じ動作で、C と C++ は
1.1.1 と違いが出る。ICMP 以外でポートを持たないプロトコル (GRE、ESP) は変えない。

**背景 (Context)**

- `-b` での実測: C のテンプレート 1025 (IPv4 ICMP) と 2049 (IPv6 ICMP) は末尾に
  逆方向の icmpTypeCode (2 バイト) を持つ。Rust にはない (18 フィールドと
  17 フィールド。レコードは 2 バイト短く、2049 では 74 バイトと 72 バイト)。
- C では ICMP が biflow になることはない。type/code がフローキーに入るので、
  echo request と echo reply (type/code が違う) は別フローになり、対にならない。
  逆方向のフィールドに意味のある値が入ることはない。それを持たない Rust の
  テンプレートは妥当で、コピーしても、データを運べないフィールドをコピーする
  だけである。
- ただし compat テストの `-b` ケースのデータグラムサイズには影響する
  (例: `smoke6 -v 10 -a -b` は C 1408 バイト、Rust 1380 バイト)。

### D22. `-m` による過負荷の追い出し (実測、ソース)

**目的 (Goal)**

フローテーブルが `-m` を超えたとき、C と同じまとまりで追い出して export し、
同じデータグラムとヘッダ時刻にする。

**受け入れ基準 (Acceptance Criteria)**

1. compat テストの pcap `smoke`、`smoke6`、`vlan`、`slow`、`many`、`loopback` で、
   `-m 5` と `-t maxlife=1 -m 7`、`-v 1`、`-v 5`、`-v 9`、`-v 10` について、
   `--strict` でデータグラム数とバイト列が C と同一 (D12 基準 2 のフィールドは
   マスク)。
2. データグラムのヘッダ時刻 (NetFlow v1 と v5: sys_uptime と unix_nsecs、
   v9 と IPFIX: export time) が C と同じ。例: `http.cap -v 5 -a -m 5`
   (修正前は C 0x154 ms、Rust 0x12c ms)。
3. 統計の `Flows expired` と `maxflows` の行が C と同じ。
   `flows_force_expired` が同じフローを数える。
4. `-d` で `Forcing expiry of N flows` の行と `Starting expiry scan` の行が
   C と同じ順に出る。
5. D15 の修正は保つ: 追い出したフローは export し、捨てない
   (`test_flow_eviction_exports` が通り続ける)。
6. 単体テスト: 大きさ 5 のテーブルに 1 バッチで 12 フローを足したとき、追い出した
   フローが C と同じ少ないデータグラム数で export される。
7. `tools/softflowd_bench.py` で、この変更が原因の速度低下がない。
8. D10 (追い出したフローがどの flowEndReason を持つか) は同じパッチで決めるか、
   参照を付けて未解消のままにする。基準 1 がこれに依存する。

**背景 (Context)**

- 実測、データグラム数 (C 対 Rust): `many -v 5 -a -m 5` は 120 対 596、
  `many -a -t maxlife=1 -m 7` は 86 対 594、`loopback -v 1 -a -m 5` は 2 対 6、
  `loopback -v 9 -a -m 5` は 6 対 21。`http.cap -v 5 -a -m 5` はどちらも 16
  データグラムだが、ヘッダの byte 7 と 12〜14 (uptime、nsecs) が 40 ms 違う。
  時刻の原因は特定していない。「現在」を取る時点の違いと思われる。
- C (ソース): `softflowd.c:407-410` は 1 回の `pcap_dispatch()` で最大
  `max_flows` 個のパケットを読む。バッチの後 (`softflowd.c:456-476`) に
  `num_flows > max_flows` なら `check_expired()` (`-r` では `CE_EXPIRE_FORCED`) を
  実行し、続いて `force_expire()` が最も古い `num_flows - max_flows` 個のフローに
  `expires_at = 0` と `R_OVERFLOWS` を付け、テーブルが上限を超えなくなるまで
  繰り返す。追い出したフローは 1 回の `check_expired()` で出るので、複数のフローが
  1 データグラムに入る。テーブルは 1 バッチの間だけ `-m` を超えうる。
- Rust (ソース): `capture.rs:342-343` が `len >= max_flows` のとき新しいフローの
  たびに `evict_oldest_flow()` を呼び、すぐに送る (`expire.rs:84-108`、1 フローの
  スライス)。このため追い出しごとに 1 データグラムになる。テーブルは `-m` を
  超えない。`evict_oldest_flow()` は D6 に挙げた `Forcing expiry of N flows` の
  ログを書かない。
- 修正の 2 案: (a) C に従う (dispatch の後のバッチ、追い出したフローを 1 回で送る)。
  バイト単位一致への道。(b) 挿入前の追い出しを残し、1 パケットで追い出した
  フローを 1 回の送信にまとめる。バイト単位一致にはならず、メンテナの判断が
  要る。基準 1 は (a) を前提にしている。
- 関連: D10、D15 (解消: 追い出したフローは export する)、D24。

### D23. データグラムの詰め方 (実測、原因は未特定)

**目的 (Goal)**

C と Rust が v9 または IPFIX のデータグラムを別のレコードで閉じる理由を特定し、
詰め方を同じにするか、差を残す理由を書く。

**受け入れ基準 (Acceptance Criteria)**

1. 原因を特定してこの項目に書く (C のどの判定がどのサイズで止めるか)。
2. 修正または許容。修正の場合は、`http.cap -v 9 -a` と `-v 10 -a` のデータグラムの
   サイズが C と同一。許容の場合は、デコードしたレコードが両者で同じで、
   1428 バイトを超えるデータグラムがなく、ハーネスがサイズの代わりにデコードした
   レコードとレコードの合計を比べる (D12 基準 2)。
3. D12 の詰め方の注記 ("intentional ... 23 records against 22") を結果で置き換える。

**背景 (Context)**

- 実測 (`http.cap -a`): v9 は C 1368 + 68 バイト (最後のデータセットが 3 + 1
  レコード)、Rust 1408 バイト (4 レコード)。IPFIX は C 1356 + 148、
  Rust 1396 + 104。デコードしたテンプレートは同一で、レコード数も同じ。
- どちらも `IPFIX_SOFTFLOWD_MAX_PACKET_SIZE` = 1428 を使う。読んだ C の判定
  (`ipfix_flow_to_flowset()` の `len < data_len * frecnum`) は早く止まる理由を
  説明しないので、旧注記の「意図的」はまだ示されていない。
- `-b` の ICMP ケースのサイズ差は、ここではなく D21 による。

**2026-11-15 の更新 (原因を特定、C 版で修正)。**  C は、biflow でないとき、すべてのフローについて 2 レコード分の空きを要求する。`ipfix_flow_to_flowset()` (`export_template.c`) の `frecnum = bi_flag ? 1 : 2` と `len < data_len * frecnum` で、片方向にしか octets がないフローでも「満杯」を返す。データグラムが最大で 1 レコード早く閉じられていた (v9 の IPv4: 残り 60 バイト、レコード 42 バイト、要求 84 バイト)。Rust は実際のサイズで詰める。メンテナの決定: MTU の許す限り詰める (RFC に規定はない)。C 側を、要求するレコード数を `bi_flag ? 1 : (octets[0] != 0) + (octets[1] != 0)` に変更し、Rust は変更しない。変更後、`http.cap` と `v6-http.cap` (`-v 9`、`-v 10`、`-a`) のデータグラムは (IPFIX の option レコードの PID を除き) バイト単位で一致する。注意: C 版は安定版 1.1.1 と、データグラムの終わる位置 (レコードではない) が変わる。stable 対 dev の比較はデコードしたレコードを比べる。

### D24. expiry scan (ソース、一部実測)

**目的 (Goal)**

C の `check_expired` と Rust の `scan_expiries` が同じフローを選び、同じ debug の
行を書く。

**受け入れ基準 (Acceptance Criteria)**

1. モードは `softflowd.h:191-198` のとおり `0` (通常)、`-1` (全て expire)、
   `1` (強制分のみ) で、ログの行が C と同じ数を出す。
2. `-r` では C と同じく、スキャンが強制分のフローだけを expire する (モード 1)。
3. idle の判定が C と同じ比較 (`expires_at < now`) を使う。
4. compat テストの `-d` ログで `Starting expiry scan` と `EXPIRED` の行の順が
   C と同じ。
5. 3 つのモードと境界の秒の単体テスト。

**背景 (Context)**

- 実測: C が `mode -1` を出す所で Rust は `mode 1` を出す。C が次の
  `Starting expiry scan: mode 1` を出す所で Rust は `EXPIRED` の行を出す。
- ソース: Rust は真偽値の `force_all` (`expire.rs`、0 か 1) なので、「全て
  expire」(C: -1) と「強制分のみ」(C: 1) を区別できない。C は
  `expires_at < now.tv_sec` (`expire.c:217`)、Rust は
  `exp_key.expires_at <= now_sec` (`expire.rs`) で、D9 と同種の境界である。
  実行はしていない。
- 関連: D9、D22。

### D25. パケット統計 (実測)

**目的 (Goal)**

`softflowctl statistics` と終了時の統計の `Packets processed` と
`Ignored packets` が、non-IP と too short のパケットで C と同じになる。

**受け入れ基準 (Acceptance Criteria)**

1. compat テストの 2 件 ("statistics of the packets" の `-v psamp` と `-s 3`) が
   C と同一。
2. non-IP と too short のパケットで、`parse_packet()` とキャプチャループの
   カウンタの単体テスト。

**背景 (Context)**

- 実測: `-v psamp`、non-IP: C は `Packets processed: 240`、`Ignored packets:
  0 (0 non-IP, 0 too short)`。Rust は 235 と `5 (5 non-IP, 0 too short)`。
  `-s 3`、too short: C は 80 と `2 (0 non-IP, 2 too short)`、Rust は 83 と
  `5 (0 non-IP, 5 too short)`。
- 修正: 何を「無視 (ignored)」とするかの規則、サンプリングの順序、および PSAMP パケットのカウントが C と一致するようになった。

### D26. コマンドラインの文言 (実測)

**目的 (Goal)**

コマンドラインのエラーと `-h`/`--help` の文言を C と同じにするか、差を
「許容」と書く。

**受け入れ基準 (Acceptance Criteria)**

1. `PARITY_CLI_ERROR_CASES` の 75 件が標準エラーで同一。残る差は理由を付けて
   ここに「許容」と書く。
2. `-h` と `--help` が C と同じストリームに書く。
3. 終了ステータスは D3 の対象で、ここでは変えない。

**背景 (Context)**

- 実測: 75 件中 75 件で文言が違う。例: 引数なしは C が `-i, -r or -R option not
  specified.`、Rust が `Must specify a packet source (-i or -r).`。`-h` は C が
  標準出力に何も書かず、Rust は clap のヘルプを書く。
- clap は独自のメッセージと終了ステータス 2 を出す。C に合わせるには Rust の
  オプション解析をラップする必要があるかもしれない。D3 と同じくメンテナの判断。
  互換性の基準は getopt 形式の短いオプション。

**変更の設計 (2026-11-15)。** *メンテナが下の A、B、C を選び、その選択をここに書くまで着手しない。* 最初の段階は小さなモデルではなく Claude が行う。

75 ケースについて、C と Rust の 1 行目と終了ステータスを正確に並べた表が `rust/doc/CLI-PARITY-CASES.md` (生成物。75 件中 22 件は既に同じ)。違い: (1) clap が拒否するコマンドラインで Rust の終了ステータスは 2 (C は 1。D3)、(2) 文言 (`./softflowd: invalid option -- 'z'`、`option requires an argument -- 'i'`、`Packet source already specified.`、`-i, -r or -R option not specified.`)、(3) `-h` と `--help` は clap のヘルプを標準出力に出す。C は `Usage: ...` を標準エラーに出し、終了ステータス 0。

選択肢: **A** clap を残してエラーを翻訳する。`Command::try_get_matches_from`、`ErrorKind::UnknownArgument`、`MissingValue`、`ArgumentConflict`、`InvalidValue` を C の文言に対応づけて終了ステータス 1 で終わる関数を作る。`-h`/`--help` は C の usage (`options.c` の `usage()` のコピーに Rust の追加分) を標準エラーに出して 0 で終わる。**B** getopt_long 風の小さな解析器を書く。正確だが大きな変更 (メンテナは小さな diff を好む)。**C** 差を許容する (ゲートで D26/D3 を許容にする)。Claude は **A** を推奨する。`-h` だけなら C も許容できる。

*ゲート:* 完了したら `D26` と `D3` の登録を削除する。

**メンテナの決定 (2026-11-15): 混合案。** (1) D3 は直す: 終了ステータスは 1 (`opts.rs` の `parse_args_or_exit()`、`rsoftflowd` と `rsoftflowctl`)。(2) メッセージの文言と `-h`/`--help` は当面許容する (clap のメッセージのまま) が、**すべてのケースを `tools/gate_expected.json` に 1 件ずつ登録する** (D26 は 65 件。広い正規表現は使わない)。新しい差は UNEXPECTED の行になる。(3) 文言を許容する前に文法をテストする: `PARITY_CLI_ERROR_CASES` に 20 ケースを足した (D34)。後で文言を C に合わせる (上の選択肢 A) こともできる。直したケースの登録は STALE になり、ゲートが登録の削除を求める。

### D27. `-g -M` の CPU clock の行 (実測) - 解消 (2026-11-15)

**目的 (Goal)**

`-M` 付きの `-g` が C と同じ行を出す。

**受け入れ基準 (Acceptance Criteria)**

1. compat の "cpu clocks of -g -M" が C と同じ行になる (値は性質上違う。行の
   組と形式は同じにする)。
2. "cpu clocks of -g" は MATCHED のまま。

**背景 (Context)**

- 実測: `-M` 付きの C は合計 (1228) だけ。Rust は合計 (455) と
  `cpu clocks (export): 8 (1 calls)`。`-M` なしでは両方とも 2 行を出す。

**変更の設計 (2026-11-15、実装者向け)。**

*ファイル:* `rust/src/bin/rsoftflowd.rs` の `main` の末尾 (`if tracker.param.gauge_clock {`)。

*C の動作* (`softflowd.c:535-545`): `cpu clocks: N` を出し、`-M` があれば `cpu clocks (export): n/a with threaded export` を出す。`-M` がなければ `cpu clocks (export): N (K calls)` を出す。Rust は `-M` (`args.use_thread`) を受け付けるが、呼び出したスレッドで export し、常に数値を出す。

*変更:* `if tracker.param.gauge_clock` のブロックで、`args.use_thread` が真なら `cpu clocks (export): n/a with threaded export` を出し、偽なら今の行を出す。他は変えない (`eprintln!` のまま。出力先はこの項目の対象外)。

*テスト:* `rust/tests/integration_tests.rs` に統合テストを追加する。`rsoftflowd -r <pcap> -g -M -n 127.0.0.1:<port>` を実行し、標準エラーに `cpu clocks (export): n/a with threaded export` があり `calls)` がないこと。`-M` なしでは `calls)` があること。旧コードで失敗する。

*ゲート:* `tools/gate_expected.json` の `D27` の登録を削除する。compat の "cpu clocks of -g -M" ("live on lo, cpu clocks of -g -M" も) が MATCHED で、"cpu clocks of -g" は MATCHED のまま。両方の文書で D27 の行を `解消` にする。

### D28. control socket の応答とシグナル (2026-11-02 に実測、一部再測定) - 解消 (2026-11-15)

**目的 (Goal)**

`exit` と `shutdown` の応答、および SIGHUP、SIGINT、SIGTERM、SIGUSR1 のログの
行が C と同じになる。

**受け入れ基準 (Acceptance Criteria)**

1. compat の control socket 応答 (`exit`、`shutdown`) と `lo` の live 項目
   (SIGHUP、SIGINT、SIGTERM、SIGUSR1) が C と同一。
2. `daemon` の項目 (権限、syslog) を `/var/empty` があり `/dev/log` がない
   マシンで実行し、結果をここに書く。

**背景 (Context)**

- 2026-11-15 の実測: SIGINT で C は `Shutting down on user request` だけを
  ログに出し、Rust は `Shutting down complete, exiting.` を足す。他のシグナルと
  応答は 2026-11-02 の実測で、詳しくは再実行していない。
- `daemon` の項目は 2026-11-15 にはスキップした。

**変更の設計 (2026-11-15、実装者向け)。** 6 つの小さな編集で、それぞれ 1 行から数行。編集のたびに、下に挙げる compat の項目を実行する。

1. *`timeouts` の応答* (`rust/src/control.rs`、`tcp = 3600 ...` を書く所): C の 8 行 (`stats.c:258-267`) をそのまま書く (`%d` は秒。前の文字列は右端をそろえる空白つき):
```
           TCP timeout: 3600s
  TCP post-RST timeout: 120s
  TCP post-FIN timeout: 300s
           UDP timeout: 300s
          ICMP timeout: 300s
       General timeout: 3600s
      Maximum lifetime: 604800s
       Expiry interval: 60s
```
   応答は `softflowd[PID]: Printing timeouts:` と pid で始まる (今もそうなっている)。プログラム名はハーネスが期待するまま。
2. *`shutdown` コマンド*: ログ行 `Shutdown command received.` を削除する (`rsoftflowd.rs` の 363 行付近)。C は最後に `Shutting down on user request` (WARNING) を 1 回だけ出す。
3. *`exit` コマンド*: `Exit command received.` を削除し、すぐ終了する所で `log::warn!` で `Exiting immediately on user request` を出す (C: `softflowd.c:493`)。
4. *最後の行*: `log::info!("Shutting down complete, exiting.")` (`rsoftflowd.rs` の 521 行付近) を削除する。C はここで何も書かない。
5. *SIGHUP*: 文言は `SIGHUP received (config reload not implemented)` (C: `softflowd.c:388`)。Rust は `SIGHUP received, re-opening logs (not implemented yet)`。
6. *SIGUSR1* (実バグ): Rust は扱っておらず、既定の動作でプロセスが終了する。他のシグナルと同じように登録し (`signal_hook::flag::register(SIGUSR1, ...)`、`rsoftflowd.rs` の 60 行付近)、メインループでフラグが立っていたら、info レベルで `stats: tracked=<テーブルのフロー数> total_packets=<パケット数>` を出す (C: `softflowd.c:377-384`、`%u` と `%llu`)。

*テスト:* (a) `timeouts` の文言の単体テスト、(b) 統合テスト: `rsoftflowd -d -r <ファイル> ...` を起動し、SIGUSR1 を送って、プロセスが生きていてログに `stats: tracked=` があること、(c) compat の項目 "control replies ending with shutdown / exit"、"the log of the shutdown command"、"the log of the exit command"、"live on lo, SIGINT / SIGTERM"。ハーネスに SIGUSR1 と SIGHUP の項目を足す (後の「追加するテスト」を参照)。

*ゲート:* 3 つの `D28` の登録を削除する。D28 の行を `解消` にする。

### D29. 起動ログの順序と、root での余分な行 (実測、Rust のバグ)

**目的 (Goal)**

`-d` のとき、標準エラーの最初の数行が、root でも root でなくても C の順序になる。

**受け入れ基準 (Acceptance Criteria)**

1. `cargo test --test integration_tests test_d6_logging_stderr_first_four_lines` が、
   一般ユーザーでも root でも、100 回繰り返して通る。
2. C が書かない所で `Dropped privileges to nobody` を書かない (または差をここで
   許容する)。

**背景 (Context)**

- 実測: テストは root で、最初の行が `Shutting down after pcap EOF` になって
  失敗する。`rsoftflowd -d -r FILE -n 127.0.0.1:9` は `Shutting down after pcap
  EOF`、`Dropped privileges to nobody`、`rsoftflowd v0.1.0 starting data
  collection` …の順に出す。C は `starting data collection` が最初。
- ソース: `-r` のキャプチャスレッドは、`run_main_loop()` が
  `starting data collection` を書く (`rsoftflowd.rs:354`) より前に起動し、
  短いファイルの終わりで `Shutting down after pcap EOF` (`capture.rs:159`) を
  書く。順序は競合で決まる。`drop_privileges()` (`rsoftflowd.rs:82`) は root の
  ときだけログを書く。
- 競合は root に依存しないので、CI でも失敗しうる。

### D30. シャットダウン時にテーブルに残ったフローが export されなかった (実測、Rust のバグ)

**目的 (Goal)**

SIGINT、SIGTERM、`softflowctl shutdown` のとき、C と同じく、テーブルの全フローを
export してから終了する。

**受け入れ基準 (Acceptance Criteria)**

1. compat の "live on lo, burst over -m 10" で、`-m 10` でもそれより大きい `-m` でも、
   60 件中 60 件が 1 回ずつ export される。
2. ログに `Shutting down on user request` が 1 回出る。

**背景 (Context)**

- 実測: `-m 100` で 60 フローのとき export は 0 件 (`-m 10` では 50 件)。テーブルが
  満杯になって押し出されたフローだけが出ていた。
- 原因: コミット `75afd87` がメインループの先頭に、シャットダウンのフラグを消して
  `break` する判定を足した。全フローを export するコードはループの末尾にあり、
  到達しなくなった。この判定を削除し、末尾で要求を処理する。余分な行
  `Signal received, shutting down.` もなくなる (D28 を参照)。

### D31. 両端が同じアドレス (実測、ソースは未読)

**目的 (Goal)**

同じアドレス間 (例: `127.0.0.1` のポート 53 と `127.0.0.1` のポート 40000) の
両方向のパケットを、C と同じく 1 つの Biflow にする (RFC 5103)。

**受け入れ基準 (Acceptance Criteria)**

1. compat の pcap `loopback` が、`-v 1`、`-v 5`、`-v 9`、`-v 10`、さらに `-b`、`-m 5`、
   `-t maxlife=1 -m 7` でも、C と同じデータグラムになる。
2. `loopback` の `-D` ログが C と同一。
3. 同じアドレスの 2 パケット (ポート 53 から 40000 と、その逆) が、両方向を持つ
   1 フローになる単体テスト。

**背景 (Context)**

- 実測 (`loopback -v 9 -a -D -m 5`): C は `EXPIRED: [127.0.0.1]:53 <>
  [127.0.0.1]:40000 octets>:177 packets>:4 octets<:177 packets<:4`。Rust は 2 つの
  フローで `octets<:0`。
- Rust のフローキーは、アドレスが等しいときに方向を決めない。C は決める
  (C と C++ の同一アドレス Biflow)。
- `loopback` のケースのデータグラム数の差は、D22 ではなくこれによる。

### D32. IPFIX の option data レコードが `-e` を無視する (実測)

**目的 (Goal)**

`-e ADDRESS` を、C と同じく IPFIX の option data レコードに書く。IPv4 アドレスなら `exporterIPv4Address` (130) と `originalExporterIPv4Address` (403)、IPv6 アドレスなら `exporterIPv6Address` (131) と `originalExporterIPv6Address` (404)。他のフィールドはゼロ。

**受け入れ基準 (Acceptance Criteria)**

1. compat の `-v 10 -a -e 192.0.2.1` が、全 pcap で C と同一 (PID を除く)。
2. 新しい compat 項目 `-e 2001:db8::1` (IPv6) が C と同一。先に C で実行し、option レコードをデコードして (`analysis-tools/dec.py`)、どの 4 フィールドにアドレスが入るかを確認する。
3. `exporter_ip` がある場合 (v4 と v6) とない場合の option data レコードの単体テスト。旧コードで失敗する。
4. `tools/gate_expected.json` の `D32` の登録を削除する。

**背景 (Context)**

- 実測 (`http.cap -v 10 -a -e 192.0.2.1`): 最初のデータグラムの byte 380〜383 と 400〜403。C は `c0 00 02 01`、Rust はゼロ。
- ソース: `rust/src/exporter/export.rs` の `send_ipfix_flows()`。interfaceName の後に `packet.extend_from_slice(&[0u8; 40]);` (4 + 16 + 4 + 16 バイト) を書いている。`enc_exporterAddress()` (253 行) はアドレスを書く方法を知っているが、ここでは使われていない。C は `export.c` の `enc_exporterAddress()` が、合う種類の最初のアドレスを書く。
- *変更:* 40 個のゼロを、option template の順 (130/4、131/16、403/4、404/16) の 4 フィールドに置き換え、それぞれ上の規則で埋める。


### D33. `-b` と `-H`、`-T ether` (実測、未分析)

**目的 (Goal)**

`-H` と `-T ether` を使った Biflow の差を見つけて取り除く。

**受け入れ基準 (Acceptance Criteria)**

1. 下の 2 つの差のそれぞれの原因をここに書く。
2. compat の `-b -T ether -H 02:00:00:00:00:01` (v9 と IPFIX) が C と同一。残す差は理由を付けて「許容」と書く (その場合ゲートに「許容」の登録を作る)。
3. ゲートの `D33` の登録を削除するか、「許容」に変える。

**背景 (Context)**

- v9 (`smoke -v 9 -a -b -T ether -H 02:00:00:00:00:01`): データグラムのサイズは同じ。1 レコードにつき 1 バイト違う (offset 505、621、…。間隔はレコード長 116)。逆方向の MAC アドレスのフィールド (template 1024 の `sourceMacAddress` と 57 番のフィールド) の最後のバイトが、C は `00`、Rust は `02`。`-H` で指定したアドレスを、C がゼロを書く方向に使っている (またはその逆) ように見える。
- IPFIX (`-v 10 -a -b -T ether -H ...`): データグラムのサイズが違う (C 1384 と Rust 1428、C 1368 と Rust 1412、C 1364 と Rust 1416)。template かレコードが違う。一部は許容した D21 (ICMP の template) かもしれない。まず template のセットを調べる (`dec.py`)。
- まだ読んでいないもの: C (`packet.c`、`flow.c`) と Rust で `-H` (`--direction-mac`) が方向をどう決めるか。この項目は Claude が行う。


### D34. コマンドラインの文法 (実測。あいまいな数値を除き解消、数値は許容)

**目的 (Goal)**

C が受理するコマンドラインは、Rust が意図的に厳しくしている所を除き、同じ効果で Rust も受理する。

**受け入れ基準 (Acceptance Criteria)**

1. `PARITY_CLI_ERROR_CASES` の文法ケース 20 件で、受理と拒否が C と同じ。
2. 残る差は、あいまいな数値 (`-v 09`、`-m 5x`、`-m " 5"`、`-I`、`-s`、`-B`、`-C`、`-R` の不正な値。C は `atoi` のように読む) で、ゲートに「許容」(D34) として 1 件ずつ登録する。

**背景 (Context)**

- ケースで見つかったもの: (a) 長いオプションの一意な接頭辞 (`--rea FILE`): C は受理し、clap は受理しなかった。`infer_long_args` で解消。(b) オプションの前のフィルタ (`udp -r FILE -n ...`): C は引数を並べ替え
、clap は最初の単語以降をすべてフィルタとした。`trailing_var_arg` を外して解消。(c) `-n` の 2 回指定: C は最後を使い、clap は拒否した。`overrides_with` で解消。(d) あいまいな数値: 以前の決定 (`-I abc` と同じ) のとおりコピーしない。
- C の `-n` はコンマ区切りのリストも取る (`options.c`)。ここではテストしていない。


### D35. 受理される実行: 標準エラーのログと統計 (実測、未分析)

**目的 (Goal)**

前景でファイルを読む実行が、C と同じ行を標準エラーに書く。

**受け入れ基準 (Acceptance Criteria)**

1. ゲートの D35 の 18 ケース (文法とオプションのケースのうち受理される実行) が C と同一。
2. ゲートの `D35` の登録を削除する。

**背景 (Context)**

- 実測: `softflowd -r FILE -n 127.0.0.1:9` は、`-d` なしで標準エラーに `softflowd v1.1.1 starting data collection`、`Exporting flows from ...`、`Shutting down after pcap EOF`、`Shutting down on user request` を書く。`rsoftflowd` は何も書かない。他のケースで最初に違う行は統計のブロック (`Accumulated statistics since ...` と `Number of active flows`)。
- まだ読んでいないもの: Rust の既定のログレベル (`rsoftflowd.rs` の `env_logger` か syslog の設定) と、C が前景のログを標準エラーに出すと決める所 (`log.c`)。D26 の姿を決めるので、この項目を先に Claude が行う。


### D36. live キャプチャの idle expiry (実測、未分析)

**目的 (Goal)**

idle のフローを、C と同じ時刻 (compat の項目が許す秒の範囲) で export する。

**受け入れ基準 (Acceptance Criteria)**

1. compat の "live on lo, idle expiry (-t expint=3)" が、20 回中 20 回 MATCHED。
2. ゲートの `D36` の登録 (flaky の印つき) を削除する。

**背景 (Context)**

- 実測 6 回: `A 3.0 秒、B 2.3 秒`、`A 4.0、B 3.2`、`A 3.0、B 2.2`。MATCHED になる回もある (`A 5.0、B 4.9`)。A は常に整数秒で、B は秒の一部だけ早い。
- 原因ではなかったもの: メインループの定期スキャン (C は `next_expire() == 0` のときしかスキャンしないので、同じパッチで削除した)。読むべきもの: C の `next_expire()` と `check_expired()` (`expire.c`) が使う時計と、`rust/src/expire.rs` の `next_expire_is_now()` と `scan_expiries()` の比較、`-t expint` による期限のクラスタ化。この項目は Claude が行う。

## 品質ゲートとテスト (2026-11-15)

### ゲート: `tools/softflowd_test_suite.py gate`

パッチを受け入れてよいかを 1 つのコマンドで答える:

```
tools/softflowd_test_suite.py gate --rust-dir rust -- \
    --a ./softflowd --b rust/target/release/rsoftflowd \
    --ctl-a ./softflowctl --ctl-b rust/target/release/rsoftflowctl \
    --skip-build --skip-cpp --skip-rust --skip-static --skip-direct --skip-psamp \
    --collector python --no-benchmark --no-gauge-clock
```

`softflowd_test.py --strict` を実行し、続いて `rust/` で `cargo fmt --check`、`cargo clippy -D warnings`、`cargo test` を実行して、最後の 1 行に `GATE: PASS ...` か `GATE: FAIL ...` を出す。`--from-log FILE` は保存した出力を判定し、`--report FILE` は JSON を書く。規則は `tools/softflowd_test_gate.py` と `tools/gate_expected.json` にある:

| 分類 | 意味 | ゲート |
|---|---|---|
| accepted (許容) | 意図的に残す差 (D34) | 通る |
| open (未解消) | ここで追跡している既知の差 (D3、D26、D27、D28、D32、D33) | 通る |
| UNEXPECTED | それ以外の差や失敗 | **失敗** |
| STALE | どの行にも当たらない登録 (差が消えた) | **失敗**: 直したパッチが登録を削除する |
| DOCS | この文書の行がない、または `解消` の登録 | **失敗** |

項目を直すパッチは、`gate_expected.json` の登録を削除し、**両方の**文書で項目の行を `解消` にし、旧コードで失敗するテストを足す。他を壊すパッチは UNEXPECTED の行を出す。Claude がパッチを見る手順: (1) `git am` が通る、(2) 項目の登録を削除して `GATE: PASS`、(3) 設計に書いたファイルだけが変わり、diff が小さい、(4) `src/` を戻す (`git stash -- rust/src`) と新しいテストが失敗する、(5) 両方の文書の行が更新されている、(6) コミットメッセージが何をなぜ直したかを書いている。

### 追加するテスト (提案。価値の高い順)

1. **壊れたパケットのコーパス** (D25 のようなバグを見つける): `http.cap`、`v6-http.cap`、`vlan` から、各パケットを 0 バイトから元の長さまですべての長さで切った pcap と、固定の seed でビットを反転した pcap を作る。両方のバイナリに `-v 5`、`-v 9`、`-v 10` で読ませ、export されたレコードと最後の統計が同一で、Rust の終了ステータスが 101 (panic) でないこと。compat のステップ `--fuzz N` として足す。
2. **シャットダウンとシグナル** (D30 のようなバグを見つける): `lo` の live で `-m 10`、`-m 100`、既定の 3 通り。60 フローを送り、SIGINT、SIGTERM、`softflowctl shutdown`、`exit` で止める。export されるレコードが C と同じであること (`exit` では C は何も export しない)。SIGUSR1 (プロセスが生きていること) と SIGHUP も足す。
3. **権限と起動の順序** (D29 の回帰を見つける): root で `-i lo` がキャプチャできる。`-i nonexistent0` は daemon 化する前に終了ステータス 1 で終わる。`-d` の最初の 4 行のログが C の順序で、50 回繰り返しても崩れない (競合)。
4. **golden データグラム**: パッチの前に compat の全 pcap・全オプションのデータグラムを保存し、後で比べる。形式に関係しないパッチは 1 バイトも変えてはならない (`--save-golden DIR` と `--check-golden DIR`)。
5. **速度のガード**: 30 万パケットの pcap で `softflowd_test_suite.py bench` を実行し、Rust が C の 5 倍を超えたら失敗 (今は約 3 倍)。D25 のように別スレッドへ処理を移す変更が測定される。
6. **`-e`、`-H`、`-b` のオプション行列**: 全 pcap で `-b`、`-H`、`-T`、`-e` (v4 と v6)、`-s`、`-A` のすべての組合せを実行する。D32 と D33 は行列にこれらのオプションがあったから見つかった。
7. **CLI の表**: `CLI-PARITY-CASES.md` の 75 ケースを、1 行目だけでなく標準エラーの全体で比べる (D26 の後)。
8. **文書のチェック** (ゲートで実施済み): すべての登録に、open または accepted の行がある。

## リポジトリの状態 (ソース)

状態表の R1〜R8 です。状態は「測定日」時点のものです。

- **R1**: `rust/AGENTS.md` は、Conventional Commits、`unsafe` を使わない、
  `reference/` と goflowd への言及、と書いています。実際は、コミットは
  Conventional Commits ではなく、`unsafe` は使われていて (R7)、
  `rust/reference/` はありません。
- **R2**: `.github/workflows/build.yml` に Rust のジョブがありませんでした。
  Rust のビルドは `compat` の中でしか動きませんでした。
- **R3、R4、R5**: CI に足す検査の当初の値は、`cargo fmt --check` が失敗
  (差分 2444 行)、`cargo clippy --all-targets -- -D warnings` が失敗
  (警告 20 件)、`-D warnings` 付きの `cargo doc` が失敗(`idx:` のリンク未解決)
  でした。`cargo test` は成功(17 件)でした。
- **R6**: `src/bin/rsoftflowd.rs` の `main()` は関数に分割され、targets と
  capture のセットアップはそれぞれ `netsock.rs` と `capture.rs` に移動されました。
- **R7**: `unsafe` は 22 行にあります(`rsoftflowd.rs` 7、`export.rs` 12、
  `psamp.rs` 1、`lib.rs` 1、`net_util_unsafe.rs` 1。コメント中の語を含む
  可能性があります)。
- **R8**: `rust/tests/run_compat_tests.py` (480 行) と `rust/doc/test.ja.md` は
  `tools/softflowd_test.py` の原型でした。両ファイルは削除されたため、
  `rust/` 部分は解消され、`rust/` 外の部分は未解消です。
  `tools/` の他のスクリプトが重複しているかは確認済みで、
  重複しているのは `tools/deprecated/collector.pl` と
  `tools/deprecated/benchmark_export.sh` だけです(`collect` と `bench` に
  置き換え済み)。
- **R9**: CI の `rust` ジョブは最新の stable の Rust を入れ、その clippy に新しい
  lint がありました。ログでは `src/control.rs` と `src/exporter/export_common.rs`
  の `collapsible_if` が出ていました。手元の Rust 1.91.1 では、
  `src/bin/rsoftflowd.rs`(10 か所)の `collapsible_if` と
  `manual_is_multiple_of` も出ました。畳んだ `if` は let chains を使い、
  Rust 1.88 以上が必要です。
- **R10**: R9 のような失敗が、push した後でしか分かりませんでした。既存の
  `.githooks/pre-commit` は C の変更の clang-format だけを検査していました。
  パッチはその検査をそのまま残し、Rust の検査を足します。作業用の clone で、
  clang-format 18 と Rust 1.91.1 で確認しました: 整形されていない C ファイルは
  commit が止まる。整形されていない Rust ファイルも止まる。ドキュメントだけの
  commit では cargo を実行しない。正しい Rust の変更では 3 つの cargo コマンドが
  走って commit される。
