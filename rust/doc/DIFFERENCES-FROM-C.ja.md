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
| D3 | コマンドラインのエラー: 75 件中 47 件が違う | 2026-11-02 | 未解消 | | |
| D4 | ntopng がない | 2026-11-02 | 解消 | ntopng へのエクスポート (-v ntopng) をオプションの Cargo 機能として追加 | 2026-11-02、統合テストが成功 (機能有効時); -v ntopng-json は未移植 |
| D5 | プログラム名とバージョンが揃っていない | 2026-11-02 | 解消 | 0016 別名バイナリを削除 | 2026-11-02、cargo build で rsoftflowd と rsoftflowctl のみ生成されることを確認 |
| D6 | ログの形式が違う | 2026-11-02 | 未解消 | | |
| D7 | PSAMP レコードが違う (未測定) | 2026-11-02 | 未解消 | | |
| D8 | compat のステップ 5 に未到達 (未測定) | 2026-11-02 | 解消 | 0011 Use the same templates for NetFlow v9 as for IPFIX | 2026-11-02、ステップ 5 が初めて動いた(結果は D12) |
| D9 | 最大寿命: C は `>`、Rust は `>=` で比較 | 2026-11-02 | 解消 | 0014 Compare the maximum lifetime with > as the C version does | 2026-11-02、単体テスト maximum_lifetime_expiry_boundary が成功 (旧コードでは失敗) |
| D10 | 過負荷での追い出し: C は前の flowEndReason のまま、Rust は lack of resources | 2026-11-02 | 未解消 | | |
| D11 | NetFlow v9 のオプションテンプレート: C は interfaceName (IE 82) を持ち、Rust は持たない | 2026-11-02 | 解消 | 0015 Add interfaceName to the NetFlow v9 option template | 2026-11-02、NetFlow v9 のオプションテンプレートに interfaceName が含まれることを確認する単体テストが成功 (旧コードでは失敗) |
| D12 | compat のステップ 5: バイト単位の比較の大半が違う (本文を参照) | 2026-11-02 | 未解消 | | |
| D13 | コマンドライン (D3 の一部): 不正な `-t` を受理し、大きな時間で panic する | 2026-11-02 | 解消 | 0012 Reject the wrong -t options as the C version does | 2026-11-02、D3 の 75 件を再実行: `-t` の件は C と同じになった(終了ステータスが違うのは 38 件、以前は 47 件)。`parse_duration` と `apply_timeouts` の単体テスト |
| D14 | コマンドライン (D3 の一部): `-T port` が panic する。C は受理する | 2026-11-02 | 解消 | 0013 Accept -T port in the Rust version | 2026-11-02、D3 の 75 件を再実行: panic は残っていない(終了ステータスが違うのは 37 件、以前は 38 件)。レベル名のテスト |
| D15 | 過負荷での追い出し: Rust は追い出したフローを破棄していた (D12 の一部) | 2026-11-02 | 解消 | evict_oldest_flow() で追い出したフローのエクスポートを追加 | 2026-11-02、単体テスト test_flow_eviction_exports が成功 (旧コードでは失敗) |
| D16 | NetFlow v5 の flow_sequence が C 版の2倍の速さで増加する (D12 の一部) | 2026-11-07 | fixed | export_build_flow_header() の NetFlow v5 における flow_sequence を修正 | 2026-11-07, NetFlow v5 のシーケンス番号に関するテストが通過 (旧コードでは失敗) |
| D17 | コマンドライン (D3 の一部): 起動順序や `-n`、`-I`、インターフェイス、BPF フィルタ、制御ソケットの検証が C 版と違う | 2026-11-02 | 解消 | Check options and open capture before daemonizing, and reject bad -n and -I | 2026-11-07, `parse_boot_time_reinit` の単体テスト、デーモン化せずに終了ステータス 1 になる統合テスト |
| R1 | `rust/AGENTS.md` がリポジトリの実態と合わない | 2026-11-02 | 解消 | 0006 Update AGENTS.md and the README of the Rust version to the current policy | 2026-11-02、リポジトリと照合 |
| R2 | CI に Rust のジョブがない | 2026-11-02 | 解消 | 0004 Add a CI job that checks the format, clippy and the tests of the Rust version | 2026-11-02、クリーンな checkout で同じコマンドをローカル実行 |
| R3 | `cargo fmt --check` が失敗する | 2026-11-02 | 解消 | 0002 Format the Rust version with cargo fmt | 2026-11-02、ローカル |
| R4 | `cargo clippy -D warnings` が失敗する (警告 20 件) | 2026-11-02 | 解消 | 0003 Fix the warnings of clippy in the Rust version | 2026-11-02、ローカル |
| R5 | `cargo doc -D warnings` が失敗する | 2026-11-02 | 未解消 | | |
| R6 | デーモンの主処理がバイナリ側にある | 2026-11-02 | 未解消 | | |
| R7 | `unsafe` が 22 行にある | 2026-11-02 | 未解消 | | |
| R8 | `rust/tests/run_compat_tests.py` と `rust/doc/test.ja.md` が tools と重複 | 2026-11-02 | 未解消 | | |
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
python3 tools/softflowd_test_collector.py compat --skip-cpp \
    --collector python --pcap-dir pcaps --no-benchmark --no-gauge-clock
```

出力の最後の組 `A=softflowd vs B=rsoftflowd` が Rust です。
ほかのオプションは `tools/softflowd_test_collector.py` を見てください。

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

Rust は `env_logger` の行(`[時刻 LEVEL rsoftflowd] ...`)を出し、C は
メッセージだけを出します。細かい比較はしていません。

### D7. PSAMP (未測定)

`compat --psamp` のヘルプに、Rust の PSAMP レコードが違うと書かれています。
どこが違うかは一覧にしていません。

### D8. compat テストのステップ 5 (未測定)

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

### D12. バイト単位の比較、compat のステップ 5 (実測)

ステップ 5 は、0011 でステップ 3 が通るようになったため、2026-11-02 に初めて
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
- **R6**: `src/bin/rsoftflowd.rs` は 1056 行で、デーモンの主処理がライブラリ
  でなくバイナリ側にあります。
- **R7**: `unsafe` は 22 行にあります(`rsoftflowd.rs` 7、`export.rs` 12、
  `psamp.rs` 1、`lib.rs` 1、`net_util_unsafe.rs` 1。コメント中の語を含む
  可能性があります)。
- **R8**: `rust/tests/run_compat_tests.py`(480 行)と `rust/doc/test.ja.md` は
  `tools/softflowd_test_collector.py` の原型です(保守者の 2026-11-02 の説明)。
  削除する予定です。`tools/` の他のスクリプトが重複しているかは確認済みで、
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
