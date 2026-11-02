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
| D1 | NetFlow v9: 追加要素が違う | 2026-11-02 | 未解消 | | |
| D2 | IPFIX の flowEndReason の値が誤り | 2026-11-02 | 解消 | 0007 Fix the flowEndReason values of the Rust version | 2026-11-02、compat `--strict` の C と Rust の比較で、IPv4・IPv6 の pcap とも IPFIX が MATCHED (各 24 レコード) |
| D3 | コマンドラインのエラー: 75 件中 47 件が違う | 2026-11-02 | 未解消 | | |
| D4 | ntopng がない | 2026-11-02 | 未解消 | | |
| D5 | プログラム名とバージョンが揃っていない | 2026-11-02 | 未解消 | | |
| D6 | ログの形式が違う | 2026-11-02 | 未解消 | | |
| D7 | PSAMP レコードが違う (未測定) | 2026-11-02 | 未解消 | | |
| D8 | compat のステップ 5 に未到達 (未測定) | 2026-11-02 | 未解消 | | |
| D9 | 最大寿命: C は `>`、Rust は `>=` で比較 | 2026-11-02 | 未解消 | | |
| D10 | 過負荷での追い出し: C は前の flowEndReason のまま、Rust は lack of resources | 2026-11-02 | 未解消 | | |
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
「Rust は受理」の群では、不正な入力がログに出るだけで、デーモンは動き続けるか
終了 0 で終わります。ほかの 2 群のうち、どれを揃えるか(clap の終了 2 と C の
終了 1)は不具合ではなく方針の判断です。

### D4. ntopng (ソース)

`rust/src` に ntopng への言及がありません。C には `ntopng.c` があります。

### D5. プログラム名とバージョン (ソース)

`Cargo.toml` の `softflowd` と `softflowctl` の別名は、1 行の `include!` です。
バージョンは Rust が 0.1.0 です。usage、syslog の ident、`rust/man/*.8` の
名前はまだ揃っていません。

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
