# rsoftflowd

[irino/softflowd](https://github.com/irino/softflowd)(フローベースの
ネットワークモニタ)の Rust による書き直しです。実行ファイルは `rsoftflowd` と
`rsoftflowctl` です。

## 概要

`rsoftflowd` はネットワークインターフェースをプロミスキャスで監視し、
ネットワークフローをセミステートフルに追跡します。フローは NetFlow
バージョン 1、5、9、10 (IPFIX) のデータグラム、または PSAMP として
エクスポートします。IPv6 のフローの追跡と、IPv6 ホストへのエクスポートに
対応しています。

親ディレクトリの C 版が基準で、Rust 版はそれに合わせます(コマンドライン、
エクスポートするデータグラム、制御ソケット)。まだ違う点は、
[doc/DIFFERENCES-FROM-C.ja.md](doc/DIFFERENCES-FROM-C.ja.md) に一覧にして
追跡しています。バージョン番号 (`0.1.0`) は C 版・C++ 版とは独立です。

## 関連プロジェクト: NetFlow コレクタ

NetFlow コレクタが必要なら、関連プロジェクト "flowd"
(http://www.mindrot.org/projects/flowd/) があります。NetFlow に対応した
コレクタなら rsoftflowd でも使えます。

## ビルド

Rust の版は `rust-toolchain.toml` で固定しています。`rust/` で最初に `cargo` を
実行すると rustup が入れます。最低版は Rust 1.88 です。libpcap
(`libpcap-dev`) も必要です。

```sh
cd rust
cargo build --release      # target/release/ に rsoftflowd と rsoftflowctl
```

## 実行ファイル

- `rsoftflowd`: デーモンです。C 版 `softflowd` のオプションを短い形式と長い形式の
  両方で受け付けます(`rsoftflowd -h`)。
- `rsoftflowctl`: 動作中のデーモンの制御ソケットにコマンドを送ります:
  `rsoftflowctl [-c|--control-socket PATH] <command>`。コマンドは `statistics`、
  `dump-flows`、`expire-all`、`shutdown` などです。既定のソケットは
  `/var/run/softflowd.ctl` です。
- `cargo build` はマニュアルページ `man/rsoftflowd.8` と `man/rsoftflowctl.8` を
  書き出します(`build.rs`)。

## 検査とテスト

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`cargo test` は単体テストと `tests/` の結合テストを実行します。
CI(`.github/workflows/build.yml` のジョブ `rust`)がこの 3 つを実行します。

Rust のソースを変える commit のたびに実行するには、clone ごとに 1 回、
リポジトリの最上位で次のコマンドを実行してフックを有効にします。

```sh
git config core.hooksPath .githooks
```

このフックは、ステージした C の変更の clang-format 検査(従来からの検査)も
そのまま行います。`git commit --no-verify` で 1 回の commit だけ省略できます。
CI は実行されます。

## C 版との比較

ツールは `../tools` にあります(Python、標準ライブラリのみ。
[../tools/README.md](../tools/README.md) を見てください)。最上位ディレクトリで
C 版をビルドし(`autoreconf -if; ./configure; make`、`../README.md` を参照)、
上記のとおり Rust 版もビルドしておく必要があります。実行は最上位ディレクトリから
行います。コマンドと違いの一覧は
[doc/DIFFERENCES-FROM-C.ja.md](doc/DIFFERENCES-FROM-C.ja.md) にあります。

**ゲート**は `cargo fmt --check`、`cargo clippy`、`cargo test` と、2 つのビルドの
比較(`softflowd_test.py --strict`)を実行し、報告された違いをすべて
`tools/gate_expected.json` で分類します。最後の行は `GATE: PASS` か
`GATE: FAIL` です:

```sh
tools/softflowd_test_suite.py gate --rust-dir rust -- --a ./softflowd \
    --b rust/target/release/rsoftflowd --ctl-a ./softflowctl \
    --ctl-b rust/target/release/rsoftflowctl --skip-build --skip-cpp --skip-rust \
    --skip-static --skip-direct --skip-psamp --collector python --no-benchmark --no-gauge-clock
```

**壊れたパケットのコーパス**は、加工した pcap を両方のビルドで読み、エクスポート
されたフロー、統計、終了ステータスが一致することと、Rust 版がクラッシュしない
ことを確かめます。既定は短い版で、`--full` で全コーパスを実行します:

```sh
tools/softflowd_test_suite.py fuzz --a ./softflowd --b rust/target/release/rsoftflowd
```

**golden データグラム**は、バイト単位の比較(byte for byte)のステップの全ケースに
ついて Rust 版がエクスポートしたデータグラムを保存し、後のビルドをそれと比較します
(C 版は不要です)。フォーマットに関係しないパッチは 1 バイトも変えてはいけません。
ディレクトリは大きい(1 ケース 1 ファイル)ので、リポジトリの外に置いてください:

```sh
tools/softflowd_test_suite.py --b rust/target/release/rsoftflowd --save-golden DIR
tools/softflowd_test_suite.py --b rust/target/release/rsoftflowd --check-golden DIR
```

ライブキャプチャの検査(シグナル、シャットダウン、起動順)は root が必要で、
root でないと SKIPPED になります。

## 開発

規約(コメント、コミットメッセージ、パッチ)は [AGENTS.md](AGENTS.md) を
見てください。
