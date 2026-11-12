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

## 検査とテスト

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI(`.github/workflows/build.yml` のジョブ `rust`)がこの 3 つを実行します。

Rust のソースを変える commit のたびに実行するには、clone ごとに 1 回、
リポジトリの最上位で次のコマンドを実行してフックを有効にします。

```sh
git config core.hooksPath .githooks
```

このフックは、ステージした C の変更の clang-format 検査(従来からの検査)も
そのまま行います。`git commit --no-verify` で 1 回の commit だけ省略できます。
CI は実行されます。

C 版との比較は `tools/softflowd_test.py` です。コマンドは
[doc/DIFFERENCES-FROM-C.ja.md](doc/DIFFERENCES-FROM-C.ja.md) にあります。

## 開発

規約(コメント、コミットメッセージ、パッチ)は [AGENTS.md](AGENTS.md) を
見てください。
