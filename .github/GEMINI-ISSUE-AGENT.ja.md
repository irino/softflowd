# Gemini Issue Agent

GitHub の Issue から、Rust 版 (`rust/`) のコーディングエージェント (Gemini) を
起動します。https://github.com/irino/netsim から移植し、このリポジトリ向けに
変更しています(「netsim との違い」を参照)。

## 流れ

1. 保守者が Issue フォーム「AI coding task」(ラベル `ai-task`) で Issue を作ります。
   その Issue に `/retry` とコメントすると、もう一度実行します。
2. ワークフロー `gemini-issue-agent.yml` が Gemini を起動します。Gemini は
   ファイルの一覧・読み取り・書き込みだけができ、コマンドは実行できません。
3. ワークフローが `rust/` で `cargo fmt --check`、
   `cargo clippy --all-targets -- -D warnings`、`cargo test` を実行します。失敗
   したらログを Gemini に渡してやり直します(修復は最大 3 ラウンド)。
4. 2 つ目のジョブがパッチを検査し、ブランチ `ai/issue-N-gemini` を push して
   プルリクエストを作ります。自動ではマージしません。

## 設定(最初に 1 回)

- シークレット `GEMINI_API_KEY` (Settings、Secrets and variables、Actions)。
- 設定「Allow GitHub Actions to create and approve pull requests」
  (Settings、Actions、General)。
- 名前が `ai-task` のラベル。
- 任意: シークレット `AI_PR_TOKEN`。このリポジトリの Contents と Pull requests に
  書き込める fine-grained token です。既定のトークンで作ったプルリクエストでは
  `build.yml` が動きません(GitHub の規則です)。このトークンがあると、C 版との
  比較を含むリポジトリの CI がプルリクエストで動きます。
- モデルと上限は `.github/gemini-models.json` にあり、エージェントは順に試します。

## リポジトリを守るしくみ

- 起動できるのはリポジトリの所有者だけです(ラベルまたは `/retry`)。
- Issue の本文は信頼しないデータとして扱います。
- Gemini は見えるファイルをすべて読めます(C 版が基準です)。書けるのは `rust/`
  の下だけで、`rust/target/` と `rust/rust-toolchain.toml` は書けません。隠しパス
  (`.github/`、`.githooks/` など)は使えません。スクリプトとパッチの検査の両方で
  強制します。
- 検査はエージェントが書いたコード(テスト、`build.rs`)を実行するため、
  `GEMINI_API_KEY` とトークンを環境から外して実行します。push の権限を持つ
  ジョブはパッチを当てるだけで、そのコードは実行しません。
- 250000 バイトを超えるパッチは拒否します。

## 確認していないこと

ループで確認するのは、整形、clippy、単体テストと統合テストだけです。出力を C 版と
比べることはしません。`tools/softflowd_test.py`
(`rust/doc/DIFFERENCES-FROM-C.ja.md` を参照)を実行するか、プルリクエストで
`build.yml` を動かし、マージの前に差分を確認してください。

## Issue の書き方

1 つの Issue に 1 つの修正を、英語で書きます。

- Goal: 実装・修正する挙動。従う C のファイルと関数も書きます。
- Acceptance criteria: 観測できる条件。たとえば、今は失敗して変更後に成功する
  テスト、更新する `rust/doc/DIFFERENCES-FROM-C.en.md` の行。
- Context: 関係する `rust/` のファイルと、してはいけないこと。

## netsim との違い

- Rust のツールチェーンは `rust/rust-toolchain.toml` の版を rustup で入れます。
  そのためにサードパーティのアクションは使いません。
- 検査は `rust/` で `build.yml` と同じ 3 つのコマンドを実行します。
- 検査はシークレットを環境から外して実行します。
- エージェントが書けるのは `rust/` の下だけで、パッチの検査でも強制します。
- コミットメッセージは、プレフィックスなしのプルリクエストのタイトルです。
- `AI_PR_TOKEN` は任意で、プルリクエストで CI を動かすためのものです。
- プロンプトで `rust/AGENTS.md` の規則を指示します。
