# Gemini Issue Agent

A GitHub Issue starts a coding agent (Gemini) for the Rust version (`rust/`).
It was ported from https://github.com/irino/netsim and changed for this
repository (see "Differences from netsim").

## Flow

1. The maintainer creates an Issue with the form "AI coding task"
   (label `ai-task`). A comment `/retry` on that Issue runs it again.
2. The workflow `gemini-issue-agent.yml` starts Gemini. Gemini can only list,
   read and write files; it cannot run commands.
3. The workflow runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
   and `cargo test` in `rust/`. On a failure it gives the log to Gemini and
   tries again, up to three repair rounds.
4. A second job checks the patch, pushes the branch `ai/issue-N-gemini` and
   opens a pull request. It is never merged automatically.

## Setup (once)

- Secret `GEMINI_API_KEY` (Settings, Secrets and variables, Actions).
- Setting "Allow GitHub Actions to create and approve pull requests"
  (Settings, Actions, General).
- A label named `ai-task`.
- Optional: secret `AI_PR_TOKEN`, a fine-grained token with Contents and
  Pull requests write access to this repository. A pull request that is opened
  with the default token does not start `build.yml` (a rule of GitHub). With
  the token, the CI of the repository (including the comparison with the C
  version) runs on the pull request.
- The models and their limits are in `.github/gemini-models.json`; the agent
  tries them in order.

## What protects the repository

- Only the owner of the repository can start it (the label or `/retry`).
- The text of the Issue is treated as untrusted data.
- Gemini may read every visible file (the C version is the reference) and
  may write only under `rust/`; never `rust/target/` and never
  `rust/rust-toolchain.toml`. Hidden paths (`.github/`, `.githooks/`, ...) are
  closed to it. The script and the patch check both enforce this.
- The checks run the code of the agent (tests, `build.rs`), so they run in an
  environment without `GEMINI_API_KEY` and the token. The job that has the
  push rights only applies the patch; it never runs that code.
- A patch larger than 250000 bytes is rejected.

## What it does not check

The loop checks the format, clippy and the unit and integration tests only.
It does not compare the output with the C version. Run
`tools/softflowd_test_collector.py compat` (see
`rust/doc/DIFFERENCES-FROM-C.en.md`) or let `build.yml` run on the pull
request, and review the diff before the merge.

## Writing an Issue

Give one fix per Issue, in English:

- Goal: the behavior to implement or fix, with the C file and function to
  follow.
- Acceptance criteria: observable conditions, such as a test that fails now
  and passes after the change, and the row of
  `rust/doc/DIFFERENCES-FROM-C.en.md` to update.
- Context: the files in `rust/` that are concerned, and what not to do.

## Differences from netsim

- The Rust toolchain is the version of `rust/rust-toolchain.toml`, installed
  with rustup; no third-party action is used for it.
- The checks run in `rust/` with the three commands of `build.yml`.
- The checks run without the secrets in their environment.
- The agent may write only under `rust/`; the patch check enforces it.
- The commit message is the title of the pull request, without a prefix.
- `AI_PR_TOKEN` is optional, so that the CI runs on the pull request.
- The prompt names the rules of `rust/AGENTS.md`.
