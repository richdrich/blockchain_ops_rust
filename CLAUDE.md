# Project Guidelines

## Issue conventions

- Provide acceptance criteria / deliverables.
- Before the issue is ready to code, describe a solution.
- When creating a sub-issue (child of an epic or parent issue), set its milestone to match the parent issue's milestone.

## Test structure (rust)

- Put Rust unit and integration tests in the `tests` directory, in a subfolder matching the `src` subfolder (e.g. tests for `src/api` go in `tests/api`).
- Do not put tests inline with the code — keep them in the test tree (Java-style).
- Mark all tests with `#[test]` and use a separate `#[cfg(...)]` attribute where needed so that IntelliJ can discover them.
- Ensure all tests are referenced in `Cargo.toml`.

## Code conventions (rust)

- Do not use default values on traits outside test-only code. Defaults on traits may be used for testing, but must panic if called in non-test code.
- All state should be in a struct, not global or thread-local, except in very special cases — ask before using global or thread-local storage.
- Always validate that a call returning `Option` succeeds before using the value.

## Code conventions (generic)

- Do not prefix an in-use parameter name with `_` — that prefix signals an intentionally unused parameter.
- Do not use Title Case in comments.
- Expand acronyms on first use in documents.
- Shell commands in docs should be a single line to ease cut/paste/edit.

## Worktrees

- The repository root checkout holds the canonical branch (`master`) and must not be altered directly.
- Do all development in a worktree — the worktree is the prime working checkout.

## Files

- Create temp and output files (logs, etc.) in `tmp/` so they are gitignored.

## Continuous integration (GitHub Actions)

- Actions must run on the Node 24 runtime — Node 20 is end of life (EOL). Pin every action to a major version whose runtime is `node24` (e.g. `actions/checkout@v5`) so no Node 20 deprecation warnings appear. Composite (shell) actions have no Node runtime and are exempt.
- Every workflow must set a `concurrency` group with `cancel-in-progress: true` so a superseded run for the same ref is cancelled and stale runs do not pile up.

## Before creating a PR

1. Run `cargo test` for the workspace and verify all tests pass with no warnings.
2. Ensure the `blockchain_ops` and `algo_ops` crates build (`cargo build`).
3. Ensure `cargo clippy --workspace --all-targets` and `cargo fmt --check` pass.
4. Build the docs with warnings denied — `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` — so broken or private intra-doc links fail locally rather than in continuous integration. Continuous integration runs this and treats warnings as errors.

## Git notes

- While still modifying a PR, keep it in draft until it is ready for review/merge.
- When the PR is complete and meets all requirements, mark it ready for review/merge.
- Any PR that is not a draft must target the repository's default branch. Keep stacked work in draft with its feature-branch base until that base merges, then retarget the PR to the default branch and mark it ready. A ready PR based on another feature branch merges into that branch — not the default branch — so the work shows as merged on GitHub yet silently never reaches it. Continuous integration can enforce this with a default-branch check.
- Do not commit without asking for review.
