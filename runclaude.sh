#!/usr/bin/env bash
set -euo pipefail

# Run this Claude session under the bingle_claude GitHub machine account (gh API +
# git commit identity). Token and identity live in a gitignored file outside the
# repo, so nothing secret is committed. GH_TOKEN there overrides the per-directory
# gh account wrapper, pinning the session to the bot regardless of directory.
if [ -f "$HOME/.config/bingle_claude.env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.config/bingle_claude.env"
else
  echo "runclaude.sh: warning: ~/.config/bingle_claude.env not found; using default GitHub identity" >&2
fi

dir=$(basename "$(cd "$(dirname "$0")" && pwd)")
exec claude --dangerously-skip-permissions -w "$dir"
