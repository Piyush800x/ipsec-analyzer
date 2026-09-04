#!/usr/bin/env bash
# Runs the same checks as .github/workflows/ci.yml, so "green locally" means
# "green in CI". Keep the two in step: if you add a CI step, add it here.
#
#   ./scripts/ci-local.sh            # backend + frontend
#   ./scripts/ci-local.sh backend    # backend only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-all}"
fail=0

run () {
  echo ""
  echo "--- $1 ---"
  shift
  if "$@"; then
    echo "PASS"
  else
    echo "FAIL (exit $?)"
    fail=1
  fi
}

if [ "$TARGET" = "all" ] || [ "$TARGET" = "backend" ]; then
  cd "$ROOT/backend"
  run "ruff check"          uv run ruff check .
  run "ruff format --check" uv run ruff format --check .
  run "mypy"                uv run mypy
  run "pytest"              uv run pytest
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "frontend" ]; then
  cd "$ROOT/frontend"
  run "tsc --noEmit" npx tsc --noEmit
  run "eslint"       npm run lint
  run "next build"   npm run build
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "CI-LOCAL: FAILED"
  exit 1
fi
echo "CI-LOCAL: PASSED"
