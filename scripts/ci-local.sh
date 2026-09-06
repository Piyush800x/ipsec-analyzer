#!/usr/bin/env bash
# Runs the same checks as .github/workflows/ci.yml, so "green locally" means
# "green in CI". Keep the two in step: if you add a CI step, add it here.
#
#   ./scripts/ci-local.sh            # backend + testbed + frontend
#   ./scripts/ci-local.sh backend    # backend only
#   ./scripts/ci-local.sh testbed    # testbed only (needs Docker + XFRM)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-all}"
fail=0

# Must match testbed.peers.PEER_IMAGE and the tag the CI workflow builds.
PEER_IMAGE="ipsec-testbed-peer:0.1.0"

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

if [ "$TARGET" = "all" ] || [ "$TARGET" = "testbed" ]; then
  # Mirrors the `testbed` CI job. Needs a Docker daemon, a kernel with XFRM,
  # and the peer image built; REQUIRE_TESTBED turns a skip into a failure so
  # that "green" cannot mean "never ran". See backend/testbed/README.md.
  cd "$ROOT/backend"
  run "build peer image"    docker build -q -f testbed/Dockerfile.peer -t "$PEER_IMAGE" testbed/
  run "pytest (testbed)"    env REQUIRE_TESTBED=1 uv run pytest tests/test_testbed_*.py
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "frontend" ]; then
  # Step 6.8: a backend schema change the frontend has not absorbed must fail
  # the build here rather than surface as an undefined in the browser.
  run "gen-types --check" bash "$ROOT/scripts/gen-types.sh" --check
  cd "$ROOT/frontend"
  # `next build` first, and not for speed: Next 16 generates the typed-route
  # definitions under .next/types during a build, so on a clean checkout
  # `tsc --noEmit` fails with ~10 phantom PageProps errors until one has run.
  run "next build"   npm run build
  run "tsc --noEmit" npx tsc --noEmit
  run "eslint"       npm run lint
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "CI-LOCAL: FAILED"
  exit 1
fi
echo "CI-LOCAL: PASSED"
