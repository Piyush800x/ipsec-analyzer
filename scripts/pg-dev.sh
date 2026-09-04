#!/usr/bin/env bash
# A throwaway PostgreSQL for local dual-backend testing.
#
# LLD 4.1 requires the database layer to behave identically on PostgreSQL and
# SQLite, and tests/conftest.py runs every database test against both -- but it
# skips the PostgreSQL half unless TEST_POSTGRES_URL points somewhere. This
# starts a container to point it at.
#
#   ./scripts/pg-dev.sh up      # start (idempotent)
#   ./scripts/pg-dev.sh url     # print the URL to export
#   ./scripts/pg-dev.sh down    # stop and remove
#
#   export TEST_POSTGRES_URL="$(./scripts/pg-dev.sh url)"
#   cd backend && uv run pytest
#
# Port 55432, not 5432, so it cannot collide with a real PostgreSQL you rely on.
set -euo pipefail

NAME=ipsec-analyzer-pg
PORT=55432
IMAGE=postgres:16-alpine
URL="postgresql+asyncpg://analyzer:analyzer@localhost:${PORT}/analyzer_test"

case "${1:-up}" in
  up)
    if [ -n "$(docker ps -q -f "name=^${NAME}$")" ]; then
      echo "${NAME} already running"
    else
      docker rm -f "$NAME" >/dev/null 2>&1 || true
      docker run -d --name "$NAME" \
        -e POSTGRES_USER=analyzer \
        -e POSTGRES_PASSWORD=analyzer \
        -e POSTGRES_DB=analyzer_test \
        -p "${PORT}:5432" "$IMAGE" >/dev/null
      echo "started ${NAME} on port ${PORT}"
    fi
    for _ in $(seq 1 90); do
      if docker exec "$NAME" pg_isready -U analyzer -h 127.0.0.1 -q 2>/dev/null; then
        echo "ready"
        echo ""
        echo "  export TEST_POSTGRES_URL=\"${URL}\""
        exit 0
      fi
    done
    echo "timed out waiting for ${NAME}" >&2
    exit 1
    ;;
  url)
    echo "$URL"
    ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "removed ${NAME}" || echo "${NAME} not running"
    ;;
  *)
    echo "usage: $0 [up|url|down]" >&2
    exit 2
    ;;
esac
