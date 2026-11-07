#!/usr/bin/env bash
# Runs the tests against a throwaway Postgres.
#
# It starts a new Postgres container that has no volume and listens only
# on a random local port, runs the tests against it, and removes it. It
# never connects to any other database on this machine.
#
# Usage: scripts/test.sh [go test flags]
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="${AOS_TEST_POSTGRES_IMAGE:-postgres:15-alpine}"
NAME="aos-test-pg-$$"

docker run -d --rm --name "$NAME" -e POSTGRES_PASSWORD=test -p 127.0.0.1::5432 "$IMAGE" >/dev/null
trap 'docker stop "$NAME" >/dev/null 2>&1 || true' EXIT

PORT="$(docker port "$NAME" 5432/tcp | head -n 1 | sed 's/.*://')"

# Wait for the server that accepts network connections. The image first
# runs a short-lived setup server that listens on a socket only.
for _ in $(seq 1 200); do
  if docker exec "$NAME" pg_isready -U postgres -h 127.0.0.1 -q 2>/dev/null; then
    break
  fi
  sleep 0.2
done

export AOS_TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:${PORT}/postgres?sslmode=disable"

# -p 1: packages run one after another. Each creates the same two
# database roles, and two migrations at once would trip over each other.
go test -p 1 "$@" ./...
