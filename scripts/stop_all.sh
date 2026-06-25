#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/scripts/stop_api.sh" || true

cd "$ROOT_DIR/docker"
docker compose stop pgvector
