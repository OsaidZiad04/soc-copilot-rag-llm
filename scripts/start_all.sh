#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR/docker"
docker compose up -d pgvector

"$ROOT_DIR/scripts/start_api.sh"
"$ROOT_DIR/scripts/status_api.sh"
