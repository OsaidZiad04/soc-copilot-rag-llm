#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT_DIR/.run/api.pid"
BRIDGE_PID_FILE="$ROOT_DIR/.run/bridge.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "API is not running (no PID file)."
  exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
  kill "$PID"
  sleep 1
  if kill -0 "$PID" 2>/dev/null; then
    kill -9 "$PID" || true
  fi
  echo "API stopped (PID $PID)."
else
  echo "API process not found (stale PID file)."
fi

rm -f "$PID_FILE"

if [[ -f "$BRIDGE_PID_FILE" ]]; then
  BRIDGE_PID="$(cat "$BRIDGE_PID_FILE")"
  if kill -0 "$BRIDGE_PID" 2>/dev/null; then
    kill "$BRIDGE_PID"
    sleep 1
    if kill -0 "$BRIDGE_PID" 2>/dev/null; then
      kill -9 "$BRIDGE_PID" || true
    fi
    echo "Ollama bridge stopped (PID $BRIDGE_PID)."
  else
    echo "Ollama bridge process not found (stale PID file)."
  fi

  rm -f "$BRIDGE_PID_FILE"
fi
