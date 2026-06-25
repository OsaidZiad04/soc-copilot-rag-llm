#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/.run"
PID_FILE="$RUN_DIR/api.pid"
LOG_FILE="$RUN_DIR/api.log"
BRIDGE_SCRIPT="$RUN_DIR/ollama_bridge.py"
BRIDGE_PID_FILE="$RUN_DIR/bridge.pid"
BRIDGE_LOG_FILE="$RUN_DIR/bridge.log"
BRIDGE_HOST="${OLLAMA_BRIDGE_HOST:-127.0.0.1}"
BRIDGE_PORT="${OLLAMA_BRIDGE_PORT:-11436}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8001}"

mkdir -p "$RUN_DIR"

if ! curl -fsS --max-time 2 "http://$BRIDGE_HOST:$BRIDGE_PORT/api/tags" >/dev/null 2>&1; then
  if [[ -f "$BRIDGE_SCRIPT" ]]; then
    if [[ -f "$BRIDGE_PID_FILE" ]] && kill -0 "$(cat "$BRIDGE_PID_FILE")" 2>/dev/null; then
      echo "Ollama bridge already running (PID $(cat "$BRIDGE_PID_FILE"))"
    else
      nohup python3 "$BRIDGE_SCRIPT" > "$BRIDGE_LOG_FILE" 2>&1 &
      BRIDGE_PID=$!
      echo "$BRIDGE_PID" > "$BRIDGE_PID_FILE"
      sleep 2
      if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
        echo "Ollama bridge failed to start. Last logs:"
        tail -n 50 "$BRIDGE_LOG_FILE" || true
        exit 1
      fi
      echo "Ollama bridge started on http://$BRIDGE_HOST:$BRIDGE_PORT (PID $BRIDGE_PID)"
    fi
  else
    echo "Ollama bridge script not found: $BRIDGE_SCRIPT"
    exit 1
  fi
fi

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "API already running (PID $(cat "$PID_FILE"))"
  exit 0
fi

cd "$ROOT_DIR/src"
if command -v uvicorn >/dev/null 2>&1; then
  UVICORN_CMD=(uvicorn)
else
  UVICORN_CMD=(python3 -m uvicorn)
fi

nohup "${UVICORN_CMD[@]}" main:app --host "$HOST" --port "$PORT" > "$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"

sleep 3
if ! kill -0 "$PID" 2>/dev/null; then
  echo "API failed to start. Last logs:"
  tail -n 50 "$LOG_FILE" || true
  exit 1
fi

echo "API started on http://$HOST:$PORT (PID $PID)"
echo "Log: $LOG_FILE"
