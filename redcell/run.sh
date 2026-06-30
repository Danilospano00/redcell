#!/usr/bin/env bash
# RedCell launcher. Starts the dashboard and opens the browser.
#   ./run.sh            live demo (calls Regolo)
#   ./run.sh --offline  replay a recorded run from backend/fixtures (no network)
#   PORT=8001 ./run.sh  override the port
set -euo pipefail
cd "$(dirname "$0")"

PORT="${PORT:-8000}"
OFFLINE_ENV=()
if [ "${1:-}" = "--offline" ]; then
  OFFLINE_ENV=(REDCELL_OFFLINE=1)
  echo "▶ OFFLINE mode — replaying fixtures, no Regolo calls"
fi

# free the port if a previous run is still holding it
lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill -9 2>/dev/null || true

cd backend
env ${OFFLINE_ENV[@]+"${OFFLINE_ENV[@]}"} ../.venv/bin/python -m uvicorn main:app --port "$PORT" --log-level warning &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT

# wait for the server to answer, then open the browser
for _ in $(seq 1 40); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 0.3
done
echo "▶ RedCell up at http://127.0.0.1:$PORT/"
open "http://127.0.0.1:$PORT/" 2>/dev/null || true
wait $SRV
