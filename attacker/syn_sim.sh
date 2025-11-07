#!/bin/sh
# SAFE TCP connect flood simulator (does not forge SYNs) - low-rate by default
TARGET=${TARGET:-web_server}
PORT=${PORT:-8000}
INTERVAL=${INTERVAL:-0.2}
BATCH=${BATCH:-5}
while true; do
  for i in $(seq 1 $BATCH); do
    timeout 2 sh -c "echo > /dev/tcp/$TARGET/$PORT" 2>/dev/null && echo "$(date) CONNECT OK $TARGET:$PORT" || echo "$(date) CONNECT FAIL $TARGET:$PORT"
  done
  sleep $INTERVAL
done
