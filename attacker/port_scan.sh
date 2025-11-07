#!/bin/sh
# Safe HTTP/TCP port "scanner" - attempts TCP connect to a small range at a low rate
TARGET_HOST=${TARGET_HOST:-web_server}
START_PORT=${START_PORT:-8000}
END_PORT=${END_PORT:-8010}
INTERVAL=${INTERVAL:-1} # seconds between attempts
while true; do
  echo "Scanning ports $START_PORT-$END_PORT on $TARGET_HOST"
  for p in $(seq $START_PORT $END_PORT); do
    timeout 1 sh -c "echo > /dev/tcp/$TARGET_HOST/$p" 2>/dev/null && echo "$(date) OPEN $TARGET_HOST:$p" || echo "$(date) CLOSED $TARGET_HOST:$p"
    sleep 0.05
  done
  sleep $INTERVAL
done
