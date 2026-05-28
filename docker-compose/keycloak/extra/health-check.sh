#!/bin/bash

PORT=9000
HEALTH_PATH="/idp/health/ready"

timeout 3 bash -c '
  exec 3<>/dev/tcp/localhost/'"$PORT"' || exit 1
  echo -e "GET '"$HEALTH_PATH"' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 || exit 1
  grep -m 1 "HTTP/1.1 200 OK" <&3 > /dev/null
'
ERROR=$?

if [ "$ERROR" -eq 0 ]; then
  echo "Healthcheck Successful"
  exit 0
else
  echo "Healthcheck Failed"
  exit 1
fi