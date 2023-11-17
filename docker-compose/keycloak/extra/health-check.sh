#!/bin/bash
exec 3<>/dev/tcp/localhost/8080

echo -e "GET ${KC_HTTP_RELATIVE_PATH}/health/ready HTTP/1.1\nhost: localhost:8080\n" >&3

timeout --preserve-status 1 cat <&3 | grep -m 1 status | grep -m 1 UP
ERROR=$?

exec 3<&-
exec 3>&-

exit $ERROR
