#!/bin/bash
exec 3<>/dev/tcp/localhost/8080

echo -e "GET ${KC_HTTP_RELATIVE_PATH} HTTP/1.1\nHost: localhost\n" >&3
timeout --preserve-status 1 cat <&3 | grep -m 1 "HTTP/1.1" | grep -m 1 "303 See Other"
ERROR=$?

exec 3<&-
exec 3>&-

exit $ERROR
