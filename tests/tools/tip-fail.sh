#!/bin/sh
real=${TIP_REAL:-/usr/local/bin/tundra-ip}
if [ -n "${TIP_FAIL:-}" ] && [ -e "$TIP_FAIL" ] && [ "$1 $2" = "route replace" ]; then
	code=$(cat "$TIP_FAIL")
	echo "tundra-ip: injected failure" >&2
	exit "${code:-1}"
fi
exec "$real" "$@"
