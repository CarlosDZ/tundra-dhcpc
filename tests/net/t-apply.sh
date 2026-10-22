. "$(dirname "$0")/lib.sh"

setup
touch "$TIP_FAIL"
start_client metric 200 probe off
expect_log "could not apply lease" 10 "route failure is reported"
expect_log "retrying in" 2 "retry is scheduled"
check "partial apply rolled back" no_addr
rm -f "$TIP_FAIL"
expect_log "bound to $NET." 15 "binds once tundra-ip succeeds"
eventually "address applied" 3 has_addr
check "address has a lifetime" in_ns sh -c "ip -4 addr show dev $IF | grep -q 'valid_lft [0-9]*sec'"
stop_client

in_ns ip -4 addr flush dev "$IF"
start_client metric 200 probe off
expect_log "bound to $NET." 15 "binds again"
kill -KILL "$CLIENT_PID"
wait "$CLIENT_PID" 2>/dev/null
CLIENT_PID=
n=0
while has_addr && [ "$n" -lt 400 ]; do
	sleep 0.1
	n=$((n + 1))
done
check "kernel removes the address after SIGKILL" no_addr
summary
