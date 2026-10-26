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

setup
echo 2 >"$TIP_FAIL"
start_client metric 200 probe off
wait_client 15
expect_exit 2 "a usage error from tundra-ip is fatal"
expect_log "invalid configuration for tundra-ip" 1 "the configuration error is reported"
check "no retry after a configuration error" sh -c "! grep -q 'retrying in' '$LOG'"
check "nothing left applied" no_addr
check "no lease file left" test ! -e "$LEASES/$IF.lease"
rm -f "$TIP_FAIL"
summary
