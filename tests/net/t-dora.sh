. "$(dirname "$0")/lib.sh"

setup
start_client metric 200
expect_log "bound to $NET." 15 "binds a lease"
check "address applied on the interface" has_addr
check "default route via the gateway" in_ns sh -c "ip route show default | grep -q 'via $NET.1'"
check "lease file written" test -s "$LEASES/$IF.lease"
expect_log "gateway is at" 5 "gateway MAC learned"
expect_log "renewed $NET." 15 "renews before T2"
stop_client
expect_exit 0 "SIGTERM exits with 0"
summary
