. "$(dirname "$0")/lib.sh"

setup
start_client metric 200
expect_log "bound to $NET." 15 "binds a lease"
stop_client
check "lease file kept after SIGTERM" test -s "$LEASES/$IF.lease"
check "address kept after SIGTERM" has_addr

start_client metric 200
expect_log "previous lease $NET." 3 "previous lease loaded"
expect_log "bound to $NET." 15 "rebinds with INIT-REBOOT"
check "no DISCOVER after restart" sh -c "! grep -q DHCPDISCOVER '$LOG'"
stop_client

in_ns ip -4 addr flush dev "$IF"
start_client metric 200
expect_log "bound to $NET." 15 "address removed while stopped is reapplied"
eventually "address present again" 3 has_addr
stop_client

printf 'address=garbage\n' >"$LEASES/$IF.lease"
start_client metric 200
expect_log "ignoring invalid lease file" 3 "corrupt lease file ignored"
expect_log "DHCPDISCOVER" 5 "falls back to DISCOVER"
stop_client

start_client metric 200 lease-key home
expect_log "bound to $NET." 15 "binds with lease-key"
check "lease file named after interface and key" test -s "$LEASES/$IF-home.lease"
stop_client
summary
