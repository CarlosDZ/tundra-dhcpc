. "$(dirname "$0")/lib.sh"

setup
start_client metric 200
expect_log "bound to $NET." 15 "binds a lease"
in_ns ip link set "$IF" down
expect_log "removing address" 5 "carrier loss without grace removes the address"
eventually "address removed" 3 no_addr
in_ns ip link set "$IF" up
expect_log "requesting previous address" 5 "carrier back: INIT-REBOOT"
expect_count "bound to $NET." 2 15 "previous lease confirmed"
eventually "address applied again" 3 has_addr
stop_client

start_client metric 200 carrier-grace 3000
expect_log "bound to $NET." 15 "binds with carrier-grace"
in_ns ip link set "$IF" down
expect_log "keeping address for 3000 ms" 5 "short loss keeps the address"
check "address kept during grace" has_addr
in_ns ip link set "$IF" up
expect_log "requesting previous address" 5 "carrier back within grace: INIT-REBOOT"
in_ns ip link set "$IF" down
expect_log "carrier still down, removing address" 6 "grace expiry removes the address"
eventually "address removed after grace" 3 no_addr
stop_client
expect_exit 0 "SIGTERM exits with 0"
summary
