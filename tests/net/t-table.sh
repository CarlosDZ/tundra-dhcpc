. "$(dirname "$0")/lib.sh"

setup
start_client table local
wait_client 3
expect_exit 2 "reserved table rejected"
start_client rule-priority 1000
wait_client 3
expect_exit 2 "rule-priority without table rejected"

start_client metric 200 table 100 rule-priority 1500 probe off
expect_log "bound to $NET." 15 "binds with a routing table"
IP=$(ns_addr)
check "subnet route in table 100 with src" in_ns sh -c "ip route show table 100 | grep -q 'src $IP'"
check "default route in table 100" in_ns sh -c "ip route show table 100 | grep -q '^default via $NET.1'"
check "default route also in main" in_ns sh -c "ip route show table main | grep -q '^default via $NET.1'"
check "source rule installed" in_ns sh -c "ip rule show table 100 | grep -q '^1500:.*from $IP'"

stop_dnsmasq
expect_log "lease expired, removing address" 30 "lease expires without a server"
eventually "rule removed" 3 in_ns sh -c "[ -z \"\$(ip rule show table 100)\" ]"
eventually "table 100 emptied" 3 in_ns sh -c "[ -z \"\$(ip route show table 100 2>/dev/null)\" ]"
eventually "address removed" 3 no_addr
summary
