. "$(dirname "$0")/lib.sh"

old_gone() {
	! in_ns ip -4 -o addr show dev "$IF" | grep -q " $OLD/"
}

setup
start_client metric 200 probe off
expect_log "bound to $NET." 15 "binds a lease"
OLD=$(ns_addr)
stop_client
stop_dnsmasq
rm -f "$WORK/leases"
DHCP_RANGE="$NET.200,$NET.210,2m" start_dnsmasq --dhcp-authoritative
start_client metric 200 probe off
expect_log "DHCPNAK" 10 "previous address refused after a network change"
expect_log "bound to $NET.20" 15 "binds in the new range"
eventually "previous address removed" 3 old_gone
stop_client

setup
start_client metric 200 probe off
expect_log "bound to $NET." 15 "binds before the gateway changes"
stop_dnsmasq
DHCP_ROUTER="$NET.2" start_dnsmasq
expect_log "lease changed, reapplying" 20 "a different lease on renewal is reapplied"
eventually "default route follows the new gateway" 5 in_ns sh -c "ip route show default | grep -q 'via $NET.2'"
stop_client

setup
"$TOOLS/dhcpsecs" "$BR" 2 >"$WORK/secs" &
SNIFF=$!
start_client secs 30 probe off
expect_log "bound to $NET." 15 "binds with a forced secs"
wait "$SNIFF"
check "DISCOVER and REQUEST carry the forced secs" sh -c "[ \"\$(sort -u '$WORK/secs')\" = 30 ]"
stop_client

setup
stop_dnsmasq
"$TOOLS/dhcpsecs" "$BR" 2 >"$WORK/secs" &
SNIFF=$!
start_client
wait "$SNIFF"
check "first DISCOVER carries secs 0" sh -c "[ \"\$(sed -n 1p '$WORK/secs')\" = 0 ]"
check "retransmission carries the elapsed seconds" sh -c "[ \"\$(sed -n 2p '$WORK/secs')\" -ge 3 ]"
stop_client
summary
