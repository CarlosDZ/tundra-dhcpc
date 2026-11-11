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

check "the lease file names the MAC it belongs to" grep -qx "mac=$(in_ns cat /sys/class/net/$IF/address)" "$LEASES/$IF.lease"
in_ns ip link set "$IF" down
in_ns ip link set "$IF" address 02:12:34:56:78:9a
in_ns ip link set "$IF" up
start_client metric 200
expect_log "previous lease $NET.* belongs to another mac, forgotten" 3 "a lease of another MAC is not reused"
expect_log "DHCPDISCOVER" 5 "the new MAC starts from discovery"
check "without asking for the address of the old one" sh -c "! grep -q 'requesting previous address' '$LOG'"
expect_log "bound to $NET." 15 "and gets its own lease"
check "now stored under the new MAC" grep -qx "mac=02:12:34:56:78:9a" "$LEASES/$IF.lease"
check "the old address is taken off the interface" sh -c "[ \"\$(ip netns exec $NS ip -4 -o addr show dev $IF | wc -l)\" -eq 1 ]"
check "quietly" sh -c "! grep -q 'tundra-ip exited' '$LOG'"
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

setup
stop_dnsmasq
start_dnsmasq --dhcp-option=6,9.9.9.9,1.1.1.1,8.8.8.8
start_client metric 200 probe off
expect_log "bound to $NET." 15 "binds with three DNS servers"
check "lease file stores every DNS server" grep -qx 'dns=9.9.9.9,1.1.1.1,8.8.8.8' "$LEASES/$IF.lease"
stop_client
summary
