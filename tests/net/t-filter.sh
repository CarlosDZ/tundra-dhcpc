. "$(dirname "$0")/lib.sh"

setup
stop_dnsmasq
start_client
expect_log "DHCPDISCOVER sent" 5 "client is selecting"
check "raw socket carries the BPF filter" in_ns sh -c "ss -0 -b | grep -q 'bpf filter (9)'"
start_dnsmasq
expect_log "bound to $NET." 20 "binds through the filter"
stop_client
summary
