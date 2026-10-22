. "$(dirname "$0")/lib.sh"

EVMAC=02:aa:aa:aa:aa:01

setup
start_client metric 200
expect_log "gateway is at" 20 "bound and gateway learned"
IP=$(ns_addr)
claim "$EVMAC" "$IP" "$IP"
expect_log "defending address $IP" 3 "a single claim is defended"
check "address kept after defense" has_addr
claim "$EVMAC" "$IP" "$IP"
expect_log "DHCPDECLINE sent" 3 "a second claim within the interval gives up"
expect_count "bound to $NET." 2 20 "binds a new address"
stop_client

setup
start_client metric 200
expect_log "gateway is at" 20 "C: bound"
IP=$(ns_addr)
for i in 1 2 3; do
	claim "02:aa:aa:aa:aa:0$i" "$IP" "$IP"
	sleep 2
done
wait_client 5
expect_exit 111 "C: repeated claims raise the alert"
expect_log "repeatedly claimed (C)" 1 "C: alert names the case"
eventually "C: address removed" 3 no_addr

setup
start_client metric 200
expect_log "gateway is at" 20 "D: bound"
IP=$(ns_addr)
claim 02:bb:bb:bb:bb:bb "$NET.1" "$IP"
wait_client 5
expect_exit 111 "D: gateway impersonation raises the alert"
expect_log "gateway impersonation (D)" 1 "D: alert names the case"

setup
start_client metric 200
expect_log "gateway is at" 20 "invalid MAC: bound"
IP=$(ns_addr)
claim 01:00:5e:00:00:01 "$IP" "$IP" 02:cc:cc:cc:cc:cc
wait_client 5
expect_exit 111 "invalid MAC raises the alert at once"

setup
for n in $(seq 100 150); do
	in_evil ip addr add "$NET.$n/32" dev "$EVIF"
done
start_client metric 200
wait_client 40
expect_exit 111 "A: one host claiming every address raises the alert"
expect_log "single host claiming addresses (A)" 1 "A: alert names the case"

setup
ip netns exec "$EVIL" "$TOOLS/arpresp" "$EVIF" &
start_client metric 200
wait_client 90
expect_exit 111 "B: many MACs raise the alert"
expect_log "many hosts claiming addresses (B)" 1 "B: alert names the case"
summary
