. "$(dirname "$0")/lib.sh"

rule_gone() {
	[ -z "$(in_ns ip rule show table 100)" ]
}

setup
start_client metric 200 table 100 probe off
expect_log "bound to $NET." 15 "SIGUSR1: bound with a routing table"
kill -USR1 "$CLIENT_PID"
wait_client 5
expect_exit 0 "SIGUSR1 exits with 0"
expect_log "releasing address on $IF" 1 "SIGUSR1 releases the address"
eventually "address removed after SIGUSR1" 3 no_addr
eventually "rule removed after SIGUSR1" 3 rule_gone
check "lease file kept after SIGUSR1" test -s "$LEASES/$IF.lease"

start_client metric 200 probe off
expect_log "previous lease $NET." 3 "the released lease is loaded again"
expect_log "bound to $NET." 15 "the released lease resumes with INIT-REBOOT"
kill -HUP "$CLIENT_PID"
sleep 1
check "SIGHUP does not stop the client" kill -0 "$CLIENT_PID"
check "address kept after SIGHUP" has_addr
stop_client

setup
mkfifo "$WORK/out"
ip netns exec "$NS" "$DHCPC" "$IF" metric 200 probe off >"$WORK/out" 2>&1 &
CLIENT_PID=$!
head -n 1 "$WORK/out" >/dev/null
eventually "SIGPIPE: binds after its reader is gone" 15 has_addr
check "SIGPIPE does not stop the client" kill -0 "$CLIENT_PID"
stop_client
rm -f "$WORK/out"

setup
start_client metric 200 table 100 probe off
expect_log "bound to $NET." 15 "removal: bound with a routing table"
in_ns ip link del "$IF"
wait_client 5
expect_exit 1 "a removed interface exits with 1"
expect_log "interface $IF removed" 1 "the removal is reported"
check "rule removed with the interface" rule_gone
check "lease file kept after the removal" test -s "$LEASES/$IF.lease"
summary
