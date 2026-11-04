. "$(dirname "$0")/lib.sh"

no_sleeper() {
	! pgrep -f "sleep 1001" >/dev/null
}

setup
start_client metric 200
expect_log "probing address $NET." 15 "the address is probed before use"
expect_log "bound to $NET." 15 "a free address is bound"
stop_client

setup
echo taken >"$BIARP_FAKE"
start_client metric 200
expect_log "in use by 02:aa:aa:aa:aa:01" 15 "taken: the conflict is reported"
expect_log "DHCPDECLINE sent" 3 "taken: the address is declined"
rm -f "$BIARP_FAKE"
expect_log "bound to $NET." 20 "taken: the next address is bound"
stop_client

setup
echo alert >"$BIARP_FAKE"
start_client metric 200
wait_client 20
expect_exit 111 "alert: the probe's 111 is propagated"
expect_log "^alert 111/4 stop by tundra-blueice-arp on $IF " 1 "alert: the probe's line reaches the client output"
check "alert: printed once" sh -c "[ \$(grep -c '^alert ' '$LOG') -eq 1 ]"
check "alert: the address is declined" grep -q "DHCPDECLINE sent" "$LOG"
check "alert: no address applied" no_addr
check "alert: no lease kept" test ! -e "$LEASES/$IF.lease"

setup
echo usage >"$BIARP_FAKE"
start_client metric 200
wait_client 20
expect_exit 2 "usage: a probe usage error stops with 2"

setup
echo fail >"$BIARP_FAKE"
start_client metric 200
expect_log "could not probe address $NET." 15 "fail: the failure is reported"
rm -f "$BIARP_FAKE"
expect_log "bound to $NET." 30 "fail: the probe is retried"
stop_client

setup
echo hang >"$BIARP_FAKE"
start_client metric 200
expect_log "probing address" 15 "hang: probing"
expect_log "timed out" 10 "hang: the probe times out"
eventually "hang: the stuck probe is killed" 3 no_sleeper
rm -f "$BIARP_FAKE"
expect_log "bound to $NET." 30 "hang: the probe is retried"
stop_client

setup
echo hang >"$BIARP_FAKE"
start_client metric 200
expect_log "probing address" 15 "SIGTERM: probing"
stop_client
expect_exit 0 "SIGTERM during the probe exits with 0"
eventually "SIGTERM: the probe is killed" 3 no_sleeper

setup
start_client metric 200
expect_log "bound to $NET." 15 "SIGUSR2: bound"
IP=$(ns_addr)
kill -USR2 "$CLIENT_PID"
expect_log "address $IP in conflict, declining it" 3 "SIGUSR2: the conflict is reported"
expect_log "DHCPDECLINE sent" 3 "SIGUSR2: the address is declined"
expect_count "bound to $NET." 2 20 "SIGUSR2: another address is bound"
stop_client

setup
stop_dnsmasq
start_client metric 200
expect_log "DHCPDISCOVER sent" 5 "SIGUSR2 without address: selecting"
kill -USR2 "$CLIENT_PID"
expect_log "ignoring SIGUSR2" 3 "SIGUSR2 without address is ignored"
check "SIGUSR2 without address keeps running" kill -0 "$CLIENT_PID"
stop_client
summary
