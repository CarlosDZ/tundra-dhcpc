. "$(dirname "$0")/lib.sh"

SENSOR=${BIARP_REAL:-$ROOT/../tundra-blueice-arp/build/test/tundra-blueice-arp}
if [ ! -x "$SENSOR" ]; then
	printf '# skip: no tundra-blueice-arp at %s\n' "$SENSOR"
	exit 0
fi
BIARP_REAL=$SENSOR
export BIARP_REAL

setup
start_client metric 200
expect_log "probing address $NET." 15 "sensor: the address is probed"
expect_log "bound to $NET." 20 "sensor: a free address is bound"
stop_client

setup
for n in $(seq 100 150); do
	in_evil ip addr add "$NET.$n/32" dev "$EVIF"
done
start_client metric 200
wait_client 60
expect_exit 111 "sensor: A is propagated as 111"
expect_log "^alert 111/4 stop by tundra-blueice-arp on $IF .* info case A " 1 "sensor: the alert is signed by the sensor"
expect_count "DHCPDECLINE sent" 3 1 "sensor: every taken address is declined"
summary
