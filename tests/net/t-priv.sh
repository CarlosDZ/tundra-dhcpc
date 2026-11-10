. "$(dirname "$0")/lib.sh"

PRIV=$ROOT/build/test/priv
TIP=${TIP_REAL:-/usr/local/bin/tundra-ip}
SENSOR=${BIARP_REAL:-$ROOT/../tundra-blueice-arp/build/test/tundra-blueice-arp}
unset BIARP_REAL
INH=cap_net_admin,cap_net_raw,cap_net_bind_service
NOCAPS=0000000000000000

status_is() {
	grep -q "^$2:[[:space:]]*$3\$" "/proc/$1/status"
}

worker_pid() {
	pgrep -P "$CLIENT_PID" -x tundra-dhcpc
}

gone() {
	! kill -0 "$1" 2>/dev/null
}

no_sleeper() {
	! pgrep -f "sleep 1001" >/dev/null
}

setup
start_client metric 200 probe off
expect_log "bound to $NET." 15 "confinement: bound"
WORKER=$(worker_pid)
check "the client runs as two processes" test -n "$WORKER"
check "worker: seccomp filter loaded" status_is "$WORKER" Seccomp 2
check "worker: no_new_privs set" status_is "$WORKER" NoNewPrivs 1
for set in CapInh CapPrm CapEff CapAmb; do
	check "worker: $set empty" status_is "$WORKER" "$set" "$NOCAPS"
done
check "monitor: no seccomp filter" status_is "$CLIENT_PID" Seccomp 0
check "monitor: no_new_privs unset" status_is "$CLIENT_PID" NoNewPrivs 0
stop_client
expect_exit 0 "confinement: SIGTERM exits with 0"
eventually "confinement: the worker is gone" 3 gone "$WORKER"

setup
start_client metric 200 probe off
expect_log "bound to $NET." 15 "worker killed: bound"
WORKER=$(worker_pid)
kill -KILL "$WORKER"
wait_client 5
expect_exit 1 "a killed worker stops the monitor with 1"
expect_log "worker killed by signal 9" 1 "the worker's death is reported"

setup
echo hang >"$BIARP_FAKE"
start_client metric 200
expect_log "probing address" 15 "worker killed while probing: probing"
kill -KILL "$(worker_pid)"
wait_client 5
expect_exit 1 "a worker killed while probing stops the monitor with 1"
eventually "the probe does not outlive the worker" 3 no_sleeper
rm -f "$BIARP_FAKE"

setup
start_client metric 200 probe off
expect_log "bound to $NET." 15 "monitor killed: bound"
WORKER=$(worker_pid)
kill -KILL "$CLIENT_PID"
wait "$CLIENT_PID" 2>/dev/null
CLIENT_PID=
eventually "the worker does not outlive the monitor" 3 gone "$WORKER"

setup
sh -c "TUNDRA_PARENT_PID=\$\$ ip netns exec '$NS' '$DHCPC' '$IF' metric 200 probe off >'$LOG' 2>&1 &
echo \$! >'$WORK/pid'
n=150
while [ \$n -gt 0 ] && ! grep -q 'bound to' '$LOG'; do
	sleep 0.1
	n=\$((n - 1))
done"
ORPHAN=$(cat "$WORK/pid")
eventually "parent death: the client stops" 5 gone "$ORPHAN"
expect_log "received Terminated, exiting" 1 "parent death: stopped by SIGTERM"
check "parent death: address kept" has_addr
TUNDRA_PARENT_PID=2 "$DHCPC" "$IF" >/dev/null 2>&1
CLIENT_EXIT=$?
expect_exit 143 "a parent that is already gone ends the client at once"

unprivileged() {
	TIP_REAL=$PRIV/tundra-ip ip netns exec "$NS" capsh "$@" --user="$RUNAS" \
		--shell="$PRIV/tundra-dhcpc" -- "$IF" metric 200 >"$LOG" 2>&1 &
	CLIENT_PID=$!
}

RUNAS=$(stat -c %U "$ROOT")
[ "$RUNAS" = root ] && RUNAS=nobody
rm -rf "$PRIV"
mkdir -p "$PRIV"
cp "$DHCPC" "$PRIV/tundra-dhcpc"
cp "$TIP" "$PRIV/tundra-ip"
if ! command -v capsh >/dev/null || ! command -v setcap >/dev/null; then
	printf '# skip: file capabilities need capsh and setcap\n'
elif findmnt -no OPTIONS -T "$PRIV" | grep -qw nosuid; then
	printf '# skip: %s is mounted nosuid\n' "$PRIV"
elif ! capsh --user="$RUNAS" --shell="$PRIV/tundra-dhcpc" -- --version >/dev/null 2>&1; then
	printf '# skip: %s cannot run %s\n' "$RUNAS" "$PRIV/tundra-dhcpc"
else
	setcap cap_net_raw,cap_net_bind_service+ei "$PRIV/tundra-dhcpc"
	setcap cap_net_admin+ei "$PRIV/tundra-ip"
	mkdir -p "$LEASES" "$SENSOR_HISTORY"
	chown "$RUNAS" "$LEASES" "$SENSOR_HISTORY" "${SENSOR_HISTORY%/*}"
	if [ -x "$SENSOR" ]; then
		cp "$SENSOR" "$PRIV/tundra-blueice-arp"
		setcap cap_net_raw+ei "$PRIV/tundra-blueice-arp"
		BIARP_REAL=$PRIV/tundra-blueice-arp
		export BIARP_REAL
	else
		printf '# no tundra-blueice-arp at %s: unprivileged probe not covered\n' "$SENSOR"
	fi

	setup
	unprivileged
	wait_client 5 || CLIENT_EXIT=running
	expect_exit 1 "file capabilities alone do not open the sockets"

	unprivileged --inh="$INH"
	expect_log "probing address $NET." 15 "unprivileged: the address is probed"
	expect_log "bound to $NET." 20 "unprivileged: bound with inheritable capabilities only"
	check "unprivileged: the monitor is not root" sh -c "! grep -q '^Uid:[[:space:]]*0[[:space:]]' /proc/$CLIENT_PID/status"
	check "unprivileged: monitor CapPrm empty" status_is "$CLIENT_PID" CapPrm "$NOCAPS"
	check "unprivileged: monitor CapEff empty" status_is "$CLIENT_PID" CapEff "$NOCAPS"
	check "unprivileged: monitor CapAmb empty" status_is "$CLIENT_PID" CapAmb "$NOCAPS"
	check "unprivileged: monitor inherits only NET_ADMIN and NET_RAW" status_is "$CLIENT_PID" CapInh 0000000000003000
	WORKER=$(worker_pid)
	for set in CapInh CapPrm CapEff CapAmb; do
		check "unprivileged: worker $set empty" status_is "$WORKER" "$set" "$NOCAPS"
	done
	check "unprivileged: worker seccomp filter loaded" status_is "$WORKER" Seccomp 2
	eventually "unprivileged: address applied" 3 has_addr
	check "unprivileged: default route via the gateway" in_ns sh -c "ip route show default | grep -q 'via $NET.1'"
	check "unprivileged: lease file written" test -s "$LEASES/$IF.lease"
	kill -USR1 "$CLIENT_PID"
	wait_client 5
	expect_exit 0 "unprivileged: SIGUSR1 exits with 0"
	eventually "unprivileged: address removed after SIGUSR1" 3 no_addr

	chown root "$LEASES" "$SENSOR_HISTORY" "${SENSOR_HISTORY%/*}"
fi
rm -rf "$PRIV"
summary
