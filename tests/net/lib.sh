set -u

NS=tdc
EVIL=tdcevil
BR=tdcbr0
IF=tdc0
EVIF=tdce0
NET=10.77.0
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DHCPC=$ROOT/build/test/tundra-dhcpc
TOOLS=$ROOT/build/test/tools
WORK=$(mktemp -d /tmp/tdc-test.XXXXXX)
LOG=$WORK/client.log
LEASES=/run/tundra/dhcpc
TIP_FAIL=$WORK/fail-route
export TIP_FAIL

PASS=0
FAIL=0
CLIENT_PID=
CLIENT_EXIT=
DNSMASQ_PID=

ok() {
	PASS=$((PASS + 1))
	printf 'ok - %s\n' "$1"
}

not_ok() {
	FAIL=$((FAIL + 1))
	printf 'not ok - %s\n' "$1"
}

check() {
	desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		ok "$desc"
	else
		not_ok "$desc"
	fi
}

eventually() {
	desc=$1
	n=$(($2 * 10))
	shift 2
	while [ "$n" -gt 0 ]; do
		if "$@" >/dev/null 2>&1; then
			ok "$desc"
			return 0
		fi
		sleep 0.1
		n=$((n - 1))
	done
	not_ok "$desc"
}

wait_log() {
	n=$(($2 * 10))
	while [ "$n" -gt 0 ]; do
		grep -q -- "$1" "$LOG" 2>/dev/null && return 0
		sleep 0.1
		n=$((n - 1))
	done
	return 1
}

expect_log() {
	if wait_log "$1" "$2"; then
		ok "$3"
	else
		not_ok "$3"
		sed 's/^/#   /' "$LOG"
	fi
}

count_log() {
	grep -c -- "$1" "$LOG" 2>/dev/null
}

wait_count() {
	n=$(($3 * 10))
	while [ "$n" -gt 0 ]; do
		[ "$(count_log "$1")" -ge "$2" ] && return 0
		sleep 0.1
		n=$((n - 1))
	done
	return 1
}

expect_count() {
	if wait_count "$1" "$2" "$3"; then
		ok "$4"
	else
		not_ok "$4"
		sed 's/^/#   /' "$LOG"
	fi
}

in_ns() {
	ip netns exec "$NS" "$@"
}

in_evil() {
	ip netns exec "$EVIL" "$@"
}

ns_addr() {
	in_ns ip -4 -o addr show dev "$IF" | awk '{print $4}' | cut -d/ -f1
}

has_addr() {
	[ -n "$(ns_addr)" ]
}

no_addr() {
	[ -z "$(ns_addr)" ]
}

claim() {
	in_evil "$TOOLS/arpsend" "$EVIF" "$@"
}

start_dnsmasq() {
	dnsmasq --interface="$BR" --bind-interfaces --port=0 --no-ping \
		--dhcp-range="$NET.100,$NET.150,2m" --dhcp-option=3,"$NET.1" \
		--dhcp-leasefile="$WORK/leases" --pid-file="$WORK/dnsmasq.pid" "$@"
	DNSMASQ_PID=$(cat "$WORK/dnsmasq.pid")
}

stop_dnsmasq() {
	if [ -n "$DNSMASQ_PID" ]; then
		kill "$DNSMASQ_PID" 2>/dev/null
		DNSMASQ_PID=
		sleep 0.2
	fi
}

start_client() {
	: >"$LOG"
	ip netns exec "$NS" "$DHCPC" "$IF" "$@" >"$LOG" 2>&1 &
	CLIENT_PID=$!
}

wait_client() {
	n=$(($1 * 10))
	while kill -0 "$CLIENT_PID" 2>/dev/null; do
		[ "$n" -le 0 ] && return 1
		sleep 0.1
		n=$((n - 1))
	done
	wait "$CLIENT_PID"
	CLIENT_EXIT=$?
	CLIENT_PID=
	return 0
}

stop_client() {
	[ -n "$CLIENT_PID" ] || return 0
	kill -TERM "$CLIENT_PID" 2>/dev/null
	wait "$CLIENT_PID"
	CLIENT_EXIT=$?
	CLIENT_PID=
}

expect_exit() {
	if [ "$CLIENT_EXIT" = "$1" ]; then
		ok "$2"
	else
		not_ok "$2 (exit $CLIENT_EXIT)"
	fi
}

kill_ns() {
	for pid in $(ip netns pids "$1" 2>/dev/null); do
		kill "$pid" 2>/dev/null
	done
	ip netns del "$1" 2>/dev/null
}

teardown_net() {
	stop_client
	stop_dnsmasq
	kill_ns "$NS"
	kill_ns "$EVIL"
	ip link del "${IF}p" 2>/dev/null
	ip link del "${EVIF}p" 2>/dev/null
	ip link del "$BR" 2>/dev/null
	rm -f "$LEASES/$IF.lease" "$LEASES/$IF"-*.lease
	return 0
}

setup() {
	teardown_net
	ip link add "$BR" type bridge
	ip addr add "$NET.1/24" dev "$BR"
	ip link set "$BR" up
	ip netns add "$NS"
	ip link add "$IF" type veth peer name "${IF}p"
	ip link set "$IF" netns "$NS"
	ip link set "${IF}p" master "$BR" up
	in_ns ip link set lo up
	in_ns ip link set "$IF" up
	ip netns add "$EVIL"
	ip link add "$EVIF" type veth peer name "${EVIF}p"
	ip link set "$EVIF" netns "$EVIL"
	ip link set "${EVIF}p" master "$BR" up
	in_evil ip link set "$EVIF" up
	start_dnsmasq
}

teardown() {
	teardown_net
	rm -rf "$WORK"
}

summary() {
	printf '# %d passed, %d failed\n' "$PASS" "$FAIL"
	[ "$FAIL" -eq 0 ]
}

trap teardown EXIT
trap 'exit 130' INT TERM
