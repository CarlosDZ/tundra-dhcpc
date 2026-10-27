. "$(dirname "$0")/lib.sh"

usage_error() {
	desc=$1
	shift
	"$DHCPC" "$@" >/dev/null 2>&1
	CLIENT_EXIT=$?
	expect_exit 2 "$desc"
}

"$DHCPC" --version >/dev/null 2>&1
CLIENT_EXIT=$?
expect_exit 0 "--version exits with 0"
usage_error "no interface"
usage_error "option without value" "$IF" metric
usage_error "non-numeric metric" "$IF" metric abc
usage_error "negative carrier-grace" "$IF" carrier-grace -1
usage_error "lease-key with a slash" "$IF" lease-key ../x
usage_error "lease-key starting with a dot" "$IF" lease-key .x
usage_error "unknown probe value" "$IF" probe maybe
usage_error "secs out of range" "$IF" secs 70000
usage_error "rule-priority out of range" "$IF" table 100 rule-priority 40000
usage_error "unknown option" "$IF" color blue
usage_error "repeated metric" "$IF" metric 1 metric 2
usage_error "repeated carrier-grace" "$IF" carrier-grace 1 carrier-grace 2
summary
