#!/bin/sh
[ "$(id -u)" -eq 0 ] || exec sudo env TIP_REAL="${TIP_REAL:-}" sh "$0" "$@"
cd "$(dirname "$0")/../.." || exit 1

for dep in ip dnsmasq; do
	command -v "$dep" >/dev/null || {
		echo "missing dependency: $dep" >&2
		exit 1
	}
done

rc=0
for t in tests/net/t-*.sh; do
	printf '# %s\n' "$t"
	sh "$t" || rc=1
done
exit $rc
