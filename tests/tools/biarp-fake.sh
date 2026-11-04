#!/bin/sh
if [ -n "${BIARP_FAKE:-}" ] && [ -e "$BIARP_FAKE" ]; then
	case $(cat "$BIARP_FAKE") in
	taken)
		echo "taken mac 02:aa:aa:aa:aa:01 src 02:aa:aa:aa:aa:01"
		exit 0
		;;
	alert)
		echo "alert 111/4 stop by tundra-blueice-arp on $2 ts 0.000 reply force,disconnect info case A forged 0 -- single host claiming addresses" >&2
		exit 111
		;;
	fail)
		exit 1
		;;
	usage)
		exit 2
		;;
	hang)
		exec sleep 1001
		;;
	esac
fi
if [ -n "${BIARP_REAL:-}" ]; then
	exec "$BIARP_REAL" "$@"
fi
echo free
