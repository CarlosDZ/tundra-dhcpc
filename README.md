# tundra-dhcpc

Minimal DHCPv4 client, developed for Tundra OS, works on any Linux — obtains an
IPv4 lease, keeps it alive and applies it through `tundra-ip`.

`tundra-dhcpc` is Tundra's layer 2 network tool: it speaks the DHCP protocol
(RFC 2131) and decides **when** an address must be applied, renewed or removed.
It never talks to the kernel's routing subsystem itself: every address, route
and rule is applied by invoking `tundra-ip` (layer 1). The client is resident:
it runs until it is told to stop.

## Design philosophy

- **Protocol here, mechanism in `tundra-ip`.** The client owns the DHCP state
  machine; `tundra-ip` owns netlink. The boundary is a `fork` + `execv` and an
  exit status.
- **Policy comes from the caller.** Which routing table an interface uses, its
  metric or its rule priority are decided by whoever launches the client (the
  user or an orchestrator) and passed as arguments. The client never invents
  them.
- **It only touches what it put.** No flush on start. Everything it applies is
  done with idempotent `replace` operations and undone explicitly when the
  lease is lost.
- **Hostile networks are assumed.** Every address is probed with ARP before use
  and defended while in use; attacks are classified and reported with a
  dedicated exit status.

## Requirements

- Linux (uses `AF_PACKET`, `NETLINK_ROUTE`, `signalfd`, `CLOCK_BOOTTIME`).
- Root (raw sockets and address configuration).
- `tundra-ip` 1.7_1 or later, at the path fixed at build time (`TUNDRA_IP_PATH`,
  `/usr/bin/tundra-ip` by default).

## Usage

```
tundra-dhcpc <interface> [metric <n>] [carrier-grace <ms>] [lease-key <name>]
             [probe on|off] [secs <n>] [table <table>] [rule-priority <n>]
tundra-dhcpc --version
```

| Option | Meaning | Default |
|--------|---------|---------|
| `metric <n>` | Metric of the address' connected route and of the default route | none (kernel default) |
| `carrier-grace <ms>` | How long the address is kept after the link goes down (absorbs Wi-Fi micro-cuts) | `0` (removed at once) |
| `lease-key <name>` | Extra key for the lease file, so one interface can remember a lease per network | none |
| `probe on\|off` | `off` binds without ARP probing and defends the address forever (forced mode, see below) | `on` |
| `secs <n>` | Fixed value for the `secs` field of every message (0-65535) | real elapsed seconds |
| `table <table>` | Routing table of the interface (strong host model, see below) | none (`main` only) |
| `rule-priority <n>` | Priority of the source rule (1-32765); requires `table` | `1000` |

- Options take exactly one value and may not be repeated.
- `<table>` accepts anything `tundra-ip` accepts: a numeric id, a name from
  `/etc/tundra/network/route_tables` or `<group>.<table>`. It is passed through
  verbatim and checked against `tundra-ip` before anything is applied. `local`,
  `default`, `0`, `253` and `255` are rejected; `main`/`254` mean "no table".
- `lease-key` accepts `[A-Za-z0-9._-]`, up to 64 characters, not starting with
  `.`.

## Behaviour

### Lifecycle

The client waits for carrier, then runs DISCOVER / OFFER / REQUEST / ACK with
exponential backoff (4 s doubling up to 64 s, ±1 s jitter). Once bound it renews
at T1 by unicast, rebinds at T2 by broadcast and removes everything if the lease
expires. Losing carrier removes the address (or keeps it for `carrier-grace`);
recovering it confirms the previous lease with INIT-REBOOT. A NAK always clears
the address and restarts discovery.

### Lease persistence

The current lease is stored in `/run/tundra/dhcpc/<interface>.lease` (or
`<interface>-<lease-key>.lease`), written atomically, mode `0600`. It lives in
`/run` on purpose: it survives a restart of the client, not a reboot of the
machine. On start a valid stored lease is confirmed with INIT-REBOOT instead of
a full discovery.

### Address lifetimes

Addresses are applied with `valid` and `preferred` lifetimes equal to the
remaining lease plus a 10 s margin, and refreshed on every renewal. If the
client dies abruptly (SIGKILL, crash), the kernel removes the address on its
own when the lease would have expired.

### Strong host model (`table`)

With `table <t>`, besides the address, the client installs:

- the subnet route in table `<t>` with the lease address as `src`;
- the default route in table `<t>` **and** in `main` (`main` decides the egress
  of new connections; table `<t>` guarantees the return path);
- a rule `from <address>/32 lookup <t>` with the given priority.

All of it is removed explicitly when the lease is lost. Traffic leaving with the
interface's address therefore always leaves through that interface.

### ARP probing and defense

Before using an address the client probes it (RFC 5227: three probes 1-2 s
apart, then 2 s of silence) and, if nobody claims it, announces it twice. A
conflict sends DHCPDECLINE and retries 10 s later. While the address is in use,
a claim from another host is answered with an announcement; a second claim
within 10 s makes the client give the address up.

With `probe off` (forced mode) the address is bound without probing and is
defended forever: claims are answered at most once per defense interval and
the client never gives the address up.

### Attack detection

Conflicts are recorded over a sliding 5-minute window. The client stops with
exit status **111** and a single `alert:` line on stderr when it sees:

| Case | Condition |
|------|-----------|
| A | One MAC claiming 3 different addresses offered to us |
| B | 10 distinct (MAC, address) pairs claiming our addresses |
| C | 3 claims on the address in use |
| D | Two different MACs answering for the gateway address |
| Invalid MAC | A claim from a multicast, broadcast or all-zero MAC (immediate) |

The alert may carry two hints: the responder uses the gateway's MAC (proxy ARP
or gateway impersonation), and the ARP sender differs from the Ethernet frame
source (crafted packet or proxying device). The address and the lease are
removed before exiting. In forced mode cases A, B and C are only logged; D still
raises the alert.

### Robustness

- Received datagrams are filtered in the kernel with a BPF program (IPv4, UDP,
  not fragmented, destination port 68) and validated again in user space,
  including the UDP checksum (`PACKET_AUXDATA` is honoured for offloaded
  checksums).
- Option overload (option 52) is supported.
- `secs` follows RFC 2131: elapsed seconds since the start of the transaction,
  and the REQUEST repeats the value of the DISCOVER it answers.

## Exit status

| Code | Meaning |
|------|---------|
| `0` | Stopped by SIGTERM or SIGINT. The address and the lease file are kept, so the next start resumes with INIT-REBOOT |
| `1` | Operational failure: interface removed, socket error, `tundra-ip` could not be run |
| `2` | Invalid usage or configuration: bad arguments, invalid table, or `tundra-ip` rejected the configuration (its own exit status 2). Never retried |
| `111` | Alert: attack detected (see [Attack detection](#attack-detection)) |

Operational failures of `tundra-ip` (its exit status 1) are not fatal: the
client undoes what it applied and retries with backoff.

## Files

| Path | Purpose |
|------|---------|
| `/run/tundra/dhcpc/<if>[-<key>].lease` | Current lease (`key=value`, written atomically) |
| `TUNDRA_IP_PATH` (`/usr/bin/tundra-ip`) | Layer 1 tool invoked to apply the lease |
| `/etc/tundra/network/route_tables` | Table names, read by `tundra-ip` only |

Lease file fields: `address`, `mask`, `server`, `router`, `dns`, `lease`,
`t1_at`, `t2_at`, `expiry_at` (times in milliseconds of `CLOCK_BOOTTIME`).

## Building

```
make
make install PREFIX=/usr DESTDIR=<staging>
```

`TUNDRA_IP_PATH` sets where `tundra-ip` is looked up
(`make TUNDRA_IP_PATH=/usr/local/bin/tundra-ip`). The Makefile honours the
packager's `CPPFLAGS`, `CFLAGS` and `LDFLAGS`.

## Tests

```
make check-unit
make check
```

- `check-unit` runs the unit tests (`tests/unit/t-*.c`) built with
  AddressSanitizer and UBSan. No root needed.
- `check` runs the unit tests and then the network scenarios
  (`tests/net/t-*.sh`). They build an isolated testbed with network namespaces
  (a bridge, the client, a dnsmasq server and an attacker) and never touch the
  host's interfaces. They need root (the runner re-executes itself with `sudo`),
  `iproute2`, `dnsmasq` and an installed `tundra-ip` (`TIP_REAL` overrides its
  path, `/usr/local/bin/tundra-ip` by default).
- The test binary is built with protocol timers divided by 6, so a full run
  takes about four minutes.

## Known limitations

- After a SIGKILL with `table`, the kernel removes the address and its subnet
  routes, but the source rule and the table's default route remain. They are
  harmless (the rule points to an address that no longer exists) and are
  replaced on the next start with the same lease.
- The interface MAC is read when the raw socket is opened; if it changes while
  bound, announcements and defense keep the old one until the next discovery.

## Currently unsupported

Planned or pending design decisions:

- IPv6 (DHCPv6, SLAAC).
- Applying DNS servers; only the first DNS server and router are kept.
- Options 12 (hostname) and 61 (client identifier).
- DHCPRELEASE on exit, SIGHUP handling and structured logging.
- Waiting for a removed interface to come back.
- Dropping privileges to `CAP_NET_RAW` + `CAP_NET_ADMIN`.
