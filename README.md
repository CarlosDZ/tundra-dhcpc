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
- **Protection lives in tundra-blueice.** Every address is probed before use by
  `tundra-blueice-arp probe`; the client only acts on the result. Defending the
  address while it is in use is the job of `tundra-blueice-arp watch`, launched
  by the orchestrator.

## Requirements

- Linux (uses `AF_PACKET`, `NETLINK_ROUTE`, `signalfd`, `CLOCK_BOOTTIME`).
- `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE`: root, or the file capabilities
  described in [Privileges](#privileges).
- `tundra-ip` 1.8_0 or later, at the path fixed at build time (`TUNDRA_IP_PATH`,
  `/usr/bin/tundra-ip` by default).
- `tundra-blueice-arp` 0.2_0 or later, at the path fixed at build time
  (`TUNDRA_BLUEICE_ARP_PATH`, `/usr/bin/tundra-blueice-arp` by default).
- Linked against `libseccomp`.

## Privileges

The package marks the binary with
`setcap cap_net_raw,cap_net_bind_service+ei` from the xbps `INSTALL` script at
the root of this repository (`make install` does not run it): only a parent
that already holds both capabilities as inheritable (tundra-networkd) gets them
on exec. Any other user gets nothing and the sockets fail. Run by root it works
without the file capabilities.

After checking its arguments the client opens every socket it will ever use
(packet, UDP port 68, link netlink), drops its permitted, effective and ambient
capabilities, keeps only `CAP_NET_ADMIN` and `CAP_NET_RAW` as inheritable and
splits in two processes. Run by root the monitor keeps its capabilities (the
tools it runs would regain them on exec anyway); the worker is confined always:

| Process | Does | Holds |
|---------|------|-------|
| Monitor (the PID that was launched) | Runs `tundra-ip` and `tundra-blueice-arp probe`, writes the lease file, forwards signals and exits with the worker's status | No usable capability; `CAP_NET_ADMIN` and `CAP_NET_RAW` as inheritable, so `tundra-ip` and the probe get theirs. No seccomp: it has to `exec` |
| Worker (its child) | Speaks DHCP and runs the state machine | No capability in any set, `no_new_privs` and a seccomp filter. Any system call outside the filter kills it |

The worker asks the monitor for every change through fixed-size messages. The
monitor takes the interface, table, metric and priority from its own command
line, never from the worker, checks every field and only refreshes or removes
the configuration it applied itself.

Neither process outlives the other: a dead worker stops the monitor with `1`,
and the kernel kills the worker when the monitor dies.

The kernel clears the parent death signal when a binary with file capabilities
is executed, so the client arms it itself:

| `TUNDRA_PARENT_PID` | Effect |
|---------------------|--------|
| The PID of the parent | SIGTERM when the parent dies |
| Another PID (the parent died before the exec) | Ends at once with SIGTERM |
| Unset or not a PID above 1 | Nothing, silently |

The tools the client runs receive its own PID in that variable.

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
| `probe on\|off` | `off` binds without probing the address first | `on` |
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

### Signals

| Signal | Effect |
|--------|--------|
| SIGTERM, SIGINT | Exit keeping the address and the lease file; the next start resumes with INIT-REBOOT |
| SIGUSR1 | Release: remove the address, routes and source rule, keep the lease file and exit |
| SIGUSR2 | Conflict: send DHCPDECLINE for the address in use, remove it, forget the lease and discover again 10 s later |
| SIGHUP, SIGPIPE | Ignored, so a closed terminal or log pipe never leaves state behind |

If the interface is removed, the kernel deletes its addresses and routes; the
client removes the source rule, which belongs to no interface, keeps the lease
file and exits with `1`.

### Lease persistence

The current lease is stored in `/run/tundra/dhcpc/<interface>.lease` (or
`<interface>-<lease-key>.lease`), written atomically, mode `0600`. It lives in
`/run` on purpose: it survives a restart of the client, not a reboot of the
machine. On start a valid stored lease is confirmed with INIT-REBOOT instead of
a full discovery.

The file records the MAC the lease was given to (`mac=`). A lease of another
MAC is never reused: asking for its address would tie both MACs together. It is
forgotten, its address is taken off the interface if it is still there, and
the client starts from discovery.

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

### Address probing

Before using a new address the client runs
`tundra-blueice-arp probe <interface> <address>` as a child, without blocking
its loop, and acts on the result:

| Probe result | Client |
|--------------|--------|
| `free` | Binds the address |
| `taken mac <mac> src <mac>` | Sends DHCPDECLINE and discovers again 10 s later |
| Exit `111` | Sends DHCPDECLINE and exits with `111`. The alert line was already written by the probe on the shared stderr |
| Exit `2` | Exits with `2` |
| Exit `1`, killed, or no result within 30 s | Retries with backoff |

The probe's stdout goes to the client; its stderr is the client's own.

### Traceability

The only thing a message tells about this host is the MAC of the interface
(`chaddr`). No hostname (option 12), vendor class (60), client identifier (61),
user class (77) or FQDN (81) is ever sent, and the server name and boot file
fields go empty. The parameter request list asks only for the subnet mask, the
router and the DNS servers. A unit test checks every message built. After a
change of MAC, nothing of the previous one is sent either (see
[Lease persistence](#lease-persistence)).

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
| `0` | Stopped by SIGTERM or SIGINT (address and lease file kept, the next start resumes with INIT-REBOOT), or released by SIGUSR1 |
| `1` | Operational failure: interface removed, socket error, `tundra-ip` could not be run, SIGUSR1 could not remove what was applied, or the worker died |
| `2` | Invalid usage or configuration: bad arguments, invalid table, or `tundra-ip` rejected the configuration (its own exit status 2). Never retried |
| `111` | Alert from `tundra-blueice-arp probe`, propagated (see [Address probing](#address-probing)) |

Operational failures of `tundra-ip` (its exit status 1) are not fatal: the
client undoes what it applied and retries with backoff.

## Files

| Path | Purpose |
|------|---------|
| `/run/tundra/dhcpc/<if>[-<key>].lease` | Current lease (`key=value`, written atomically) |
| `TUNDRA_IP_PATH` (`/usr/bin/tundra-ip`) | Layer 1 tool invoked to apply the lease |
| `TUNDRA_BLUEICE_ARP_PATH` (`/usr/bin/tundra-blueice-arp`) | ARP sensor invoked to probe an address |
| `/etc/tundra/network/route_tables` | Table names, read by `tundra-ip` only |

Lease file fields: `address`, `mask`, `server`, `router`, `dns` (up to three,
comma separated), `lease`, `t1_at`, `t2_at`, `expiry_at` (times in milliseconds of
`CLOCK_BOOTTIME`).

## Building

```
make
make install PREFIX=/usr DESTDIR=<staging>
```

`TUNDRA_IP_PATH` and `TUNDRA_BLUEICE_ARP_PATH` set where `tundra-ip` and
`tundra-blueice-arp` are looked up
(`make TUNDRA_IP_PATH=/usr/local/bin/tundra-ip`). The Makefile honours the
packager's `CPPFLAGS`, `CFLAGS` and `LDFLAGS`. It needs the `libseccomp`
headers.

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
- The probe is replaced by `tests/tools/biarp-fake.sh`, which answers `free`
  unless a scenario asks for something else. `t-sensor.sh` runs against the real
  sensor: `BIARP_REAL`, or `../tundra-blueice-arp/build/test/tundra-blueice-arp`
  when it exists; otherwise it is skipped.
- `t-priv.sh` checks the confinement of both processes and runs the client as
  an unprivileged user with copies of the client, of `tundra-ip` and of the real
  sensor (when it exists) marked with file capabilities in `build/test/priv`.
  It needs `capsh` and `setcap`, and a build directory that is not mounted
  `nosuid`; otherwise that part is skipped.
- The test binary is built with protocol timers divided by 6, so a full run
  takes about five minutes.

## Known limitations

- After a SIGKILL with `table`, the kernel removes the address and its subnet
  routes, but the source rule and the table's default route remain. They are
  harmless (the rule points to an address that no longer exists) and are
  replaced on the next start with the same lease.

## Currently unsupported

Planned or pending design decisions:

- IPv6 (DHCPv6, SLAAC).
- Applying DNS servers (up to three are stored in the lease); only the first
  router is kept.
- DHCPRELEASE on exit and structured logging.
- Waiting for a removed interface to come back.
