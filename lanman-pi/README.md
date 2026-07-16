# LAN Monitor

Passive metadata monitor for devices visible from this Pi on the local LAN.

The capture process records packet metadata only: timestamps, direction, IPs,
ports, protocol guesses, byte counts, TCP flags, and simple alert labels. It
does not capture packet payloads or reconstruct content.

## Run Manually

Install OS tools:

```bash
sudo apt-get install -y tcpdump python3-flask
```

Start capture as root:

```bash
sudo python3 capture.py
```

Start the dashboard as a normal user:

```bash
python3 app.py
```

Open:

```text
http://<pi-ip>:3099
```

## Persistent Services

Service templates are in `systemd/`.

```bash
sudo cp systemd/lanman-capture.service /etc/systemd/system/
sudo cp systemd/lanman-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lanman-capture lanman-dashboard
```

## Target Identity And Selection

The dashboard defaults to `192.168.1.2`, but any discovered device can be made
the active target from the device table. The selected target is carried in the
URL as `?target=<ip>`, so multiple browser tabs can monitor different devices:

```text
http://<pi-ip>:3099/?target=192.168.1.93
```

`capture.py` records visible LAN metadata for the local `/24` when
`CAPTURE_SCOPE = "lan"`. This allows target drill-down for any device whose
traffic is visible to the observer. On an unmanaged switched or normal Wi-Fi
network, the Pi will still only see broadcast, multicast, ARP, traffic involving
the Pi, and whatever the infrastructure forwards to it. A managed switch mirror
port or monitor Wi-Fi device will increase visibility later.

The MAC for a selected target is taken from live neighbor/inventory data. If a
target does not answer ARP/neighbor discovery, LANMan displays `MAC not
observed` rather than treating observer ARP requests as target telemetry.

If discovery fails, set `TARGET_MAC` near the top of `capture.py`.

## Data

All history lives in `traffic.db` in this folder. The schema includes:

- `target_device`: target IP, learned MAC, interface, and last seen times
- `events`: packet metadata records
- `hourly_stats`: hourly byte and packet counters
- `daily_stats`: daily byte, packet, and alert counters

On a switched network, a Pi only sees traffic that reaches its interface unless
the switch/router mirrors traffic to it or the Pi is placed inline. ARP, mDNS,
broadcast, and traffic to/from the Pi are usually visible without mirroring.

A firewall on `192.168.1.2` can block ping and application probes. It normally
does not block ARP, so an `INCOMPLETE` neighbor entry usually points to the host
being asleep/offline, a different VLAN/subnet, Wi-Fi client isolation, or the Pi
not being able to see that layer-2 segment.

## LAN Inventory

The dashboard also exposes live LAN inventory endpoints:

- `/api/lan/summary`
- `/api/lan/inventory`
- `/api/lan/inventory?refresh=1`

The inventory uses data available from the Pi today:

- local interface addresses and scan scope from `ip addr`
- neighbor/ARP cache from `ip neigh`
- bounded ICMP probes of directly connected private `/24` LANs
- reverse DNS and mDNS names when resolvable
- MAC vendor lookup from local IEEE OUI data when installed
- short TCP checks for common services such as SSH, DNS, HTTP, HTTPS, SMB, RDP, and 8080

It intentionally ignores failed or incomplete neighbor entries so a ping sweep
does not turn every address in the subnet into a device. If an interface reports
an overly broad private prefix such as `/8`, LANMan scans the practical `/24`
around the Pi address instead of the entire private range.

The Pi running LANMan is treated as the `lanman_passive_observer`, not as the
target. Its local IPs are shown in the observer note only and are excluded from
target telemetry metrics, event feeds, top remote IPs, behavior summaries, and
traffic charts.

## Target Security Snapshot

LANMan can document an occasional active security snapshot for the main target:

- `/api/target/security` returns the cached snapshot only
- `/api/target/security?refresh=1` runs a manual active snapshot when allowed

The snapshot is rate-limited to once per 24 hours and stored in
`security_snapshot.json`. It uses a light nmap service/version check against the
configured `TARGET_IP`; it is not part of the passive telemetry refresh loop.
Use it when you need a documented point-in-time view of exposed services without
turning active scans into repetitive metrics.

Future collectors can add richer data without changing the dashboard shape:

- managed switch data: port, VLAN, LLDP/CDP neighbor, PoE, link speed, and switch MAC table
- Wi-Fi monitor data: BSSID, SSID, channel, RSSI, association/deauth events, and client radio identity
