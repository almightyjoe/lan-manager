# LANMan Handoff

## Purpose

LANMan is a Raspberry Pi based LAN observer and dashboard. It records packet
metadata visible from this Pi and presents target-focused views for devices on
the local network.

It does not capture packet payloads or reconstruct content. It records metadata
such as timestamp, source/destination IP, ports, protocol guess, byte length,
TCP flags, simple alert labels, ARP presence, and live inventory details.

## Runtime

- Dashboard URL: `http://192.168.1.229:3099/`
- Dashboard service: `lanman-dashboard`
- Capture service: `lanman-capture`
- Dashboard app: `app.py`
- Capture daemon: `capture.py`
- Database: `traffic.db`
- Dashboard template: `templates/dashboard.html`

Useful checks:

```bash
systemctl status lanman-dashboard lanman-capture --no-pager
ss -H -ltnp | grep ':3099'
curl -s http://127.0.0.1:3099/api/observer | python3 -m json.tool
```

## Observer Identity

The Pi running LANMan is the observer, not the monitored target.

Current observer IPs:

- `192.168.1.229`
- `192.168.1.99`

The observer is documented as `lanman_passive_observer`. Its IPs are shown in
the dashboard observer note only and are excluded from target telemetry metrics,
event feeds, top remote IPs, behavior summaries, protocol/port charts, and
hourly/daily traffic charts.

## Port

LANMan was moved from `8088` to `3099`.

The active systemd dashboard service uses:

```text
Environment=LANMAN_PORT=3099
```

The repo service template at `systemd/lanman-dashboard.service` also uses
`3099`.

Chromium has a LANMan bookmark and startup URL:

```text
http://192.168.1.229:3099/
```

Firefox has a default profile scaffold with homepage and bookmark import for
the same URL.

## Target Selection

The dashboard defaults to:

```text
192.168.1.2
```

Targets are dynamic. Any discovered device can be selected from the device table
with `Monitor`, or opened in a new browser tab.

Target-specific URLs use:

```text
http://192.168.1.229:3099/?target=<ip>
```

Example:

```text
http://192.168.1.229:3099/?target=192.168.1.93
```

All dashboard API calls carry the selected target, so stats/events/charts are
scoped to that device.

## MAC Discovery

MAC addresses come from live neighbor/ARP inventory when a device answers at
layer 2.

Important current state:

- `192.168.1.2` has not answered ARP or ping from this observer.
- Direct `arp-scan` for `192.168.1.2` returned zero responders.
- Therefore LANMan correctly shows `MAC not observed` for `192.168.1.2`.
- `192.168.1.93` is observed as `2c:cf:67:5e:ec:cd` and resolves as
  `raspberrypi.local`.

Do not treat ARP requests from the observer to a target as target telemetry.
The code excludes observer IPs from target metrics.

## Capture Scope

`capture.py` currently uses:

```python
CAPTURE_SCOPE = "lan"
```

With the current `wlan0` setup, this builds a tcpdump command like:

```text
tcpdump -nn -tttt -e -l -s 128 -i wlan0 arp or net 192.168.1.0/24
```

This records visible LAN metadata for drill-down across selected devices. On a
normal switched or Wi-Fi network, visibility is limited to traffic the Pi can
actually see: broadcast, multicast, ARP, traffic to/from the Pi, and any traffic
the network forwards to it.

Future hardware will improve visibility:

- Managed switch: mirror/SPAN port, MAC table, port/VLAN/LLDP/PoE data.
- Wi-Fi monitor device: BSSID/SSID/channel/RSSI/client radio events.

## API Overview

Core dashboard:

- `/`
- `/?target=<ip>`

Observer and LAN inventory:

- `/api/observer`
- `/api/lan/summary`
- `/api/lan/inventory`
- `/api/lan/inventory?refresh=1`

Selected-target APIs:

- `/api/device?target=<ip>`
- `/api/status?target=<ip>`
- `/api/stats?target=<ip>`
- `/api/events?target=<ip>`
- `/api/top_ips?target=<ip>`
- `/api/behavior?target=<ip>`
- `/api/protocols?target=<ip>`
- `/api/hourly?target=<ip>`
- `/api/daily?target=<ip>`
- `/api/ports?target=<ip>`

Manual security snapshot:

- `/api/target/security?target=<ip>`
- `/api/target/security?target=<ip>&refresh=1`

The security snapshot does not run on page load. It runs only from the dashboard
button or `refresh=1`, and is rate-limited to once per target per 24 hours.

## Known Limits

- `192.168.1.2` is not currently visible at layer 2. No MAC can be honestly
  documented until it answers ARP/neighbor discovery or another trusted data
  source supplies it.
- The current Pi has `192.168.1.99/8` and `192.168.1.229/24` on `wlan0`.
  LANMan clamps broad private prefixes to a practical `/24` inventory scope.
- The legacy `target_device` table is single-row and should not be used as a
  general device inventory. Live inventory is the source for dynamic target MACs.
- Until a switch mirror or Wi-Fi monitor is added, per-device telemetry depends
  on what this Pi can passively see.

## Files Changed Recently

- `app.py`: dynamic target selection, observer exclusion, LAN inventory,
  target-scoped APIs, target-scoped security snapshots.
- `capture.py`: LAN-scope capture, broader ARP metadata parsing, no stale MAC
  reuse unless it belongs to the configured target.
- `templates/dashboard.html`: dynamic target UI, device-table monitor actions,
  observer note, manual security snapshot panel.
- `README.md`: updated runtime, target selection, observer handling, and
  future collector notes.
- `systemd/lanman-dashboard.service`: dashboard port set to `3099`.

## Good Resume Prompt

If this conversation is closed, resume with:

```text
Scan /home/joe/claudework/lanman, read HANDOFF.md and README.md, then inspect
app.py, capture.py, and templates/dashboard.html before making changes.
LANMan runs on port 3099 and supports dynamic targets with ?target=<ip>.
```
