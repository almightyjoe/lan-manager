#!/usr/bin/env python3
"""
Passive traffic capture daemon for a trusted-owner target device.
Run with: sudo python3 capture.py

Spawns tcpdump, parses metadata from line-by-line output, and stores events to
SQLite. It does not capture packet payloads.
"""

import argparse
import ipaddress
import subprocess
import re
import sqlite3
import signal
import sys
import os
import queue
import shutil
import threading
import time
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
CONF_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target.conf")

def _read_conf_target():
    try:
        with open(CONF_PATH) as f:
            ip = f.read().strip()
            if ip and ip != 'none':
                return ip
    except OSError:
        pass
    return None

def _parse_args():
    p = argparse.ArgumentParser(description='Passive LAN traffic capture daemon')
    p.add_argument('--target',
                   default=_read_conf_target() or os.environ.get('LANMAN_TARGET_IP', ''),
                   help='Target IP to monitor (empty = LAN-wide, no directional focus)')
    p.add_argument('--interface', default=os.environ.get('LANMAN_INTERFACE', 'auto'),
                   help='Interface to capture on (default: auto)')
    p.add_argument('--scope', default=os.environ.get('LANMAN_SCOPE', 'lan'),
                   choices=['lan', 'target'],
                   help='Capture scope: lan (all LAN) or target (target IP only)')
    return p.parse_args()

_args = _parse_args()
TARGET_IP  = _args.target
TARGET_MAC = None           # set to "aa:bb:cc:dd:ee:ff" to skip discovery
INTERFACE  = _args.interface         # "auto", "any", or e.g. "eth0"
CAPTURE_SCOPE = _args.scope # "lan" records visible LAN metadata; "target" records only TARGET_IP
DB_PATH    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic.db")
BATCH_SIZE = 50             # flush DB every N packets or every FLUSH_INTERVAL seconds
FLUSH_INTERVAL = 2.0
HEARTBEAT_INTERVAL = 15.0
TCPDUMP    = os.environ.get("LANMAN_TCPDUMP", "tcpdump")

# Ports that are expected / not worth alerting on
COMMON_PORTS = {
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 143,
    443, 465, 587, 853, 993, 995, 3389, 5353, 8080, 8443,
}

# Ports that are actively suspicious
SUSPICIOUS_PORTS = {
    1337, 4444, 5554, 6666, 6667, 7777, 8888, 9999,
    12345, 31337, 4899, 4000, 5900,
}

# ── Regex patterns ────────────────────────────────────────────────────────────
# Matches tcpdump -tttt lines with or without -e link-layer prefixes.
PACKET_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) '
    r'(?:.*?:\s+)?IP(?:\d)? '
    r'(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))? > '
    r'(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?: '
    r'(.+)$'
)
ARP_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) '
    r'(.*?ethertype ARP.*?: )?'
    r'(Request who-has (\d+\.\d+\.\d+\.\d+) tell (\d+\.\d+\.\d+\.\d+)|'
    r'Reply (\d+\.\d+\.\d+\.\d+) is-at ([0-9a-f:]{17}))',
    re.I
)
MAC_RE = re.compile(r'\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b', re.I)
LENGTH_RE = re.compile(r'length (\d+)')
FLAGS_RE  = re.compile(r'Flags \[([^\]]*)\]')

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            direction TEXT    NOT NULL,
            src_ip    TEXT,
            src_port  INTEGER,
            dst_ip    TEXT,
            dst_port  INTEGER,
            protocol  TEXT,
            length    INTEGER DEFAULT 0,
            flags     TEXT,
            alert     TEXT,
            raw       TEXT
        );
        CREATE TABLE IF NOT EXISTS target_device (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            target_ip   TEXT,
            target_mac  TEXT,
            interface   TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            updated_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS hourly_stats (
            hour        TEXT    PRIMARY KEY,
            bytes_out   INTEGER DEFAULT 0,
            bytes_in    INTEGER DEFAULT 0,
            packets_out INTEGER DEFAULT 0,
            packets_in  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS daily_stats (
            day         TEXT    PRIMARY KEY,
            bytes_out   INTEGER DEFAULT 0,
            bytes_in    INTEGER DEFAULT 0,
            packets_out INTEGER DEFAULT 0,
            packets_in  INTEGER DEFAULT 0,
            alerts      INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS capture_status (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            state       TEXT,
            message     TEXT,
            packets     INTEGER DEFAULT 0,
            updated_at  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_dst ON events(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_events_dir ON events(direction);
        CREATE INDEX IF NOT EXISTS idx_events_alert ON events(alert);
        CREATE INDEX IF NOT EXISTS idx_events_proto ON events(protocol);
        CREATE INDEX IF NOT EXISTS idx_events_ports ON events(src_port, dst_port);
    ''')
    conn.execute(
        '''INSERT OR IGNORE INTO daily_stats
           (day, bytes_out, bytes_in, packets_out, packets_in, alerts)
           SELECT substr(timestamp, 1, 10) AS day,
                  SUM(CASE WHEN direction='out' THEN length ELSE 0 END),
                  SUM(CASE WHEN direction='in' THEN length ELSE 0 END),
                  SUM(CASE WHEN direction='out' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN direction='in' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN alert IS NOT NULL THEN 1 ELSE 0 END)
           FROM events
           GROUP BY day'''
    )
    conn.commit()
    conn.close()

def update_capture_status(state, message=None, packets=0):
    conn = sqlite3.connect(DB_PATH)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        '''INSERT INTO capture_status (id, state, message, packets, updated_at)
           VALUES (1, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             state = excluded.state,
             message = excluded.message,
             packets = excluded.packets,
             updated_at = excluded.updated_at''',
        (state, message, packets, now)
    )
    conn.commit()
    conn.close()

def db_scalar(sql, *args):
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(sql, args).fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.lower()
    if not re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', mac):
        return None
    first_octet = int(mac.split(':', 1)[0], 16)
    if mac == 'ff:ff:ff:ff:ff:ff' or first_octet & 1:
        return None
    return mac

def read_persisted_mac():
    return normalize_mac(db_scalar("SELECT target_mac FROM target_device WHERE id = 1 AND target_ip = ?", TARGET_IP))

def upsert_target_device(target_mac=None, interface=None, seen_ts=None):
    conn = sqlite3.connect(DB_PATH)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    seen_ts = seen_ts or now
    conn.execute(
        '''INSERT INTO target_device
           (id, target_ip, target_mac, interface, first_seen, last_seen, updated_at)
           VALUES (1, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             target_ip = excluded.target_ip,
             target_mac = COALESCE(excluded.target_mac, target_device.target_mac),
             interface = COALESCE(excluded.interface, target_device.interface),
             first_seen = COALESCE(target_device.first_seen, excluded.first_seen),
             last_seen = excluded.last_seen,
             updated_at = excluded.updated_at''',
        (TARGET_IP, normalize_mac(target_mac), interface, seen_ts, seen_ts, now)
    )
    conn.commit()
    conn.close()

def db_writer(q: queue.Queue, stop_event: threading.Event):
    """Background thread: drains the queue and writes to SQLite in batches."""
    conn = sqlite3.connect(DB_PATH)
    batch = []
    last_flush = time.monotonic()

    while not stop_event.is_set() or not q.empty():
        try:
            row = q.get(timeout=0.5)
            batch.append(row)
        except queue.Empty:
            pass

        now = time.monotonic()
        if len(batch) >= BATCH_SIZE or (batch and now - last_flush >= FLUSH_INTERVAL):
            _flush(conn, batch)
            batch.clear()
            last_flush = now

    if batch:
        _flush(conn, batch)
    conn.close()

def stderr_logger(stream, stop_event):
    while not stop_event.is_set():
        line = stream.readline()
        if not line:
            break
        print(f"[tcpdump] {line.rstrip()}", flush=True)

def heartbeat_writer(stop_event, packet_counter):
    while not stop_event.wait(HEARTBEAT_INTERVAL):
        update_capture_status("running", "tcpdump running", packet_counter())

def _flush(conn, batch):
    c = conn.cursor()
    c.executemany(
        '''INSERT INTO events
           (timestamp, direction, src_ip, src_port, dst_ip, dst_port,
            protocol, length, flags, alert, raw)
           VALUES (:timestamp,:direction,:src_ip,:src_port,:dst_ip,:dst_port,
                   :protocol,:length,:flags,:alert,:raw)''',
        batch
    )
    # Update hourly stats
    for row in batch:
        hour = row['timestamp'][:13]  # "YYYY-MM-DD HH"
        day = row['timestamp'][:10]
        if row['direction'] == 'out':
            c.execute(
                '''INSERT INTO hourly_stats(hour, bytes_out, packets_out)
                   VALUES(?,?,1)
                   ON CONFLICT(hour) DO UPDATE SET
                     bytes_out   = bytes_out   + excluded.bytes_out,
                     packets_out = packets_out + 1''',
                (hour, row['length'])
            )
            c.execute(
                '''INSERT INTO daily_stats(day, bytes_out, packets_out, alerts)
                   VALUES(?,?,1,?)
                   ON CONFLICT(day) DO UPDATE SET
                     bytes_out   = bytes_out   + excluded.bytes_out,
                     packets_out = packets_out + 1,
                     alerts      = alerts      + excluded.alerts''',
                (day, row['length'], 1 if row['alert'] else 0)
            )
        else:
            c.execute(
                '''INSERT INTO hourly_stats(hour, bytes_in, packets_in)
                   VALUES(?,?,1)
                   ON CONFLICT(hour) DO UPDATE SET
                     bytes_in   = bytes_in   + excluded.bytes_in,
                     packets_in = packets_in + 1''',
                (hour, row['length'])
            )
            c.execute(
                '''INSERT INTO daily_stats(day, bytes_in, packets_in, alerts)
                   VALUES(?,?,1,?)
                   ON CONFLICT(day) DO UPDATE SET
                     bytes_in   = bytes_in   + excluded.bytes_in,
                     packets_in = packets_in + 1,
                     alerts     = alerts     + excluded.alerts''',
                (day, row['length'], 1 if row['alert'] else 0)
            )
    conn.commit()

# ── Host identity ─────────────────────────────────────────────────────────────
def run_cmd(args, timeout=3):
    try:
        return subprocess.run(
            args,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""

def detect_interface():
    if INTERFACE != "auto":
        return INTERFACE
    out = run_cmd(['ip', '-o', 'route', 'get', TARGET_IP])
    m = re.search(r'\bdev\s+(\S+)', out)
    return m.group(1) if m else "any"

def detect_lan_cidr(interface):
    out = run_cmd(['ip', '-o', '-4', 'addr', 'show', 'dev', interface])
    for line in out.splitlines():
        m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
        if not m:
            continue
        ip, prefix_s = m.groups()
        parts = ip.split('.')
        if len(parts) == 4 and parts[0] in ('10', '172', '192'):
            return str(ipaddress.ip_network(f'{ip}/{prefix_s}', strict=False))
    return None

def require_tools():
    missing = []
    tcpdump_path = shutil.which(TCPDUMP)
    if not tcpdump_path:
        missing.append(TCPDUMP)
    if not shutil.which("ip"):
        missing.append("iproute2/ip")
    if missing:
        print("[capture] Required tool missing: " + ", ".join(missing), file=sys.stderr)
        print("[capture] Install on Raspberry Pi OS with: sudo apt-get install -y tcpdump iproute2", file=sys.stderr)
        sys.exit(127)
    return tcpdump_path

def discover_mac_from_neighbor():
    out = run_cmd(['ip', '-o', 'neigh', 'show', TARGET_IP])
    m = re.search(r'\blladdr\s+([0-9a-f:]{17})\b', out, re.I)
    if m:
        return normalize_mac(m.group(1))

    # Nudge ARP/neighbor discovery without inspecting application traffic.
    run_cmd(['ping', '-c', '1', '-W', '1', TARGET_IP], timeout=2)
    out = run_cmd(['ip', '-o', 'neigh', 'show', TARGET_IP])
    m = re.search(r'\blladdr\s+([0-9a-f:]{17})\b', out, re.I)
    return normalize_mac(m.group(1)) if m else None

def discover_mac_from_tcpdump_line(line):
    if 'ethertype ARP' in line or ' ARP,' in line:
        arp = parse_arp_line(line)
        return arp.get('target_mac') if arp else None

    arp = parse_arp_line(line)
    if arp and arp.get('target_mac'):
        return arp['target_mac']

    # tcpdump -e Ethernet lines usually include src and dst MACs before IP.
    macs = [normalize_mac(m) for m in MAC_RE.findall(line)]
    if len(macs) < 2:
        return None
    row = parse_line(line, target_mac=None)
    if not row:
        return None
    if row['src_ip'] == TARGET_IP:
        return macs[0]
    if row['dst_ip'] == TARGET_IP:
        return macs[1]
    return None

def parse_arp_line(line):
    m = ARP_RE.match(line.strip())
    if not m:
        return None
    ts = m.group(1)
    request_ip = m.group(4)
    request_from = m.group(5)
    reply_ip = m.group(6)
    reply_mac = normalize_mac(m.group(7))

    if reply_ip == TARGET_IP:
        return {
            'timestamp': ts,
            'direction': 'in',
            'src_ip': reply_ip,
            'src_port': None,
            'dst_ip': request_from,
            'dst_port': None,
            'protocol': 'ARP',
            'length': 0,
            'flags': None,
            'alert': None,
            'raw': line.strip()[:300],
            'target_mac': reply_mac,
        }

    if request_ip == TARGET_IP or request_from == TARGET_IP:
        return {
            'timestamp': ts,
            'direction': 'out' if request_from == TARGET_IP else 'in',
            'src_ip': request_from,
            'src_port': None,
            'dst_ip': request_ip,
            'dst_port': None,
            'protocol': 'ARP',
            'length': 0,
            'flags': None,
            'alert': None,
            'raw': line.strip()[:300],
            'target_mac': None,
        }
    if request_ip and request_from:
        return {
            'timestamp': ts,
            'direction': 'other',
            'src_ip': request_from,
            'src_port': None,
            'dst_ip': request_ip,
            'dst_port': None,
            'protocol': 'ARP',
            'length': 0,
            'flags': None,
            'alert': None,
            'raw': line.strip()[:300],
            'target_mac': None,
        }
    if reply_ip and reply_mac:
        return {
            'timestamp': ts,
            'direction': 'other',
            'src_ip': reply_ip,
            'src_port': None,
            'dst_ip': None,
            'dst_port': None,
            'protocol': 'ARP',
            'length': 0,
            'flags': None,
            'alert': None,
            'raw': line.strip()[:300],
            'target_mac': reply_mac if reply_ip == TARGET_IP else None,
        }
    return None

# ── Packet parsing ────────────────────────────────────────────────────────────
def detect_protocol(src_port, dst_port, info):
    il = info.lower()
    if 'flags [' in il:      return 'TCP'
    if 'icmp' in il:         return 'ICMP'
    if 'arp'  in il:         return 'ARP'
    if src_port in (53,) or dst_port in (53,): return 'DNS'
    if 'udp' in il:          return 'UDP'
    return 'OTHER'

def detect_alert(direction, src_port, dst_port, protocol, length):
    alerts = []
    remote_port = dst_port if direction == 'out' else src_port

    if remote_port in SUSPICIOUS_PORTS:
        alerts.append(f"suspicious_port:{remote_port}")
    elif remote_port and remote_port not in COMMON_PORTS and protocol in ('TCP', 'UDP'):
        if remote_port < 1024 or remote_port > 49151:
            alerts.append(f"unusual_port:{remote_port}")

    if length and length > 5_000_000:
        alerts.append("large_transfer")

    return ','.join(alerts) if alerts else None

def parse_line(line: str, target_mac=None):
    arp = parse_arp_line(line)
    if arp:
        arp.pop('target_mac', None)
        return arp

    m = PACKET_RE.match(line.strip())
    if not m:
        return None
    ts_str, src_ip, src_port_s, dst_ip, dst_port_s, info = m.groups()

    src_port = int(src_port_s) if src_port_s else None
    dst_port = int(dst_port_s) if dst_port_s else None

    lm = LENGTH_RE.search(info)
    length = int(lm.group(1)) if lm else 0

    fm = FLAGS_RE.search(info)
    flags = fm.group(1) if fm else None

    protocol  = detect_protocol(src_port, dst_port, info)
    if TARGET_IP and src_ip == TARGET_IP:
        direction = 'out'
    elif TARGET_IP and dst_ip == TARGET_IP:
        direction = 'in'
    else:
        direction = 'other'
    alert     = detect_alert(direction, src_port, dst_port, protocol, length)

    return {
        'timestamp': ts_str,
        'direction': direction,
        'src_ip':    src_ip,
        'src_port':  src_port,
        'dst_ip':    dst_ip,
        'dst_port':  dst_port,
        'protocol':  protocol,
        'length':    length,
        'flags':     flags,
        'alert':     alert,
        'raw':       line.strip()[:300],
    }

# ── Main capture loop ─────────────────────────────────────────────────────────
def build_tcpdump_cmd(interface, target_mac):
    tcpdump_path = shutil.which(TCPDUMP) or TCPDUMP
    base = [tcpdump_path, '-nn', '-tttt', '-e', '-l', '-s', '128', '-i', interface]
    if CAPTURE_SCOPE == "lan":
        cidr = detect_lan_cidr(interface) if interface != "any" else None
        if cidr:
            return base + ['arp', 'or', 'net', cidr]
    if target_mac and interface != "any":
        return base + ['ether', 'host', target_mac]
    return base + ['host', TARGET_IP]

def run():
    if os.geteuid() != 0:
        print("ERROR: capture.py must run as root (sudo python3 capture.py)")
        sys.exit(1)

    tcpdump_path = require_tools()
    init_db()
    # Make DB readable by non-root web server process
    os.chmod(DB_PATH, 0o666)

    interface = detect_interface()
    target_mac = normalize_mac(TARGET_MAC) or read_persisted_mac() or discover_mac_from_neighbor()
    upsert_target_device(target_mac=target_mac, interface=interface)
    update_capture_status("starting", "starting tcpdump", 0)

    write_q   = queue.Queue(maxsize=10000)
    stop_ev   = threading.Event()
    writer_th = threading.Thread(target=db_writer, args=(write_q, stop_ev), daemon=True)
    writer_th.start()

    cmd = build_tcpdump_cmd(interface, target_mac)
    print(f"[capture] Starting: {' '.join(cmd)}")
    print(f"[capture] Target IP : {TARGET_IP}")
    print(f"[capture] Target MAC: {target_mac or 'unknown, learning from traffic'}")
    print(f"[capture] Scope     : {CAPTURE_SCOPE}")
    print(f"[capture] Interface : {interface}")
    print(f"[capture] tcpdump   : {tcpdump_path}")
    print(f"[capture] Database  : {DB_PATH}")
    update_capture_status("running", "tcpdump started", 0)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    stderr_th = threading.Thread(target=stderr_logger, args=(proc.stderr, stop_ev), daemon=True)
    stderr_th.start()
    heartbeat_th = threading.Thread(
        target=heartbeat_writer,
        args=(stop_ev, lambda: packets_seen),
        daemon=True
    )
    heartbeat_th.start()

    def _shutdown(sig, frame):
        print("\n[capture] Shutting down…")
        proc.terminate()
        stop_ev.set()
        writer_th.join(timeout=5)
        stderr_th.join(timeout=2)
        heartbeat_th.join(timeout=2)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    packets_seen = 0
    try:
        for line in proc.stdout:
            if not target_mac:
                learned_mac = discover_mac_from_tcpdump_line(line)
                if learned_mac:
                    target_mac = learned_mac
                    upsert_target_device(target_mac=target_mac, interface=interface)
                    print(f"[capture] Learned target MAC: {target_mac}")

            row = parse_line(line, target_mac=target_mac)
            if row:
                packets_seen += 1
                if packets_seen % 25 == 0:
                    upsert_target_device(target_mac=target_mac, interface=interface, seen_ts=row['timestamp'][:19])
                try:
                    write_q.put_nowait(row)
                except queue.Full:
                    pass   # drop rather than block; log if needed
                if packets_seen % 100 == 0:
                    print(f"[capture] {packets_seen} packets logged  "
                          f"(queue depth: {write_q.qsize()})")
        rc = proc.wait(timeout=2)
        if rc != 0:
            msg = f"tcpdump exited with status {rc}"
            update_capture_status("error", msg, packets_seen)
            print(f"[capture] {msg}", file=sys.stderr)
            sys.exit(rc)
    except Exception as exc:
        update_capture_status("error", str(exc), packets_seen)
        print(f"[capture] Error: {exc}")
    finally:
        stop_ev.set()
        writer_th.join(timeout=5)
        stderr_th.join(timeout=2)
        heartbeat_th.join(timeout=2)

if __name__ == '__main__':
    run()
