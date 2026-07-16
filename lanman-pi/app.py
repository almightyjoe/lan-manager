#!/usr/bin/env python3
"""
Web dashboard server for the LAN monitor.
Run with: python3 app.py   (no root needed)

Dashboard: http://<your-pi-ip>:3099
"""

import os
import ipaddress
import json
import shutil
import socket
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import lru_cache
from flask import Flask, render_template, jsonify, request

DEFAULT_TARGET_IP = "192.168.1.2"
DB_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic.db")
PORT      = int(os.environ.get("LANMAN_PORT", "3099"))
SECURITY_SNAPSHOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_snapshot.json")
CONF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target.conf")

app = Flask(__name__)

PORT_NAMES = {
    20:'FTP-data', 21:'FTP', 22:'SSH', 25:'SMTP', 53:'DNS',
    67:'DHCP', 68:'DHCP', 80:'HTTP', 110:'POP3', 123:'NTP',
    143:'IMAP', 443:'HTTPS', 465:'SMTPS', 587:'SMTP-sub',
    853:'DNS-TLS', 993:'IMAPS', 995:'POP3S', 3389:'RDP',
    5353:'mDNS', 8080:'HTTP-alt', 8443:'HTTPS-alt',
}

LAN_SCAN_TTL = 5 * 60
LAN_SCAN_TIMEOUT = 0.35
SECURITY_SCAN_TTL = 24 * 60 * 60
COMMON_SERVICE_PORTS = {
    22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
    445: 'SMB', 3389: 'RDP', 8080: 'HTTP-alt',
}
_lan_scan_cache = {'at': 0, 'data': None}
_oui_cache = None

def get_db():
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.row_factory = sqlite3.Row
    return conn

def fmt_bytes(n):
    if n is None: return '0 B'
    for unit in ('B','KB','MB','GB','TB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def table_exists(conn, table):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)
    ).fetchone() is not None

def scalar(conn, sql, *args):
    return conn.execute(sql, args).fetchone()[0] or 0

def requested_target_ip():
    raw = request.args.get('target') or request.args.get('target_ip') or DEFAULT_TARGET_IP
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return DEFAULT_TARGET_IP
    if ip.version != 4 or not ip.is_private:
        return DEFAULT_TARGET_IP
    return str(ip)

def target_page_url(ip):
    return f"/?target={ip}"

def security_snapshot_path(target_ip):
    safe = target_ip.replace('.', '_')
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), f"security_snapshot_{safe}.json")

def observer_ips():
    return local_interfaces()[2]

def observer_sql_clause(columns=('src_ip', 'dst_ip')):
    ips = sorted(observer_ips())
    if not ips:
        return "", []
    placeholders = ','.join(['?'] * len(ips))
    clause = ' AND '.join(f"({col} IS NULL OR {col} NOT IN ({placeholders}))" for col in columns)
    return clause, ips * len(columns)

def observer_condition(prefix='AND', columns=('src_ip', 'dst_ip')):
    clause, args = observer_sql_clause(columns)
    return (f" {prefix} {clause}" if clause else ""), args

def target_condition(target_ip, prefix='AND'):
    return f" {prefix} (src_ip = ? OR dst_ip = ?)", [target_ip, target_ip]

def telemetry_condition(target_ip, prefix='WHERE'):
    parts = ["(src_ip = ? OR dst_ip = ?)"]
    args = [target_ip, target_ip]
    observer_clause, observer_args = observer_sql_clause()
    if observer_clause:
        parts.append(observer_clause)
        args.extend(observer_args)
    return f" {prefix} " + " AND ".join(parts), args

def scalar_filtered(conn, sql, base_args=(), columns=('src_ip', 'dst_ip')):
    clause, args = observer_sql_clause(columns)
    return conn.execute(sql.format(observer_filter=clause), tuple(base_args) + tuple(args)).fetchone()[0] or 0

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

def local_interfaces():
    out = run_cmd(['ip', '-j', 'addr', 'show'])
    try:
        rows = json.loads(out or '[]')
    except json.JSONDecodeError:
        rows = []

    interfaces = []
    local_ips = set()
    networks = []
    for item in rows:
        ifname = item.get('ifname')
        if ifname == 'lo':
            continue
        iface = {
            'name': ifname,
            'state': item.get('operstate'),
            'mac': item.get('address'),
            'addresses': [],
        }
        for addr in item.get('addr_info', []):
            if addr.get('family') != 'inet':
                continue
            ip = addr.get('local')
            prefix = addr.get('prefixlen')
            if not ip or prefix is None:
                continue
            iface['addresses'].append({
                'ip': ip,
                'prefix': prefix,
                'dynamic': bool(addr.get('dynamic')),
                'scope': addr.get('scope'),
            })
            local_ips.add(ip)
            try:
                net = ipaddress.ip_network(f'{ip}/{prefix}', strict=False)
                if net.version == 4 and net.is_private:
                    if net.prefixlen < 24:
                        net = ipaddress.ip_network(f'{ip}/24', strict=False)
                    networks.append({'interface': ifname, 'cidr': str(net)})
            except ValueError:
                pass
        interfaces.append(iface)

    # de-dupe networks while keeping interface context
    seen = set()
    unique_networks = []
    for net in networks:
        key = (net['interface'], net['cidr'])
        if key not in seen:
            seen.add(key)
            unique_networks.append(net)
    return interfaces, unique_networks, local_ips

def parse_neighbors():
    out = run_cmd(['ip', '-j', 'neigh', 'show'])
    try:
        rows = json.loads(out or '[]')
    except json.JSONDecodeError:
        rows = []
    devices = {}
    for row in rows:
        ip = row.get('dst')
        if not ip or ':' in ip:
            continue
        state = row.get('state', [])
        if isinstance(state, str):
            state = [state]
        if not row.get('lladdr') and any(s in ('FAILED', 'INCOMPLETE') for s in state):
            continue
        devices[ip] = {
            'ip': ip,
            'interface': row.get('dev'),
            'mac': row.get('lladdr'),
            'state': state,
            'sources': ['neighbor'],
        }
    return devices

@lru_cache(maxsize=512)
def reverse_name(ip):
    names = []
    host = run_cmd(['getent', 'hosts', ip], timeout=0.6)
    if host:
        parts = host.split()
        names.extend(parts[1:])
    avahi = run_cmd(['avahi-resolve-address', ip], timeout=0.6)
    if avahi:
        parts = avahi.split()
        if len(parts) >= 2:
            names.append(parts[1].rstrip('.'))
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        names.append(ptr.rstrip('.'))
    except (OSError, socket.herror, socket.gaierror):
        pass
    result = []
    for name in names:
        if name and name not in result:
            result.append(name)
    return result

def load_oui():
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    _oui_cache = {}
    for path in ('/usr/share/ieee-data/oui.txt', '/var/lib/ieee-data/oui.txt', '/usr/share/misc/oui.txt'):
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    if '(hex)' not in line:
                        continue
                    prefix, vendor = line.split('(hex)', 1)
                    key = prefix.strip().replace('-', ':').lower()
                    _oui_cache[key] = vendor.strip()
            break
        except OSError:
            continue
    return _oui_cache

def mac_vendor(mac):
    if not mac:
        return None
    oui = load_oui()
    return oui.get(':'.join(mac.lower().split(':')[:3]))

def ping_host(ip):
    try:
        rc = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=1.4
        ).returncode
        return rc == 0
    except subprocess.TimeoutExpired:
        return False

def tcp_probe(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=LAN_SCAN_TIMEOUT):
            return True
    except OSError:
        return False

def active_lan_probe(networks, local_ips):
    candidates = []
    for net in networks:
        try:
            n = ipaddress.ip_network(net['cidr'], strict=False)
        except ValueError:
            continue
        if n.num_addresses > 256:
            continue
        candidates.extend(str(ip) for ip in n.hosts() if str(ip) not in local_ips)
    candidates = sorted(set(candidates), key=lambda ip: tuple(int(p) for p in ip.split('.')))
    if not candidates:
        return []
    found = []
    with ThreadPoolExecutor(max_workers=128) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in candidates}
        for fut in as_completed(futures):
            if fut.result():
                found.append(futures[fut])
    return found

def probe_services(devices):
    targets = list(devices.keys())[:256]
    targets = targets[:32]
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {}
        for ip in targets:
            for port in COMMON_SERVICE_PORTS:
                futures[pool.submit(tcp_probe, ip, port)] = (ip, port)
        for fut in as_completed(futures):
            ip, port = futures[fut]
            if fut.result():
                devices[ip].setdefault('open_ports', []).append({
                    'port': port,
                    'service': COMMON_SERVICE_PORTS[port],
                })

def resolve_device_names(devices):
    targets = list(devices.keys())[:128]
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(reverse_name, ip): ip for ip in targets}
        for fut in as_completed(futures):
            devices[futures[fut]]['names'] = fut.result()

def lan_inventory(force=False):
    now = time.time()
    if not force and _lan_scan_cache['data'] and now - _lan_scan_cache['at'] < LAN_SCAN_TTL:
        return _lan_scan_cache['data']

    interfaces, networks, local_ips = local_interfaces()
    devices = parse_neighbors()

    for ip in active_lan_probe(networks, local_ips):
        devices.setdefault(ip, {'ip': ip, 'sources': []})
        if 'ping' not in devices[ip]['sources']:
            devices[ip]['sources'].append('ping')

    # Re-read neighbors after ping so ARP/ND has a chance to populate MACs.
    for ip, row in parse_neighbors().items():
        existing = devices.setdefault(ip, {'ip': ip, 'sources': []})
        existing.update({k: v for k, v in row.items() if v})
        existing['sources'] = sorted(set(existing.get('sources', []) + row.get('sources', [])))

    resolve_device_names(devices)
    for ip in list(devices.keys()):
        devices[ip]['is_local'] = ip in local_ips
        devices[ip].setdefault('names', [])
        devices[ip]['vendor'] = mac_vendor(devices[ip].get('mac'))
        devices[ip].setdefault('open_ports', [])
        devices[ip].setdefault('state', [])
        devices[ip]['sources'] = sorted(set(devices[ip].get('sources', [])))

    observer = {
        'role': 'lanman_passive_observer',
        'ips': sorted(local_ips),
        'interfaces': interfaces,
        'note': 'This host supplies LANMan observation and active inventory probes. Its IPs are documented here only and excluded from target telemetry metrics.',
    }
    public_devices = {ip: row for ip, row in devices.items() if ip not in local_ips}

    probe_services(public_devices)

    data = {
        'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'interfaces': interfaces,
        'networks': networks,
        'local_ips': sorted(local_ips),
        'observer': observer,
        'devices': sorted(public_devices.values(), key=lambda d: tuple(int(p) for p in d['ip'].split('.'))),
        'limits': {
            'mode': 'direct_lan_active_probe',
            'note': 'Uses local interfaces, neighbor/ARP cache, ICMP ping, reverse name lookups, OUI vendor data, and quick TCP probes. Switch mirror/SNMP and Wi-Fi monitor data can be added as collectors later.',
        },
    }
    _lan_scan_cache.update({'at': now, 'data': data})
    return data

def inventory_device(target_ip, force=False):
    inv = lan_inventory(force=force)
    for device in inv.get('devices', []):
        if device.get('ip') == target_ip:
            return device
    for ip in inv.get('observer', {}).get('ips', []):
        if ip == target_ip:
            return {
                'ip': target_ip,
                'is_observer': True,
                'names': ['lanman observer'],
                'mac': None,
                'vendor': None,
                'state': ['LOCAL'],
                'sources': ['observer'],
                'open_ports': [],
            }
    neigh = run_cmd(['ip', '-o', 'neigh', 'show', target_ip])
    state = neigh.split()[-1:] if neigh else []
    return {
        'ip': target_ip,
        'mac': None,
        'vendor': None,
        'names': reverse_name(target_ip),
        'state': state or ['NOT_OBSERVED'],
        'sources': [],
        'open_ports': [],
        'identity_note': 'No MAC observed. The target has not answered ARP/neighbor discovery from this observer.',
    }

def parse_nmap_output(raw):
    services = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 3 or '/' not in parts[0]:
            continue
        port_proto, state, service = parts[:3]
        if state not in ('open', 'open|filtered'):
            continue
        port_s, proto = port_proto.split('/', 1)
        if not port_s.isdigit():
            continue
        services.append({
            'port': int(port_s),
            'protocol': proto,
            'state': state,
            'service': service,
            'details': ' '.join(parts[3:]),
        })
    return services

def load_security_snapshot(target_ip):
    path = security_snapshot_path(target_ip)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None

def save_security_snapshot(target_ip, data):
    with open(security_snapshot_path(target_ip), 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2)

def target_security_snapshot(target_ip, force=False):
    cached = load_security_snapshot(target_ip)
    now = time.time()
    if cached and not force:
        return cached
    if not cached and not force:
        return {
            'target_ip': target_ip,
            'scanned_at': None,
            'epoch': None,
            'mode': 'no_snapshot',
            'summary': 'No active target security snapshot has been run. Use Run snapshot when needed.',
            'command': None,
            'services': [],
            'raw': '',
        }
    if cached and force and now - cached.get('epoch', 0) < SECURITY_SCAN_TTL:
        cached['stale_notice'] = 'Using cached result; active target vulnerability snapshot is rate-limited to once every 24 hours.'
        return cached

    cmd = ['nmap', '-Pn', '-sV', '--version-light', '-T3', '--top-ports', '100', target_ip]
    started = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if not shutil.which('nmap'):
        data = {
            'target_ip': target_ip,
            'scanned_at': started,
            'epoch': now,
            'mode': 'unavailable',
            'summary': 'nmap is not installed; no active vulnerability snapshot was run.',
            'command': None,
            'services': [],
            'raw': '',
        }
        save_security_snapshot(target_ip, data)
        return data

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120
        )
        raw = proc.stdout[-12000:]
        services = parse_nmap_output(raw)
        data = {
            'target_ip': target_ip,
            'scanned_at': started,
            'epoch': now,
            'mode': 'manual_active_snapshot',
            'summary': f'Found {len(services)} open TCP service(s) in a top-100 nmap service/version check.',
            'command': ' '.join(cmd),
            'returncode': proc.returncode,
            'services': services,
            'raw': raw,
        }
    except subprocess.TimeoutExpired as exc:
        data = {
            'target_ip': target_ip,
            'scanned_at': started,
            'epoch': now,
            'mode': 'manual_active_snapshot',
            'summary': 'nmap timed out before completing.',
            'command': ' '.join(cmd),
            'returncode': None,
            'services': [],
            'raw': (exc.stdout or '')[-12000:] if isinstance(exc.stdout, str) else '',
        }
    save_security_snapshot(target_ip, data)
    return data

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    target_ip = requested_target_ip()
    return render_template('dashboard.html', target_ip=target_ip, default_target_ip=DEFAULT_TARGET_IP)

@app.route('/api/status')
def api_status():
    """Is the DB present and recently updated?"""
    target_ip = requested_target_ip()
    if not os.path.exists(DB_PATH):
        return jsonify({'active': False, 'message': 'No database found — is capture.py running?'})
    conn = get_db()
    if not conn:
        return jsonify({'active': False, 'message': 'No database found — is capture.py running?'})
    status = None
    if table_exists(conn, 'capture_status'):
        status = conn.execute("SELECT * FROM capture_status WHERE id = 1").fetchone()
    where, args = telemetry_condition(target_ip)
    last_event = conn.execute(f"SELECT MAX(timestamp) FROM events{where}", args).fetchone()[0]
    conn.close()

    if status:
        updated = datetime.strptime(status['updated_at'], '%Y-%m-%d %H:%M:%S')
        age = (datetime.now() - updated).total_seconds()
        return jsonify({
            'active': age < 45 and status['state'] == 'running',
            'state': status['state'],
            'message': status['message'],
            'packets': status['packets'],
            'heartbeat_age_seconds': round(age, 1),
            'last_event': last_event,
        })

    mtime = os.path.getmtime(DB_PATH)
    age = datetime.now().timestamp() - mtime
    return jsonify({'active': age < 30, 'db_age_seconds': round(age, 1), 'last_event': last_event})

@app.route('/api/device')
def api_device():
    target_ip = requested_target_ip()
    inv_device = inventory_device(target_ip)
    conn = get_db()
    if not conn:
        return jsonify({
            'target_ip': target_ip,
            'target_mac': inv_device.get('mac'),
            'mac_status': 'observed' if inv_device.get('mac') else 'not_observed',
            'identity_note': inv_device.get('identity_note'),
            'inventory': inv_device,
        })
    device = {
        'target_ip': target_ip,
        'target_mac': inv_device.get('mac'),
        'mac_status': 'observed' if inv_device.get('mac') else 'not_observed',
        'interface': inv_device.get('interface'),
        'first_seen': None,
        'last_seen': None,
        'updated_at': None,
        'names': inv_device.get('names', []),
        'vendor': inv_device.get('vendor'),
        'state': inv_device.get('state', []),
        'sources': inv_device.get('sources', []),
        'open_ports': inv_device.get('open_ports', []),
        'identity_note': inv_device.get('identity_note'),
    }
    if table_exists(conn, 'target_device'):
        row = conn.execute("SELECT * FROM target_device WHERE id = 1").fetchone()
        if row and row['target_ip'] == target_ip:
            device.update(dict(row))
            if inv_device.get('mac'):
                device['target_mac'] = inv_device.get('mac')
                device['mac_status'] = 'observed'
    where, args = telemetry_condition(target_ip)
    last_event = conn.execute(f"SELECT MAX(timestamp) FROM events{where}", args).fetchone()[0]
    device['last_event'] = last_event
    conn.close()
    return jsonify(device)

@app.route('/api/lan/inventory')
def api_lan_inventory():
    force = request.args.get('refresh') == '1'
    return jsonify(lan_inventory(force=force))

@app.route('/api/lan/summary')
def api_lan_summary():
    inv = lan_inventory(force=request.args.get('refresh') == '1')
    devices = inv.get('devices', [])
    return jsonify({
        'scanned_at': inv.get('scanned_at'),
        'interfaces': len([i for i in inv.get('interfaces', []) if i.get('state') == 'UP']),
        'networks': inv.get('networks', []),
        'local_ips': inv.get('local_ips', []),
        'observer': inv.get('observer'),
        'devices': len(devices),
        'named_devices': sum(1 for d in devices if d.get('names')),
        'macs': sum(1 for d in devices if d.get('mac')),
        'open_services': sum(len(d.get('open_ports', [])) for d in devices),
        'limits': inv.get('limits'),
    })

@app.route('/api/observer')
def api_observer():
    interfaces, networks, local_ips = local_interfaces()
    return jsonify({
        'role': 'lanman_passive_observer',
        'ips': sorted(local_ips),
        'interfaces': interfaces,
        'networks': networks,
        'note': 'Observer IPs are excluded from target telemetry metrics and are shown only as LANMan instrumentation.',
    })

@app.route('/api/target/security')
def api_target_security():
    target_ip = requested_target_ip()
    force = request.args.get('refresh') == '1'
    return jsonify(target_security_snapshot(target_ip, force=force))

@app.route('/api/stats')
def api_stats():
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify({})
    c = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')

    since_24h = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    where, target_args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)

    stats = {
        'total_packets_today':  conn.execute(
            f"SELECT COUNT(*) FROM events WHERE timestamp LIKE ?{telemetry_and}",
            (f"{today}%", *target_args)
        ).fetchone()[0] or 0,
        'total_bytes_out_today': conn.execute(
            f"SELECT SUM(length) FROM events WHERE timestamp LIKE ? AND src_ip = ?{observer_condition()[0]}",
            (f"{today}%", target_ip, *observer_condition()[1])
        ).fetchone()[0] or 0,
        'total_bytes_in_today':  conn.execute(
            f"SELECT SUM(length) FROM events WHERE timestamp LIKE ? AND dst_ip = ?{observer_condition()[0]}",
            (f"{today}%", target_ip, *observer_condition()[1])
        ).fetchone()[0] or 0,
        'unique_remote_ips_24h': conn.execute(
            "SELECT COUNT(DISTINCT CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END) "
            f"FROM events WHERE timestamp >= ?{telemetry_and}",
            (target_ip, since_24h, *target_args)
        ).fetchone()[0] or 0,
        'alerts_today': conn.execute(
            f"SELECT COUNT(*) FROM events WHERE timestamp LIKE ? AND alert IS NOT NULL{telemetry_and}",
            (f"{today}%", *target_args)
        ).fetchone()[0] or 0,
        'total_packets_all':  conn.execute(f"SELECT COUNT(*) FROM events{where}", target_args).fetchone()[0] or 0,
        'total_bytes_out_all': conn.execute(
            f"SELECT SUM(length) FROM events WHERE src_ip = ?{observer_condition()[0]}",
            (target_ip, *observer_condition()[1])
        ).fetchone()[0] or 0,
        'total_bytes_in_all':  conn.execute(
            f"SELECT SUM(length) FROM events WHERE dst_ip = ?{observer_condition()[0]}",
            (target_ip, *observer_condition()[1])
        ).fetchone()[0] or 0,
    }
    # Format byte values
    for k in ('total_bytes_out_today','total_bytes_in_today',
              'total_bytes_out_all','total_bytes_in_all'):
        stats[k + '_fmt'] = fmt_bytes(stats[k])

    conn.close()
    return jsonify(stats)

@app.route('/api/events')
def api_events():
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify([])
    limit  = min(int(request.args.get('limit', 100)), 500)
    offset = max(int(request.args.get('offset', 0)), 0)
    alerts_only = request.args.get('alerts_only') == '1'

    target_clause, target_args = telemetry_condition(target_ip, prefix='')
    target_clause = target_clause.strip()
    where_parts = []
    args = []
    if target_clause:
        where_parts.append(target_clause)
        args.extend(target_args)
    if alerts_only:
        where_parts.append("alert IS NOT NULL")
    where = "WHERE " + " AND ".join(where_parts) if where_parts else ""
    rows = conn.execute(
        f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        (*args, limit, offset)
    ).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d['direction'] = 'out' if d['src_ip'] == target_ip else 'in' if d['dst_ip'] == target_ip else 'other'
        # Annotate ports with service names
        d['src_port_name'] = PORT_NAMES.get(d['src_port'], '')
        d['dst_port_name'] = PORT_NAMES.get(d['dst_port'], '')
        result.append(d)
    return jsonify(result)

@app.route('/api/top_ips')
def api_top_ips():
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify([])
    limit = min(int(request.args.get('limit', 15)), 50)
    hours = int(request.args.get('hours', 24))
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    where, args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)

    rows = conn.execute(
        '''SELECT
             CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END AS remote_ip,
             COUNT(*)         AS connections,
             SUM(length)      AS total_bytes,
             SUM(CASE WHEN src_ip = ? THEN length ELSE 0 END) AS bytes_out,
             SUM(CASE WHEN dst_ip = ? THEN length ELSE 0 END) AS bytes_in
           FROM events
           WHERE timestamp >= ?''' + telemetry_and + '''
           GROUP BY remote_ip
           ORDER BY connections DESC
           LIMIT ?''',
        (target_ip, target_ip, target_ip, since, *args, limit)
    ).fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d['total_bytes_fmt'] = fmt_bytes(d['total_bytes'])
        d['bytes_out_fmt']   = fmt_bytes(d['bytes_out'])
        d['bytes_in_fmt']    = fmt_bytes(d['bytes_in'])
        result.append(d)
    return jsonify(result)

@app.route('/api/behavior')
def api_behavior():
    target_ip = requested_target_ip()
    """Passive behavior summary: timing, fan-out, ports, and alert volume."""
    conn = get_db()
    if not conn:
        return jsonify({})
    hours = min(max(int(request.args.get('hours', 24)), 1), 24 * 30)
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    where, args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)

    row = conn.execute(
        '''SELECT
             COUNT(*) AS packets,
             SUM(length) AS bytes_total,
             SUM(CASE WHEN src_ip = ? THEN length ELSE 0 END) AS bytes_out,
             SUM(CASE WHEN dst_ip = ? THEN length ELSE 0 END) AS bytes_in,
             COUNT(DISTINCT CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END) AS remote_ips,
             COUNT(DISTINCT CASE WHEN src_ip = ? THEN dst_port ELSE src_port END) AS remote_ports,
             SUM(CASE WHEN alert IS NOT NULL THEN 1 ELSE 0 END) AS alerts,
             MIN(timestamp) AS first_seen,
             MAX(timestamp) AS last_seen
           FROM events
           WHERE timestamp >= ?''' + telemetry_and,
        (target_ip, target_ip, target_ip, target_ip, since, *args)
    ).fetchone()

    busiest = conn.execute(
        '''SELECT substr(timestamp, 12, 2) AS hour, COUNT(*) AS packets,
                  SUM(length) AS bytes_total
           FROM events
           WHERE timestamp >= ?''' + telemetry_and + '''
           GROUP BY hour
           ORDER BY packets DESC
           LIMIT 1''',
        (since, *args)
    ).fetchone()

    summary = dict(row) if row else {}
    for key in ('bytes_total', 'bytes_out', 'bytes_in'):
        summary[f'{key}_fmt'] = fmt_bytes(summary.get(key) or 0)
    summary['hours'] = hours
    summary['busiest_hour'] = dict(busiest) if busiest else None
    conn.close()
    return jsonify(summary)

@app.route('/api/protocols')
def api_protocols():
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify([])
    hours = int(request.args.get('hours', 24))
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    where, args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)
    rows = conn.execute(
        f"SELECT protocol, COUNT(*) AS cnt FROM events WHERE timestamp >= ?{telemetry_and} GROUP BY protocol ORDER BY cnt DESC",
        (since, *args)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/hourly')
def api_hourly():
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify([])
    days = int(request.args.get('days', 2))
    since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    where, args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)
    rows = conn.execute(
        '''SELECT substr(timestamp, 1, 13) AS hour,
                  SUM(CASE WHEN src_ip = ? THEN length ELSE 0 END) AS bytes_out,
                  SUM(CASE WHEN dst_ip = ? THEN length ELSE 0 END) AS bytes_in,
                  SUM(CASE WHEN src_ip = ? THEN 1 ELSE 0 END) AS packets_out,
                  SUM(CASE WHEN dst_ip = ? THEN 1 ELSE 0 END) AS packets_in
           FROM events
           WHERE timestamp >= ?''' + telemetry_and + '''
           GROUP BY hour
           ORDER BY hour''',
        (target_ip, target_ip, target_ip, target_ip, since, *args)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/daily')
def api_daily():
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify([])
    days = min(max(int(request.args.get('days', 30)), 1), 365)
    since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    where, args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)
    rows = conn.execute(
        '''SELECT substr(timestamp, 1, 10) AS day,
                  SUM(CASE WHEN src_ip = ? THEN length ELSE 0 END) AS bytes_out,
                  SUM(CASE WHEN dst_ip = ? THEN length ELSE 0 END) AS bytes_in,
                  SUM(CASE WHEN src_ip = ? THEN 1 ELSE 0 END) AS packets_out,
                  SUM(CASE WHEN dst_ip = ? THEN 1 ELSE 0 END) AS packets_in,
                  SUM(CASE WHEN alert IS NOT NULL THEN 1 ELSE 0 END) AS alerts
           FROM events
           WHERE timestamp >= ?''' + telemetry_and + '''
           GROUP BY day
           ORDER BY day''',
        (target_ip, target_ip, target_ip, target_ip, since, *args)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/ports')
def api_ports():
    """Top destination ports the target connects to."""
    target_ip = requested_target_ip()
    conn = get_db()
    if not conn:
        return jsonify([])
    hours = int(request.args.get('hours', 24))
    since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    where, args = telemetry_condition(target_ip)
    telemetry_and = where.replace(' WHERE ', ' AND ', 1)
    rows = conn.execute(
        '''SELECT
             CASE WHEN src_ip = ? THEN dst_port ELSE src_port END AS port,
             COUNT(*) AS cnt
           FROM events
           WHERE timestamp >= ?
            ''' + telemetry_and + '''
             AND (CASE WHEN src_ip = ? THEN dst_port ELSE src_port END) IS NOT NULL
           GROUP BY port
           ORDER BY cnt DESC
           LIMIT 20''',
        (target_ip, since, *args, target_ip)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d['service'] = PORT_NAMES.get(d['port'], '')
        result.append(d)
    return jsonify(result)

@app.route('/api/db/scrub', methods=['POST'])
def api_db_scrub():
    # Only scrub if capture is actively running (guard: don't scrub if manually paused)
    svc = subprocess.run(
        ['systemctl', 'is-active', 'lanman-capture'],
        capture_output=True, text=True, timeout=5
    )
    if svc.stdout.strip() != 'active':
        return jsonify({'ok': False, 'reason': 'capture not active, scrub skipped'})

    days = int((request.get_json(silent=True) or {}).get('days', 30))
    cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')

    # Stop capture so we're the only writer, then restart when done
    subprocess.run(['sudo', 'systemctl', 'stop', 'lanman-capture'],
                   capture_output=True, timeout=10)
    try:
        conn = get_db()
        if not conn:
            return jsonify({'ok': False, 'reason': 'no database'})
        deleted = conn.execute('DELETE FROM events WHERE timestamp < ?', (cutoff,)).rowcount
        conn.commit()
        conn.close()
        sqlite3.connect(DB_PATH, timeout=10).execute('VACUUM').connection.close()
    finally:
        subprocess.run(['sudo', 'systemctl', 'start', 'lanman-capture'],
                       capture_output=True, timeout=10)

    return jsonify({'ok': True, 'deleted': deleted, 'cutoff': cutoff, 'days': days})

@app.route('/api/target/set', methods=['POST'])
def api_target_set():
    data = request.get_json(silent=True) or {}
    ip_raw = data.get('ip', '').strip()
    try:
        ip = str(ipaddress.ip_address(ip_raw))
    except ValueError:
        return jsonify({'ok': False, 'error': f'Invalid IP: {ip_raw}'}), 400

    with open(CONF_PATH, 'w') as f:
        f.write(ip + '\n')

    # Restart capture so it picks up the new target
    result = subprocess.run(
        ['sudo', 'systemctl', 'restart', 'lanman-capture'],
        capture_output=True, text=True, timeout=15
    )
    return jsonify({'ok': result.returncode == 0, 'target': ip, 'stderr': result.stderr.strip()})

@app.route('/api/target/clear', methods=['POST'])
def api_target_clear():
    with open(CONF_PATH, 'w') as f:
        f.write('none\n')
    result = subprocess.run(
        ['sudo', 'systemctl', 'restart', 'lanman-capture'],
        capture_output=True, text=True, timeout=15
    )
    return jsonify({'ok': result.returncode == 0, 'stderr': result.stderr.strip()})

@app.route('/api/target/current')
def api_target_current():
    try:
        with open(CONF_PATH) as f:
            ip = f.read().strip()
            if ip == 'none':
                ip = None
    except OSError:
        ip = None
    return jsonify({'target': ip})

@app.route('/api/capture/service-status')
def api_capture_service_status():
    result = subprocess.run(
        ['systemctl', 'is-active', 'lanman-capture'],
        capture_output=True, text=True, timeout=5
    )
    state = result.stdout.strip()  # 'active', 'inactive', 'failed', 'activating', etc.
    result2 = subprocess.run(
        ['systemctl', 'show', 'lanman-capture', '--property=ActiveEnterTimestamp,ExecMainPID'],
        capture_output=True, text=True, timeout=5
    )
    props = {}
    for line in result2.stdout.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            props[k] = v
    return jsonify({
        'state': state,
        'active': state == 'active',
        'pid': props.get('ExecMainPID'),
        'since': props.get('ActiveEnterTimestamp'),
    })

@app.route('/api/capture/control', methods=['POST'])
def api_capture_control():
    data = request.get_json(silent=True) or {}
    action = data.get('action', '')
    if action not in ('start', 'stop', 'restart'):
        return jsonify({'ok': False, 'error': 'invalid action'}), 400
    result = subprocess.run(
        ['sudo', 'systemctl', action, 'lanman-capture'],
        capture_output=True, text=True, timeout=15
    )
    return jsonify({
        'ok': result.returncode == 0,
        'action': action,
        'stderr': result.stderr.strip(),
    })

if __name__ == '__main__':
    print(f"[dashboard] Serving on http://0.0.0.0:{PORT}")
    print(f"[dashboard] Default target: {DEFAULT_TARGET_IP}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
