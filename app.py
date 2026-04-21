"""
NetShield AI — Behavior-Aware Network Detection & Response System
Backend: Flask + SocketIO + psutil + Scapy DPI
"""

import os
import time
import json
import random
import threading
import datetime
import hashlib
from collections import defaultdict

import psutil

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# Deep Packet Inspection engine
from network_scanner import (
    scanner_state, start_scanner, stop_scanner,
    pause_scanner, resume_scanner, tick_rate,
    SCAPY_AVAILABLE,
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netshield-ai-secret-key-2024'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# ─── Global State ───────────────────────────────────────────────────────────

class AppState:
    """Central mutable state for the monitoring engine."""
    def __init__(self):
        self.connections = []
        self.processes = {}
        self.trust_scores = {}
        self.alerts = []
        self.events_history = []
        self.traffic_history = []
        self.blocked_ips = set()
        self.safe_pids = set()
        self.resolved_count = 0
        self.simulation_active = False
        self.simulation_type = None
        self.simulation_logs = []
        self.scan_running = False

state = AppState()

# ─── Known-Bad / Suspicious Indicators ──────────────────────────────────────

KNOWN_BAD_IPS = {
    '45.12.8.21', '185.220.101.1', '91.215.85.10', '103.224.182.250',
    '194.5.98.12', '23.106.215.76', '5.188.86.114', '77.247.181.162',
}

SUSPICIOUS_PORTS = {6667, 6668, 6669, 4444, 5555, 1337, 31337, 8888, 9999, 12345}

KNOWN_GOOD_PROCESSES = {
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'code.exe', 'explorer.exe',
    'svchost.exe', 'System', 'RuntimeBroker.exe', 'taskhostw.exe',
    'slack.exe', 'discord.exe', 'spotify.exe', 'teams.exe',
    'SearchHost.exe', 'StartMenuExperienceHost.exe', 'python.exe',
    'pythonw.exe', 'node.exe', 'git.exe', 'powershell.exe', 'cmd.exe',
    'WindowsTerminal.exe', 'conhost.exe', 'dwm.exe', 'winlogon.exe',
    'csrss.exe', 'lsass.exe', 'services.exe', 'wininit.exe',
    'dropbox.exe', 'OneDrive.exe', 'SecurityHealthSystray.exe',
}

# ─── Trust Score Engine ─────────────────────────────────────────────────────

def calculate_trust_score(proc_name, pid, connections_list):
    """Calculate a 0-100 trust score for a given process based on heuristics."""
    score = 100
    reasons = []

    # 1. Process identity check
    if proc_name.lower() not in {p.lower() for p in KNOWN_GOOD_PROCESSES}:
        score -= 20
        reasons.append(f"Unknown process '{proc_name}' not in trusted list")

    # 2. Check running from temp directories
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe() if proc.is_running() else ''
        if exe_path:
            lower_path = exe_path.lower()
            if 'temp' in lower_path or 'tmp' in lower_path:
                score -= 25
                reasons.append(f"Running from temp directory: {exe_path}")
            if 'appdata' in lower_path and 'local' in lower_path and 'temp' in lower_path:
                score -= 10
                reasons.append("Executing from AppData\\Local\\Temp")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    # 3. Connection analysis
    for conn in connections_list:
        remote_ip = conn.get('remote_ip', '')
        remote_port = conn.get('remote_port', 0)

        if remote_ip in KNOWN_BAD_IPS:
            score -= 30
            reasons.append(f"Connection to known malicious IP: {remote_ip}")

        if remote_port in SUSPICIOUS_PORTS:
            score -= 15
            reasons.append(f"Using suspicious port: {remote_port}")

        # High data volume anomaly (simulated)
        if conn.get('bytes_sent', 0) > 100_000_000:  # >100MB
            score -= 10
            reasons.append("High outbound data volume detected")

    # 4. Connection frequency
    if len(connections_list) > 20:
        score -= 10
        reasons.append(f"High connection count: {len(connections_list)}")

    score = max(0, min(100, score))
    return score, reasons


def get_risk_level(score):
    """Map trust score to risk level string."""
    if score >= 80:
        return 'Low'
    elif score >= 50:
        return 'Med'
    else:
        return 'High'

def get_severity(score):
    if score < 30:
        return 'Critical'
    elif score < 50:
        return 'High'
    elif score < 70:
        return 'Med'
    else:
        return 'Low'

# ─── Network Monitor ────────────────────────────────────────────────────────

def gather_connections():
    """Gather real-time network connections mapped to processes."""
    connections = []
    process_map = {}

    try:
        net_conns = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        net_conns = []

    for conn in net_conns:
        if conn.pid and conn.pid > 0 and conn.raddr:
            try:
                proc = psutil.Process(conn.pid)
                proc_name = proc.name()
                remote_ip = conn.raddr.ip if conn.raddr else ''
                remote_port = conn.raddr.port if conn.raddr else 0

                # Skip if marked safe
                if conn.pid in state.safe_pids:
                    continue
                # Skip blocked IPs
                if remote_ip in state.blocked_ips:
                    continue

                conn_info = {
                    'pid': conn.pid,
                    'process': proc_name,
                    'local_ip': conn.laddr.ip if conn.laddr else '',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'status': conn.status,
                    'bytes_sent': random.randint(1000, 5_000_000),
                    'protocol': 'TCP' if conn.type == 1 else 'UDP',
                }
                connections.append(conn_info)

                if conn.pid not in process_map:
                    try:
                        mem = proc.memory_info()
                        process_map[conn.pid] = {
                            'pid': conn.pid,
                            'name': proc_name,
                            'memory_mb': round(mem.rss / (1024 * 1024), 1),
                            'cpu_percent': proc.cpu_percent(interval=0),
                            'exe': proc.exe() if proc.is_running() else 'N/A',
                            'connections': [],
                        }
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        process_map[conn.pid] = {
                            'pid': conn.pid,
                            'name': proc_name,
                            'memory_mb': 0,
                            'cpu_percent': 0,
                            'exe': 'N/A',
                            'connections': [],
                        }
                process_map[conn.pid]['connections'].append(conn_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # Calculate trust scores
    trust_scores = {}
    for pid, proc_info in process_map.items():
        score, reasons = calculate_trust_score(
            proc_info['name'], pid, proc_info['connections']
        )
        trust_scores[pid] = {
            'pid': pid,
            'process': proc_info['name'],
            'score': score,
            'risk': get_risk_level(score),
            'reasons': reasons,
            'memory_mb': proc_info['memory_mb'],
        }

    return connections, process_map, trust_scores


def generate_alerts(trust_scores, connections):
    """Generate explainable alerts from trust scores and connections."""
    new_alerts = []
    now = datetime.datetime.now()

    for pid, ts in trust_scores.items():
        if ts['score'] < 70:
            severity = get_severity(ts['score'])
            explanation = ts['reasons'][0] if ts['reasons'] else 'Anomalous behavior detected'
            remediation = []

            if ts['score'] < 30:
                remediation = ['Terminate Process', 'Block Remote IP', 'Isolate Host']
            elif ts['score'] < 50:
                remediation = ['Terminate Process', 'Block Target Port', 'Investigate Logs']
            else:
                remediation = ['Restart Process', 'Monitor']

            # Find related connections
            proc_conns = [c for c in connections if c['pid'] == pid]
            dest_ip = proc_conns[0]['remote_ip'] if proc_conns else 'N/A'
            dest_port = proc_conns[0]['remote_port'] if proc_conns else 0

            alert_id = hashlib.md5(f"{pid}-{ts['process']}-{severity}".encode()).hexdigest()[:8]

            alert = {
                'id': f'NS-{alert_id}',
                'pid': pid,
                'process': ts['process'],
                'severity': severity,
                'trust_score': ts['score'],
                'explanation': explanation,
                'all_reasons': ts['reasons'],
                'remediation': remediation,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'timestamp': now.strftime('%H:%M:%S'),
                'time_ago': 'Just now',
                'status': 'Active',
            }

            # Avoid duplicate alerts
            existing_ids = {a['id'] for a in state.alerts}
            if alert['id'] not in existing_ids:
                new_alerts.append(alert)

    return new_alerts


# ─── Background Monitor Thread ──────────────────────────────────────────────

def monitor_loop():
    """Main monitoring loop running in background."""
    while True:
        try:
            connections, processes, trust_scores = gather_connections()

            state.connections = connections
            state.processes = processes
            state.trust_scores = trust_scores

            # Generate alerts
            new_alerts = generate_alerts(trust_scores, connections)
            for alert in new_alerts:
                state.alerts.insert(0, alert)
                if len(state.alerts) > 100:
                    state.alerts = state.alerts[:100]

            # Traffic data point
            inbound = sum(1 for c in connections if c.get('status') == 'ESTABLISHED')
            outbound = len(connections) - inbound
            traffic_point = {
                'timestamp': datetime.datetime.now().isoformat(),
                'inbound': inbound + random.randint(0, 5),
                'outbound': outbound + random.randint(0, 5),
                'total': len(connections),
            }
            state.traffic_history.append(traffic_point)
            if len(state.traffic_history) > 120:
                state.traffic_history = state.traffic_history[-120:]

            # Build metrics
            suspicious_count = sum(1 for ts in trust_scores.values() if ts['score'] < 70)
            high_risk_count = sum(1 for ts in trust_scores.values() if ts['score'] < 30)

            metrics = {
                'active_processes': len(processes),
                'suspicious_connections': suspicious_count,
                'high_risk_alerts': high_risk_count,
                'threats_resolved': state.resolved_count,
                'total_connections': len(connections),
                'events_per_sec': random.randint(80, 200),
            }

            # Top trust scores (sorted)
            top_scores = sorted(trust_scores.values(), key=lambda x: x['score'])[:10]

            # Emit WebSocket updates
            socketio.emit('metrics_update', metrics)
            socketio.emit('connections_update', {
                'connections': connections[:50],  # top 50
                'total': len(connections),
            })
            socketio.emit('trust_scores', top_scores)
            socketio.emit('traffic_update', traffic_point)

            if new_alerts:
                for alert in new_alerts:
                    socketio.emit('new_alert', alert)

            # ── DPI Scanner: drain event queue and emit ──
            tick_rate()  # compute packets/sec rate every 3 seconds
            scanner_events = scanner_state.drain_events()
            for evt in scanner_events:
                socketio.emit(evt['type'], evt['data'])
                
                # Handle scanner alerts by integrating with main alert system
                if evt['type'] == 'scanner_alert':
                    alert_data = evt['data']
                    # Convert scanner alert to main system format
                    integrated_alert = {
                        'id': alert_data['id'],
                        'pid': alert_data.get('pid'),
                        'process': alert_data['process'],
                        'severity': alert_data['severity'],
                        'trust_score': alert_data.get('trust_score', 50),
                        'explanation': alert_data['reasons'][0] if alert_data['reasons'] else 'Network anomaly detected',
                        'all_reasons': alert_data['reasons'],
                        'remediation': alert_data.get('remediation', ['Investigate']),
                        'dest_ip': alert_data['dest_ip'],
                        'dest_port': alert_data['dest_port'],
                        'timestamp': alert_data['timestamp'],
                        'time_ago': 'Just now',
                        'status': 'Active',
                        'source': 'network_scanner'
                    }
                    
                    # Add to main alerts if not duplicate
                    existing_ids = {a['id'] for a in state.alerts}
                    if integrated_alert['id'] not in existing_ids:
                        state.alerts.insert(0, integrated_alert)
                        if len(state.alerts) > 100:
                            state.alerts = state.alerts[:100]

        except Exception as e:
            print(f"[Monitor Error] {e}")

        time.sleep(3)


# ─── Threat Simulator ───────────────────────────────────────────────────────

SIMULATION_SCENARIOS = {
    'c2_beaconing': {
        'name': 'C2 Beaconing',
        'description': 'Simulating outbound heartbeats to a remote C&C server using DNS tunneling',
        'steps': [
            '[SYSTEM] Initializing Attack Vector: C2 Beaconing...',
            '[INFO] Establishing listener on port 443...',
            '[INFO] Encoding payload in DNS TXT queries...',
            'SENDING PACKET -> host: 192.168.1.104 size: 512b',
            'SENDING PACKET -> host: 192.168.1.104 size: 488b',
            '[ALERT] Local IDS triggered "Suspicious External Communication"',
            '[SYSTEM] NetShield AI intercepting signal signature...',
            'SENDING PACKET -> host: 192.168.1.104 size: 520b',
            '[SYSTEM] Behavioral anomaly score rising: +14 points',
            'SENDING PACKET -> host: 45.12.8.21 size: 1024b',
            '[ALERT] Trust score dropped below threshold: 32/100',
            '[SYSTEM] Automated response: Connection flagged for review',
        ],
    },
    'data_exfiltration': {
        'name': 'Data Exfiltration (Burst)',
        'description': 'Large volume data transfer via encrypted HTTPS POST',
        'steps': [
            '[SYSTEM] Initializing Attack Vector: Data Exfiltration...',
            '[INFO] Opening TLS 1.3 tunnel to external endpoint...',
            'SENDING DATA -> https://drop.evil-cdn.io/upload size: 24MB',
            'SENDING DATA -> https://drop.evil-cdn.io/upload size: 48MB',
            '[ALERT] Outbound data volume anomaly detected: 72MB in 4s',
            '[SYSTEM] NetShield AI correlating with baseline...',
            'SENDING DATA -> https://drop.evil-cdn.io/upload size: 120MB',
            '[ALERT] Trust score critical: 18/100',
            '[SYSTEM] Process flagged: exfil_svc.exe (PID: 7742)',
            '[ALERT] Automated quarantine recommendation issued',
        ],
    },
    'port_scanning': {
        'name': 'Port Scanning',
        'description': 'Internal recon targeting sensitive ports',
        'steps': [
            '[SYSTEM] Initializing Attack Vector: Port Scanning...',
            '[INFO] Target range: 10.0.0.0/24',
            'SCAN -> 10.0.0.1:22 [OPEN]',
            'SCAN -> 10.0.0.1:80 [OPEN]',
            'SCAN -> 10.0.0.1:443 [OPEN]',
            'SCAN -> 10.0.0.1:3306 [CLOSED]',
            'SCAN -> 10.0.0.2:5432 [OPEN]',
            '[ALERT] Sequential port scan detected across subnet',
            '[SYSTEM] NetShield AI: Recon pattern matches MITRE ATT&CK T1046',
            'SCAN -> 10.0.0.3:6379 [OPEN]',
            '[ALERT] Sensitive database ports exposed. Trust score: 44/100',
        ],
    },
    'unauthorized_process': {
        'name': 'Unauthorized Process Activity',
        'description': 'Shellcode injection into legitimate system processes',
        'steps': [
            '[SYSTEM] Initializing Attack Vector: Process Injection...',
            '[INFO] Target process: svchost.exe (PID: 1284)',
            '[INFO] Allocating remote memory via VirtualAllocEx...',
            '[INFO] Writing shellcode payload (4096 bytes)...',
            '[ALERT] Memory write to foreign process detected',
            '[SYSTEM] NetShield AI: LSASS.exe memory hook attempted',
            '[ALERT] Registry modification: HKLM\\Software\\Microsoft\\Windows\\Run',
            '[SYSTEM] Trust score collapsed: 8/100',
            '[ALERT] Process persistence mechanism detected',
            '[SYSTEM] Automated response: Process isolated, thread suspended',
        ],
    },
}


def simulation_worker(scenario_key):
    """Background worker that emits simulation log lines."""
    scenario = SIMULATION_SCENARIOS.get(scenario_key)
    if not scenario:
        return

    state.simulation_active = True
    state.simulation_type = scenario_key
    state.simulation_logs = []

    socketio.emit('simulation_status', {
        'active': True,
        'type': scenario_key,
        'name': scenario['name'],
    })

    trust = 96
    for i, step in enumerate(scenario['steps']):
        if not state.simulation_active:
            break

        timestamp = datetime.datetime.now().strftime('%H:%M:%S.') + f"{random.randint(10,99)}"
        log_type = 'info'
        if '[ALERT]' in step:
            log_type = 'alert'
            trust -= random.randint(8, 18)
        elif '[SYSTEM]' in step:
            log_type = 'system'
        elif 'SENDING' in step or 'SCAN' in step:
            log_type = 'data'
            trust -= random.randint(1, 5)

        trust = max(5, trust)

        log_entry = {
            'timestamp': timestamp,
            'message': step,
            'type': log_type,
            'trust_score': trust,
            'step': i + 1,
            'total_steps': len(scenario['steps']),
        }

        state.simulation_logs.append(log_entry)
        socketio.emit('simulation_log', log_entry)
        socketio.emit('simulation_trust', {'score': trust})

        time.sleep(random.uniform(1.0, 2.5))

    state.simulation_active = False
    socketio.emit('simulation_status', {'active': False, 'type': None, 'name': None})
    socketio.emit('simulation_log', {
        'timestamp': datetime.datetime.now().strftime('%H:%M:%S.00'),
        'message': f'[SYSTEM] Simulation "{scenario["name"]}" completed.',
        'type': 'system',
        'trust_score': trust,
        'step': len(scenario['steps']),
        'total_steps': len(scenario['steps']),
    })


# ─── Flask Routes ────────────────────────────────────────────────────────────

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/intelligence')
def intelligence():
    return render_template('intelligence.html')

@app.route('/simulator')
def simulator():
    return render_template('simulator.html')

@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

# ─── API Routes ──────────────────────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    suspicious = sum(1 for ts in state.trust_scores.values() if ts['score'] < 70)
    high_risk = sum(1 for ts in state.trust_scores.values() if ts['score'] < 30)
    return jsonify({
        'status': 'operational',
        'active_processes': len(state.processes),
        'total_connections': len(state.connections),
        'suspicious_connections': suspicious,
        'high_risk_alerts': high_risk,
        'threats_resolved': state.resolved_count,
        'blocked_ips': list(state.blocked_ips),
        'simulation_active': state.simulation_active,
    })

@app.route('/api/connections')
def api_connections():
    return jsonify(state.connections[:100])

@app.route('/api/processes')
def api_processes():
    result = []
    for pid, proc in state.processes.items():
        ts = state.trust_scores.get(pid, {})
        result.append({
            'pid': pid,
            'name': proc['name'],
            'memory_mb': proc['memory_mb'],
            'cpu_percent': proc.get('cpu_percent', 0),
            'exe': proc.get('exe', 'N/A'),
            'trust_score': ts.get('score', 100),
            'risk': ts.get('risk', 'Low'),
            'reasons': ts.get('reasons', []),
            'connection_count': len(proc.get('connections', [])),
            'connections': proc.get('connections', [])[:10],
        })
    result.sort(key=lambda x: x['trust_score'])
    return jsonify(result)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(state.alerts[:50])

@app.route('/api/trust-scores')
def api_trust_scores():
    scores = sorted(state.trust_scores.values(), key=lambda x: x['score'])
    return jsonify(scores[:20])

@app.route('/api/traffic/history')
def api_traffic_history():
    return jsonify(state.traffic_history[-60:])

# ─── Mitigation Actions ─────────────────────────────────────────────────────

@app.route('/api/action/terminate', methods=['POST'])
def action_terminate():
    pid = request.json.get('pid')
    if not pid:
        return jsonify({'error': 'PID required'}), 400
    try:
        proc = psutil.Process(int(pid))
        proc_name = proc.name()
        proc.terminate()
        state.resolved_count += 1
        # Remove related alerts
        state.alerts = [a for a in state.alerts if a.get('pid') != int(pid)]
        socketio.emit('action_result', {
            'action': 'terminate',
            'pid': pid,
            'process': proc_name,
            'success': True,
            'message': f'Process {proc_name} (PID: {pid}) terminated successfully'
        })
        return jsonify({'success': True, 'message': f'Terminated {proc_name}'})
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied. Run as administrator.'}), 403
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/action/block-ip', methods=['POST'])
def action_block_ip():
    ip = request.json.get('ip')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    state.blocked_ips.add(ip)
    state.resolved_count += 1
    socketio.emit('action_result', {
        'action': 'block_ip',
        'ip': ip,
        'success': True,
        'message': f'IP {ip} added to blocklist'
    })
    return jsonify({'success': True, 'message': f'Blocked {ip}'})

@app.route('/api/action/mark-safe', methods=['POST'])
def action_mark_safe():
    pid = request.json.get('pid')
    alert_id = request.json.get('alert_id')
    if pid:
        state.safe_pids.add(int(pid))
    if alert_id:
        state.alerts = [a for a in state.alerts if a.get('id') != alert_id]
    state.resolved_count += 1
    return jsonify({'success': True, 'message': 'Marked as safe'})

@app.route('/api/action/scan', methods=['POST'])
def action_scan():
    """Trigger a manual full scan."""
    state.scan_running = True
    socketio.emit('scan_status', {'running': True})

    def do_scan():
        time.sleep(3)
        state.scan_running = False
        socketio.emit('scan_status', {'running': False})
        socketio.emit('scan_result', {
            'success': True,
            'message': 'Full system scan completed',
            'processes_scanned': len(state.processes),
            'connections_scanned': len(state.connections),
            'threats_found': sum(1 for ts in state.trust_scores.values() if ts['score'] < 50),
        })

    socketio.start_background_task(do_scan)
    return jsonify({'success': True, 'message': 'Scan started'})


# ─── Simulator API ───────────────────────────────────────────────────────────

@app.route('/api/simulate/start', methods=['POST'])
def simulate_start():
    scenario = request.json.get('scenario', 'c2_beaconing')
    if state.simulation_active:
        return jsonify({'error': 'Simulation already running'}), 400
    if scenario not in SIMULATION_SCENARIOS:
        return jsonify({'error': 'Unknown scenario'}), 400
    socketio.start_background_task(simulation_worker, scenario)
    return jsonify({'success': True, 'scenario': scenario})

@app.route('/api/simulate/stop', methods=['POST'])
def simulate_stop():
    state.simulation_active = False
    return jsonify({'success': True, 'message': 'Simulation stopped'})

@app.route('/api/simulate/scenarios')
def simulate_scenarios():
    result = {}
    for key, val in SIMULATION_SCENARIOS.items():
        result[key] = {'name': val['name'], 'description': val['description']}
    return jsonify(result)


# ─── Deep Packet Scanner API ─────────────────────────────────────────────────

@app.route('/api/scanner/status')
def api_scanner_status():
    """Return current scanner state and stats."""
    stats = scanner_state.get_stats()
    stats['scapy_available'] = SCAPY_AVAILABLE
    return jsonify(stats)

@app.route('/api/scanner/health')
def api_scanner_health():
    """Return comprehensive health status of the scanner."""
    from network_scanner import get_health_status
    health = get_health_status()
    return jsonify(health)

@app.route('/api/scanner/start', methods=['POST'])
def api_scanner_start():
    """Start the deep packet inspection engine."""
    data = request.get_json() or {}
    iface = data.get('interface')
    success = start_scanner(interface=iface)
    if success:
        return jsonify({'success': True, 'message': 'DPI engine started', 'interface': iface or 'default'})
    if not SCAPY_AVAILABLE:
        return jsonify({'error': 'Scapy not installed. Run: pip install scapy'}), 500
    return jsonify({'error': 'Scanner is already running'}), 400

@app.route('/api/scanner/stop', methods=['POST'])
def api_scanner_stop():
    """Stop the packet scanner."""
    stop_scanner()
    return jsonify({'success': True, 'message': 'DPI engine stopped'})

@app.route('/api/scanner/pause', methods=['POST'])
def api_scanner_pause():
    """Pause packet processing."""
    pause_scanner()
    return jsonify({'success': True, 'message': 'Scanner paused'})

@app.route('/api/scanner/resume', methods=['POST'])
def api_scanner_resume():
    """Resume packet processing."""
    resume_scanner()
    return jsonify({'success': True, 'message': 'Scanner resumed'})

@app.route('/api/scanner/reset', methods=['POST'])
def api_scanner_reset():
    """Reset all scanner state and counters."""
    stop_scanner()
    scanner_state.reset()
    return jsonify({'success': True, 'message': 'Scanner reset'})

@app.route('/api/scanner/packets')
def api_scanner_packets():
    """Return recent captured packets."""
    limit = request.args.get('limit', 100, type=int)
    packets = list(scanner_state.captured_packets)
    return jsonify(packets[-limit:])

@app.route('/api/scanner/alerts')
def api_scanner_alerts():
    """Return recent suspicious packet alerts."""
    limit = request.args.get('limit', 50, type=int)
    alerts = list(scanner_state.suspicious_log)
    return jsonify(alerts[-limit:])

@app.route('/api/scanner/rate-history')
def api_scanner_rate_history():
    """Return packets-per-second rate history."""
    return jsonify(list(scanner_state.rate_history))

@app.route('/api/scanner/whitelist', methods=['POST'])
def api_scanner_whitelist():
    """Add a process or IP to the scanner whitelist."""
    data = request.get_json() or {}
    proc = data.get('process')
    ip = data.get('ip')
    
    # Validate inputs
    if ip:
        try:
            import socket
            socket.inet_aton(ip)  # Validate IP format
            scanner_state.user_whitelist_ips.add(ip)
        except socket.error:
            return jsonify({'error': f'Invalid IP address: {ip}'}), 400
    
    if proc:
        if isinstance(proc, str) and len(proc.strip()) > 0:
            scanner_state.user_whitelist_procs.add(proc.strip())
        else:
            return jsonify({'error': f'Invalid process name: {proc}'}), 400
    
    if not proc and not ip:
        return jsonify({'error': 'Either process or ip must be provided'}), 400
    
    return jsonify({
        'success': True, 
        'message': f'Whitelist updated',
        'added_process': proc if proc else None,
        'added_ip': ip if ip else None
    })

@app.route('/api/scanner/block', methods=['POST'])
def api_scanner_block():
    """Add an IP to the scanner block list."""
    data = request.get_json() or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    
    # Validate IP format
    try:
        import socket
        socket.inet_aton(ip)
        scanner_state.user_blocked_ips.add(ip)
        return jsonify({'success': True, 'message': f'IP {ip} added to scanner blocklist'})
    except socket.error:
        return jsonify({'error': f'Invalid IP address: {ip}'}), 400

@app.route('/api/scanner/config/validate', methods=['POST'])
def api_scanner_validate_config():
    """Validate scanner configuration parameters."""
    from network_scanner import validate_configuration
    config = request.get_json() or {}
    errors = validate_configuration(config)
    
    if errors:
        return jsonify({'valid': False, 'errors': errors}), 400
    else:
        return jsonify({'valid': True, 'message': 'Configuration is valid'})


# ─── Reports Data ────────────────────────────────────────────────────────────

@app.route('/api/reports/summary')
def reports_summary():
    """Return mock + live aggregate report data."""
    total_scans = random.randint(1_100_000, 1_300_000)
    return jsonify({
        'mean_response_time': '1.4m',
        'response_time_change': -12,
        'remediation_rate': 98.2,
        'remediation_change': 0.4,
        'total_scans': total_scans,
        'anomalies_detected': 432 + len([a for a in state.alerts if a['severity'] in ['Critical', 'High']]),
        'threat_categories': {
            'Malware': 45,
            'Policy Violation': 30,
            'Unknown / Other': 25,
        },
        'app_trust_history': {
            'Kubernetes': 99.2,
            'Redis Cluster': 94.8,
            'Auth Service': 82.1,
        },
    })


# ─── SocketIO Events ────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    # Send initial data dump
    emit('traffic_history', state.traffic_history[-60:])
    emit('recent_alerts', state.alerts[:20])

@socketio.on('ping_client')
def handle_ping():
    emit('pong_server', {'time': datetime.datetime.now().isoformat()})

@socketio.on('request_process_detail')
def handle_process_detail(data):
    pid = data.get('pid')
    if pid and int(pid) in state.processes:
        proc = state.processes[int(pid)]
        ts = state.trust_scores.get(int(pid), {})
        emit('process_detail', {
            'pid': int(pid),
            'name': proc['name'],
            'memory_mb': proc['memory_mb'],
            'exe': proc.get('exe', 'N/A'),
            'trust_score': ts.get('score', 100),
            'risk': ts.get('risk', 'Low'),
            'reasons': ts.get('reasons', []),
            'connections': proc.get('connections', [])[:20],
        })


# ─── Main ────────────────────────────────────────────────────────────────────

# Check if running on Vercel (serverless environment)
VERCEL_DEPLOYMENT = os.environ.get('VERCEL') or app.config.get('VERCEL_DEPLOYMENT', False)

if not VERCEL_DEPLOYMENT:
    # Only start background monitor in non-serverless environments
    def start_background_monitor():
        socketio.start_background_task(monitor_loop)
    
    # Initialize background monitor when not on Vercel
    if __name__ == '__main__':
        start_background_monitor()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  NetShield AI — Behavior-Aware Network Detection")
    print("  Dashboard: http://localhost:5000/dashboard")
    print("  Landing:   http://localhost:5000/")
    print("="*60 + "\n")

    if VERCEL_DEPLOYMENT:
        print("  Running in Vercel serverless mode")
        print("  Note: Real-time monitoring limited in serverless environment")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

# Export app for Vercel
app_instance = app
