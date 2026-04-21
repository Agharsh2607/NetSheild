"""
NetShield AI — Deep Packet Inspection Engine
Uses Scapy for real-time packet capture and analysis.
Integrates with the main Flask+SocketIO backend via a thread-safe event queue.
"""

import threading
import hashlib
import socket
import time
from datetime import datetime
from collections import defaultdict, deque

import psutil

# Try to import scapy – graceful fallback if not installed / no admin
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─── Configuration ──────────────────────────────────────────────────────────

# Processes that are expected to make network calls (reduce noise)
WHITELIST_PROCS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe", "spotify.exe",
    "slack.exe", "discord.exe", "teams.exe", "code.exe", "explorer.exe",
    "System", "RuntimeBroker.exe", "SearchHost.exe", "OneDrive.exe",
    "SecurityHealthSystray.exe", "dwm.exe", "winlogon.exe", "csrss.exe",
    "lsass.exe", "services.exe", "wininit.exe", "conhost.exe",
    "taskhostw.exe", "StartMenuExperienceHost.exe", "node.exe",
}

# IPs that should never trigger alerts
WHITELIST_IPS = {
    "127.0.0.1", "0.0.0.0", "::1", "255.255.255.255",
    "224.0.0.1", "224.0.0.251", "224.0.0.252",  # Multicast
}

# Known malicious IPs (threat intel feed)
KNOWN_BAD_IPS = {
    "45.12.8.21", "185.220.101.1", "91.215.85.10", "103.224.182.250",
    "194.5.98.12", "23.106.215.76", "5.188.86.114", "77.247.181.162",
}

# Ports commonly used by malware / backdoors
SUSPICIOUS_PORTS = {6667, 6668, 6669, 4444, 5555, 1337, 31337, 8888, 9999, 12345}


# ─── Scanner State ──────────────────────────────────────────────────────────

class ScannerState:
    """Thread-safe state container for the packet scanner."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self.running = False
        self.paused = False
        self.total_packets = 0
        self.suspicious_packets = 0
        self.blocked_count = 0
        self.start_time = None
        
        # Rolling buffer of recent captured packets (max 500)
        self.captured_packets = deque(maxlen=500)
        # Only suspicious packets for the alert feed (max 200)
        self.suspicious_log = deque(maxlen=200)
        # Traffic rate tracking (packets per second snapshots) - 2 minute history
        self.rate_history = deque(maxlen=40)  # 40 * 3 seconds = 2 minutes
        # Per-process packet counts
        self.process_packet_counts = defaultdict(int)
        # Per-destination IP packet counts
        self.destination_counts = defaultdict(int)
        # Custom user whitelist additions
        self.user_whitelist_procs = set()
        self.user_whitelist_ips = set()
        # Custom user blocklist
        self.user_blocked_ips = set()
        # Event queue for SocketIO emissions (consumed by main app)
        self.event_queue = deque(maxlen=1000)
        # Snapshot counters for rate calculation
        self._last_count = 0
        self._last_rate_time = time.time()
        # Buffer utilization tracking
        self._max_buffer_size = 500
        self._max_alert_buffer_size = 200
    
    def add_packet(self, packet_info):
        with self._lock:
            self.captured_packets.append(packet_info)
            self.total_packets += 1
            proc = packet_info.get("process", "Unknown")
            dest = packet_info.get("dest_ip", "")
            self.process_packet_counts[proc] += 1
            self.destination_counts[dest] += 1
    
    def add_suspicious(self, alert_info):
        with self._lock:
            self.suspicious_log.append(alert_info)
            self.suspicious_packets += 1
            self.event_queue.append({
                "type": "scanner_alert",
                "data": alert_info,
            })
    
    def emit_event(self, event_type, data):
        with self._lock:
            self.event_queue.append({"type": event_type, "data": data})
    
    def drain_events(self):
        """Pop all pending events for emission. Returns a list."""
        with self._lock:
            events = list(self.event_queue)
            self.event_queue.clear()
            return events
    
    def compute_rate(self):
        """Compute packets/sec since last call. Emits every 3 seconds."""
        now = time.time()
        with self._lock:
            elapsed = now - self._last_rate_time
            if elapsed < 3.0:  # Emit every 3 seconds as per requirements
                return None
            count = self.total_packets
            rate = (count - self._last_count) / elapsed if elapsed > 0 else 0
            self._last_count = count
            self._last_rate_time = now
            rate_point = {
                "timestamp": datetime.now().isoformat(),
                "packets_per_sec": round(rate, 1),
                "total_packets": count,
                "suspicious": self.suspicious_packets,
            }
            self.rate_history.append(rate_point)
            return rate_point
    
    def get_stats(self):
        with self._lock:
            uptime = 0
            if self.start_time:
                uptime = int(time.time() - self.start_time)
            
            # Top talkers by destination
            top_destinations = sorted(
                self.destination_counts.items(),
                key=lambda x: x[1], reverse=True
            )[:10]
            
            # Top processes by packet count
            top_processes = sorted(
                self.process_packet_counts.items(),
                key=lambda x: x[1], reverse=True
            )[:10]
            
            return {
                "running": self.running,
                "paused": self.paused,
                "total_packets": self.total_packets,
                "suspicious_packets": self.suspicious_packets,
                "blocked_count": self.blocked_count,
                "uptime_seconds": uptime,
                "top_destinations": [{"ip": ip, "count": c} for ip, c in top_destinations],
                "top_processes": [{"process": p, "count": c} for p, c in top_processes],
                "capture_buffer_size": len(self.captured_packets),
                "capture_buffer_utilization": round(len(self.captured_packets) / self._max_buffer_size * 100, 1),
                "alert_buffer_size": len(self.suspicious_log),
                "alert_buffer_utilization": round(len(self.suspicious_log) / self._max_alert_buffer_size * 100, 1),
            }
    
    def reset(self):
        with self._lock:
            self.total_packets = 0
            self.suspicious_packets = 0
            self.blocked_count = 0
            self.start_time = None
            self.captured_packets.clear()
            self.suspicious_log.clear()
            self.rate_history.clear()
            self.process_packet_counts.clear()
            self.destination_counts.clear()
            self.event_queue.clear()
            self._last_count = 0
            self._last_rate_time = time.time()


scanner_state = ScannerState()


# ─── Process Resolver ───────────────────────────────────────────────────────

# Cache to avoid hammering psutil every packet
_port_process_cache = {}
_cache_ttl = 5  # seconds
_cache_time = 0
_cache_lock = threading.Lock()


def _refresh_port_cache():
    """Rebuild the local-port → process mapping from psutil."""
    global _port_process_cache, _cache_time
    new_cache = {}
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    if proc.is_running():
                        proc_info = proc.as_dict(attrs=['name', 'exe', 'memory_info'])
                        memory_mb = 0
                        if proc_info.get('memory_info'):
                            memory_mb = round(proc_info['memory_info'].rss / (1024 * 1024), 1)
                        new_cache[conn.laddr.port] = (
                            proc_info['name'], 
                            conn.pid,
                            proc_info.get('exe', 'N/A'),
                            memory_mb
                        )
                    else:
                        new_cache[conn.laddr.port] = ("Unknown", conn.pid, "N/A", 0)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    new_cache[conn.laddr.port] = ("Unknown", conn.pid, "N/A", 0)
    except (psutil.AccessDenied, PermissionError):
        pass
    
    with _cache_lock:
        _port_process_cache = new_cache
        _cache_time = time.time()


def get_process_from_port(local_port):
    """Maps a local port to (process_name, pid, exe_path, memory_mb). Uses a TTL cache."""
    global _cache_time
    
    with _cache_lock:
        if time.time() - _cache_time > _cache_ttl:
            _refresh_port_cache()
        return _port_process_cache.get(local_port, ("Unknown", None, "N/A", 0))


# ─── Packet Analysis ───────────────────────────────────────────────────────

def classify_packet(proc_name, pid, dest_ip, dest_port, src_port, packet_size, exe_path=""):
    """
    Classify a packet and return (is_suspicious, reasons, severity, trust_delta).
    Enhanced with comprehensive detection rules and trust scoring.
    """
    reasons = []
    severity = "Info"
    trust_delta = 0
    
    # 1. Known bad IP (Critical - highest priority)
    if dest_ip in KNOWN_BAD_IPS:
        reasons.append(f"Connection to known malicious IP: {dest_ip}")
        severity = "Critical"
        trust_delta -= 30
    
    # 2. Suspicious port
    if dest_port in SUSPICIOUS_PORTS:
        reasons.append(f"Traffic on suspicious port: {dest_port}")
        severity = max_severity(severity, "High")
        trust_delta -= 15
    
    # 3. Unknown process making network calls
    all_whitelisted = WHITELIST_PROCS | scanner_state.user_whitelist_procs
    if proc_name not in all_whitelisted and proc_name != "Unknown":
        reasons.append(f"Non-whitelisted process '{proc_name}' sending packets")
        severity = max_severity(severity, "Med")
        trust_delta -= 10
    
    # 4. Large packet (possible exfiltration indicator)
    if packet_size and packet_size > 10000:  # 10KB threshold
        reasons.append(f"Large packet detected: {packet_size} bytes (potential data exfiltration)")
        severity = max_severity(severity, "Med")
        trust_delta -= 5
    
    # 5. Browser using non-standard ports
    browser_procs = {"chrome.exe", "msedge.exe", "firefox.exe", "safari.exe", "opera.exe"}
    standard_web_ports = {80, 443, 8080, 8443}
    if (proc_name.lower() in {p.lower() for p in browser_procs} and 
        dest_port not in standard_web_ports and dest_port > 1024):
        reasons.append(f"Browser using non-standard port: {dest_port}")
        severity = max_severity(severity, "Low")
        trust_delta -= 5
    
    # 6. Process running from temp directories
    if exe_path and exe_path != "N/A":
        exe_lower = exe_path.lower()
        if any(temp_dir in exe_lower for temp_dir in ['temp', 'tmp', 'appdata\\local\\temp']):
            reasons.append(f"Process running from temp directory: {exe_path}")
            severity = max_severity(severity, "High")
            trust_delta -= 20
    
    # 7. Blocked IP
    if dest_ip in scanner_state.user_blocked_ips:
        reasons.append(f"Packet to user-blocked IP: {dest_ip}")
        severity = max_severity(severity, "High")
        scanner_state.blocked_count += 1
        trust_delta -= 25
    
    # 8. Whitelisted IP check (should not generate alerts)
    all_whitelisted_ips = WHITELIST_IPS | scanner_state.user_whitelist_ips
    if dest_ip in all_whitelisted_ips and dest_ip not in KNOWN_BAD_IPS:
        # Override - whitelisted IPs don't generate alerts unless they're known bad
        if dest_ip not in KNOWN_BAD_IPS:
            return False, [], "Info", 0
    
    is_suspicious = len(reasons) > 0
    return is_suspicious, reasons, severity, trust_delta


def max_severity(current, new):
    """Return the more severe of two severity levels."""
    order = {"Info": 0, "Low": 1, "Med": 2, "High": 3, "Critical": 4}
    if order.get(new, 0) > order.get(current, 0):
        return new
    return current


def calculate_trust_score(base_score, trust_delta):
    """Calculate final trust score ensuring it stays within 0-100 bounds."""
    final_score = base_score + trust_delta  # trust_delta is negative for suspicious activity
    return max(0, min(100, final_score))


def get_severity_from_trust_score(trust_score):
    """Map trust score to severity level."""
    if trust_score < 30:
        return "Critical"
    elif trust_score < 50:
        return "High"
    elif trust_score < 70:
        return "Med"
    else:
        return "Low"


# ─── Scapy Packet Callback ──────────────────────────────────────────────────

def _packet_callback(packet):
    """Called for every captured packet by scapy.sniff()."""
    if not scanner_state.running or scanner_state.paused:
        return
    
    if not packet.haslayer(scapy.IP):
        return
    
    ip_layer = packet[scapy.IP]
    dest_ip = ip_layer.dst
    src_ip = ip_layer.src
    
    # Get transport layer info
    src_port = 0
    dest_port = 0
    protocol = "OTHER"
    flags = ""
    
    if packet.haslayer(scapy.TCP):
        tcp = packet[scapy.TCP]
        src_port = tcp.sport
        dest_port = tcp.dport
        protocol = "TCP"
        flags = str(tcp.flags)
    elif packet.haslayer(scapy.UDP):
        udp = packet[scapy.UDP]
        src_port = udp.sport
        dest_port = udp.dport
        protocol = "UDP"
    else:
        return  # Skip non-TCP/UDP for now
    
    # Skip whitelisted IPs (unless they're known bad)
    all_whitelisted_ips = WHITELIST_IPS | scanner_state.user_whitelist_ips
    if dest_ip in all_whitelisted_ips and dest_ip not in KNOWN_BAD_IPS:
        return
    
    # Resolve process with enhanced information
    proc_name, pid, exe_path, memory_mb = get_process_from_port(src_port)
    
    packet_size = len(packet)
    now = datetime.now()
    
    # Build packet info record
    pkt_info = {
        "timestamp": now.strftime('%H:%M:%S.%f')[:-3],
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "flags": flags,
        "size": packet_size,
        "process": proc_name,
        "pid": pid,
        "exe_path": exe_path,
        "memory_mb": memory_mb,
    }
    
    scanner_state.add_packet(pkt_info)
    
    # Classify with enhanced detection
    is_suspicious, reasons, severity, trust_delta = classify_packet(
        proc_name, pid, dest_ip, dest_port, src_port, packet_size, exe_path
    )
    
    if is_suspicious:
        # Calculate final trust score
        base_trust = 100
        final_trust = calculate_trust_score(base_trust, trust_delta)
        
        # Generate unique alert ID
        alert_id = hashlib.md5(
            f"{proc_name}-{dest_ip}-{dest_port}-{int(now.timestamp()) // 10}".encode()
        ).hexdigest()[:8]
        
        alert_info = {
            "id": f"PKT-{alert_id}",
            "timestamp": now.strftime('%H:%M:%S'),
            "process": proc_name,
            "pid": pid,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "src_port": src_port,
            "protocol": protocol,
            "flags": flags,
            "size": packet_size,
            "severity": severity,
            "reasons": reasons,
            "trust_delta": trust_delta,
            "trust_score": final_trust,
            "exe_path": exe_path,
            "memory_mb": memory_mb,
            "remediation": _get_remediation_actions(severity, final_trust),
        }
        scanner_state.add_suspicious(alert_info)


def _get_remediation_actions(severity, trust_score):
    """Get recommended remediation actions based on severity and trust score."""
    if severity == "Critical" or trust_score < 30:
        return ["Terminate Process", "Block Remote IP", "Isolate Host"]
    elif severity == "High" or trust_score < 50:
        return ["Terminate Process", "Block Target Port", "Investigate Logs"]
    elif severity == "Med" or trust_score < 70:
        return ["Restart Process", "Monitor", "Review Process"]
    else:
        return ["Monitor", "Log Event"]


# ─── Scanner Thread ──────────────────────────────────────────────────────────

_scanner_thread = None
_stop_event = threading.Event()


def start_scanner(interface=None):
    """Start the scapy packet capture in a background thread."""
    global _scanner_thread, _stop_event
    
    if not SCAPY_AVAILABLE:
        scanner_state.emit_event("scanner_error", {
            "message": "Scapy is not installed. Run: pip install scapy",
            "error_type": "dependency_missing"
        })
        return False
    
    if scanner_state.running:
        return False  # Already running
    
    # Validate interface if specified
    if interface:
        try:
            available_interfaces = scapy.get_if_list()
            if interface not in available_interfaces:
                scanner_state.emit_event("scanner_error", {
                    "message": f"Network interface '{interface}' not found. Available: {', '.join(available_interfaces)}",
                    "error_type": "invalid_interface"
                })
                return False
        except Exception as e:
            scanner_state.emit_event("scanner_error", {
                "message": f"Failed to validate network interface: {str(e)}",
                "error_type": "interface_validation_failed"
            })
            return False
    
    _stop_event.clear()
    scanner_state.running = True
    scanner_state.paused = False
    scanner_state.start_time = time.time()
    
    scanner_state.emit_event("scanner_status", {
        "running": True,
        "interface": interface or "default",
        "message": f"Deep Packet Inspection engine started on interface: {interface or 'default'}"
    })
    
    def _run():
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries and not _stop_event.is_set():
            try:
                # Scapy sniff – blocks until stop_filter returns True
                scapy.sniff(
                    prn=_packet_callback,
                    store=0,
                    iface=interface,
                    stop_filter=lambda _: _stop_event.is_set(),
                )
                break  # Successful completion
                
            except PermissionError:
                scanner_state.emit_event("scanner_error", {
                    "message": "Permission denied. Run as Administrator to capture packets.",
                    "error_type": "permission_denied"
                })
                break  # Don't retry permission errors
                
            except Exception as e:
                retry_count += 1
                error_msg = f"Scanner error (attempt {retry_count}/{max_retries}): {str(e)}"
                scanner_state.emit_event("scanner_error", {
                    "message": error_msg,
                    "error_type": "capture_failed",
                    "retry_count": retry_count
                })
                
                if retry_count < max_retries:
                    scanner_state.emit_event("scanner_status", {
                        "running": True,
                        "message": f"Restarting scanner in 30 seconds (attempt {retry_count + 1}/{max_retries})"
                    })
                    time.sleep(30)  # Wait before retry
                else:
                    break
        
        scanner_state.running = False
        scanner_state.emit_event("scanner_status", {
            "running": False,
            "message": "Packet scanner stopped"
        })
    
    _scanner_thread = threading.Thread(target=_run, daemon=True, name="scapy-scanner")
    _scanner_thread.start()
    return True


def stop_scanner():
    """Signal the scapy sniffer to stop."""
    global _stop_event
    _stop_event.set()
    scanner_state.running = False
    scanner_state.emit_event("scanner_status", {
        "running": False,
        "message": "Scanner stopped by user"
    })


def pause_scanner():
    """Pause packet processing (sniffer still runs but ignores packets)."""
    scanner_state.paused = True
    scanner_state.emit_event("scanner_status", {
        "running": True,
        "paused": True,
        "message": "Scanner paused"
    })


def resume_scanner():
    """Resume packet processing."""
    scanner_state.paused = False
    scanner_state.emit_event("scanner_status", {
        "running": True,
        "paused": False,
        "message": "Scanner resumed"
    })


# ─── Rate Emitter (called from main app's background loop) ──────────────────

def tick_rate():
    """
    Should be called periodically (every 1-3 seconds) from the main
    monitor loop. Computes PPS rate and queues a WebSocket event.
    """
    rate_point = scanner_state.compute_rate()
    if rate_point:
        scanner_state.emit_event("scanner_rate", rate_point)
    return rate_point


def get_health_status():
    """Get comprehensive health status of the scanner system."""
    with scanner_state._lock:
        health = {
            "status": "healthy" if scanner_state.running and not scanner_state.paused else "degraded",
            "scapy_available": SCAPY_AVAILABLE,
            "running": scanner_state.running,
            "paused": scanner_state.paused,
            "uptime_seconds": int(time.time() - scanner_state.start_time) if scanner_state.start_time else 0,
            "packet_processing_rate": len(scanner_state.rate_history),
            "buffer_health": {
                "packet_buffer_usage": len(scanner_state.captured_packets),
                "packet_buffer_max": scanner_state._max_buffer_size,
                "alert_buffer_usage": len(scanner_state.suspicious_log),
                "alert_buffer_max": scanner_state._max_alert_buffer_size,
            },
            "cache_health": {
                "process_cache_entries": len(_port_process_cache),
                "cache_age_seconds": int(time.time() - _cache_time),
                "cache_ttl_seconds": _cache_ttl,
            },
            "performance_metrics": {
                "total_packets_processed": scanner_state.total_packets,
                "suspicious_packets_detected": scanner_state.suspicious_packets,
                "detection_rate_percent": round(
                    (scanner_state.suspicious_packets / max(scanner_state.total_packets, 1)) * 100, 2
                ),
            }
        }
        
        # Determine overall health status
        if not SCAPY_AVAILABLE:
            health["status"] = "critical"
            health["issues"] = ["Scapy not available"]
        elif not scanner_state.running:
            health["status"] = "stopped"
        elif scanner_state.paused:
            health["status"] = "paused"
        elif len(scanner_state.captured_packets) >= scanner_state._max_buffer_size * 0.9:
            health["status"] = "warning"
            health["issues"] = ["Packet buffer near capacity"]
        
        return health


def validate_configuration(config):
    """Validate scanner configuration parameters."""
    errors = []
    
    if "interface" in config:
        interface = config["interface"]
        if interface and SCAPY_AVAILABLE:
            try:
                available_interfaces = scapy.get_if_list()
                if interface not in available_interfaces:
                    errors.append(f"Invalid interface '{interface}'. Available: {', '.join(available_interfaces)}")
            except Exception as e:
                errors.append(f"Cannot validate interface: {str(e)}")
    
    if "whitelist_ips" in config:
        for ip in config["whitelist_ips"]:
            try:
                socket.inet_aton(ip)  # Basic IP validation
            except socket.error:
                errors.append(f"Invalid IP address: {ip}")
    
    if "whitelist_processes" in config:
        for proc in config["whitelist_processes"]:
            if not isinstance(proc, str) or len(proc.strip()) == 0:
                errors.append(f"Invalid process name: {proc}")
    
    return errors
