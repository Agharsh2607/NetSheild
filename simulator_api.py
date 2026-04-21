import os
import json
import uuid
import random
import asyncio
import hashlib
from datetime import datetime

import socketio
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# ─── App Setup ─────────────────────────────────────────────────────────────

app = FastAPI(title="NetShield AI Simulator")
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, app)

# Mount paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# ─── State Management ──────────────────────────────────────────────────────

class SimulatorState:
    def __init__(self):
        self.scenario = "normal"  # normal, beaconing, exfiltration, full-attack
        self.processes = {}
        self.connections = []
        self.alerts = []
        self.metrics = {
            "active_processes": 0,
            "suspicious_connections": 0,
            "high_risk_alerts": 0,
            "threats_resolved": 0,
            "total_connections": 0,
        }
        self.traffic_history = []
        self.blocked_ips = set()
        self.safe_pids = set()

state = SimulatorState()

# ─── Simulation Generators ──────────────────────────────────────────────────

KNOWN_GOOD_IPS = ["142.250.190.46", "104.18.2.161", "13.107.4.52", "52.203.1.20"]
MALICIOUS_IPS = ["45.12.8.21", "185.220.101.1", "5.188.86.114"]
BASE_PROCESSES = [
    {"pid": 1024, "name": "svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe", "memory": 24.5},
    {"pid": 2048, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe", "memory": 115.2},
    {"pid": 3320, "name": "chrome.exe", "exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "memory": 350.1},
    {"pid": 4112, "name": "Code.exe", "exe": "C:\\Users\\Admin\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", "memory": 280.9},
    {"pid": 5510, "name": "slack.exe", "exe": "C:\\Users\\Admin\\AppData\\Local\\slack\\slack.exe", "memory": 180.5},
]

MALICIOUS_PROCESSES = {
    "beaconing": {"pid": 5432, "name": "update_svc.exe", "exe": "C:\\Users\\Admin\\AppData\\Local\\Temp\\update_svc.exe", "memory": 8.2},
    "exfiltration": {"pid": 6654, "name": "powershell.exe", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "memory": 65.4},
    "full-attack": {"pid": 8888, "name": "rundll32.exe", "exe": "C:\\Windows\\System32\\rundll32.exe", "memory": 12.1},
}

def generate_normal_baseline():
    """Generates baseline background processes and safe connections."""
    state.processes = {}
    state.connections = []
    
    for bp in BASE_PROCESSES:
        if bp["pid"] in state.safe_pids:
            continue
            
        proc = bp.copy()
        proc["trust_score"] = 100
        proc["risk"] = "Low"
        proc["reasons"] = []
        proc["connections"] = []
        
        # Add 1-3 normal connections per process
        if proc["name"] in ["chrome.exe", "slack.exe"]:
            for _ in range(random.randint(1, 3)):
                conn = {
                    "pid": proc["pid"],
                    "process": proc["name"],
                    "local_ip": "192.168.1.105",
                    "local_port": random.randint(49152, 65535),
                    "remote_ip": random.choice(KNOWN_GOOD_IPS),
                    "remote_port": 443,
                    "protocol": "TCP",
                    "status": "ESTABLISHED",
                    "bytes_sent": random.randint(1000, 50000)
                }
                proc["connections"].append(conn)
                state.connections.append(conn)
                
        state.processes[proc["pid"]] = proc

def inject_scenario_anomalies():
    """Injects specific behavioral anomalies based on active scenario."""
    if state.scenario == "normal":
        return
        
    anomaly = MALICIOUS_PROCESSES.get(state.scenario)
    if anomaly and anomaly["pid"] not in state.safe_pids:
        proc = anomaly.copy()
        proc["connections"] = []
        score = 100
        reasons = []
        
        # Scenario Logic
        if state.scenario == "beaconing":
            score -= 40
            reasons.append("Connection to known malicious IP (45.12.8.21)")
            reasons.append("Running from Temp directory")
            conn = {
                "pid": proc["pid"],
                "process": proc["name"],
                "local_ip": "192.168.1.105",
                "local_port": random.randint(49152, 65535),
                "remote_ip": "45.12.8.21",
                "remote_port": 443,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "bytes_sent": 512  # Small heartbeat
            }
            if conn["remote_ip"] not in state.blocked_ips:
                proc["connections"].append(conn)
                state.connections.append(conn)
                
        elif state.scenario == "exfiltration":
            score -= 60
            reasons.append("High outbound data volume detected")
            reasons.append("Unusual PowerShell network activity")
            conn = {
                "pid": proc["pid"],
                "process": proc["name"],
                "local_ip": "192.168.1.105",
                "local_port": random.randint(49152, 65535),
                "remote_ip": "185.220.101.1",
                "remote_port": 8088,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "bytes_sent": random.randint(50_000_000, 150_000_000) # Gigantic upload
            }
            if conn["remote_ip"] not in state.blocked_ips:
                proc["connections"].append(conn)
                state.connections.append(conn)
                
        elif state.scenario == "full-attack":
            score -= 85
            reasons.append("C2 Beaconing via Port 4444")
            reasons.append("Suspicious child process spawned")
            reasons.append("Memory injection detected")
            conn = {
                "pid": proc["pid"],
                "process": proc["name"],
                "local_ip": "192.168.1.105",
                "local_port": random.randint(49152, 65535),
                "remote_ip": "5.188.86.114",
                "remote_port": 4444,
                "protocol": "TCP",
                "status": "ESTABLISHED",
                "bytes_sent": random.randint(1000, 50000)
            }
            if conn["remote_ip"] not in state.blocked_ips:
                proc["connections"].append(conn)
                state.connections.append(conn)

        proc["trust_score"] = score
        proc["risk"] = "Critical" if score < 30 else "High"
        proc["reasons"] = reasons
        
        state.processes[proc["pid"]] = proc
        
        # Generate Alert if bad enough
        if score < 70:
            generate_alert(proc)

def generate_alert(proc):
    alert_id = hashlib.md5(f"{proc['pid']}-{proc['name']}".encode()).hexdigest()[:8]
    
    # Check if we already have it
    if any(a["id"] == f"NS-{alert_id}" for a in state.alerts):
        return

    alert = {
        'id': f'NS-{alert_id}',
        'pid': proc['pid'],
        'process': proc['name'],
        'severity': 'Critical' if proc['trust_score'] < 30 else 'High',
        'trust_score': proc['trust_score'],
        'explanation': proc['reasons'][0] if proc['reasons'] else "Behavior anomaly",
        'all_reasons': proc['reasons'],
        'remediation': ['Terminate Process', 'Block Remote IP', 'Isolate Host'] if proc['trust_score'] < 30 else ['Investigate'],
        'dest_ip': proc['connections'][0]['remote_ip'] if proc['connections'] else 'N/A',
        'dest_port': proc['connections'][0]['remote_port'] if proc['connections'] else 0,
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'time_ago': 'Just now',
        'status': 'Active',
    }
    state.alerts.insert(0, alert)

# ─── Background Loop ────────────────────────────────────────────────────────

async def engine_loop():
    """Main simulation loop running asynchronously."""
    while True:
        try:
            generate_normal_baseline()
            inject_scenario_anomalies()
            
            # Traffic history point
            inbound = random.randint(5, 20)
            outbound = len(state.connections) + random.randint(0, 5)
            traffic_point = {
                'timestamp': datetime.now().isoformat(),
                'inbound': inbound,
                'outbound': outbound,
                'total': inbound + outbound,
            }
            state.traffic_history.append(traffic_point)
            if len(state.traffic_history) > 60:
                state.traffic_history.pop(0)

            # Update Metrics
            suspicious_count = sum(1 for p in state.processes.values() if p['trust_score'] < 70)
            high_risk_count = sum(1 for p in state.processes.values() if p['trust_score'] < 30)

            state.metrics = {
                'active_processes': len(state.processes),
                'suspicious_connections': suspicious_count,
                'high_risk_alerts': high_risk_count,
                'threats_resolved': state.metrics['threats_resolved'],
                'total_connections': len(state.connections),
                'events_per_sec': random.randint(80, 200),
            }

            top_scores = sorted(state.processes.values(), key=lambda x: x['trust_score'])[:10]
            mapped_scores = [
                {
                    'pid': p['pid'],
                    'process': p['name'],
                    'score': p['trust_score'],
                    'risk': p['risk'],
                    'memory_mb': p['memory']
                } for p in top_scores
            ]

            # Emit via WebSocket
            await sio.emit('metrics_update', state.metrics)
            await sio.emit('connections_update', {
                'connections': state.connections[:50],
                'total': len(state.connections)
            })
            await sio.emit('trust_scores', mapped_scores)
            await sio.emit('traffic_update', traffic_point)

            if state.alerts:
                for alert in state.alerts[:3]: # Send latest
                    await sio.emit('new_alert', alert)

        except Exception as e:
            print(f"[Engine Error] {e}")

        await asyncio.sleep(3)

# Start background task on startup
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(engine_loop())

# ─── Frontend Routes (Templates) ───────────────────────────────────────────

@app.get("/")
async def get_landing(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})

@app.get("/dashboard")
async def get_dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/alerts")
async def get_alerts(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request})

@app.get("/intelligence")
async def get_intelligence(request: Request):
    return templates.TemplateResponse("intelligence.html", {"request": request})

@app.get("/simulator")
async def get_simulator(request: Request):
    return templates.TemplateResponse("simulator.html", {"request": request})

@app.get("/reports")
async def get_reports(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})

@app.get("/docs")
async def get_docs(request: Request):
    return templates.TemplateResponse("docs.html", {"request": request})

# ─── API Routes ────────────────────────────────────────────────────────────

@app.get("/api/status")
async def api_status():
    return JSONResponse({
        'status': 'operational',
        'active_processes': state.metrics['active_processes'],
        'total_connections': len(state.connections),
        'suspicious_connections': state.metrics['suspicious_connections'],
        'high_risk_alerts': state.metrics['high_risk_alerts'],
        'threats_resolved': state.metrics['threats_resolved'],
        'blocked_ips': list(state.blocked_ips),
        'simulation_active': state.scenario != "normal",
    })

@app.get("/api/processes")
async def api_processes():
    result = list(state.processes.values())
    result.sort(key=lambda x: x['trust_score'])
    return JSONResponse(result)

@app.get("/api/events")
async def api_events():
    return JSONResponse(state.connections[:100])

@app.get("/api/connections")
async def api_connections():
    return JSONResponse(state.connections[:100])

@app.get("/api/alerts")
async def api_alerts():
    return JSONResponse(state.alerts[:50])

@app.get("/api/trust-scores")
async def api_trust_scores():
    scores = sorted(state.processes.values(), key=lambda x: x['trust_score'])
    return JSONResponse(scores[:20])

@app.get("/api/traffic/history")
async def api_traffic_history():
    return JSONResponse(state.traffic_history[-60:])

@app.get("/api/simulate/scenarios")
async def get_scenarios():
    return JSONResponse({
        "beaconing": {"name": "C2 Beaconing", "description": "Persistent callbacks mimicking malware"},
        "exfiltration": {"name": "Data Exfiltration", "description": "Massive outbound data to unauthorized IP"},
        "full-attack": {"name": "Full Infection", "description": "Process injection and C2 communications"}
    })

# ─── Mitigation Action POSTs ────────────────────────────────────────────────

class PidRequest(BaseModel):
    pid: int

class IpRequest(BaseModel):
    ip: str

class MarkSafeRequest(BaseModel):
    pid: int = None
    alert_id: str = None

class ScenarioRequest(BaseModel):
    scenario: str

@app.post("/api/action/terminate")
async def respond_terminate(req: PidRequest):
    if req.pid in state.processes:
        proc_name = state.processes[req.pid]["name"]
        
        # In a real app we'd kill. Here, we mask it!
        state.safe_pids.add(req.pid) # Hide it from engine
        
        state.metrics['threats_resolved'] += 1
        state.alerts = [a for a in state.alerts if a.get('pid') != req.pid]
        
        await sio.emit('action_result', {
            'action': 'terminate',
            'pid': req.pid,
            'process': proc_name,
            'success': True,
            'message': f'Fake Process {proc_name} (PID: {req.pid}) successfully terminated in simulator'
        })
        return JSONResponse({'success': True, 'message': f'Terminated {proc_name}'})
    return JSONResponse({'error': 'Process not found'}, status_code=404)

@app.post("/api/action/block-ip")
async def respond_block_ip(req: IpRequest):
    state.blocked_ips.add(req.ip)
    state.metrics['threats_resolved'] += 1
    await sio.emit('action_result', {
        'action': 'block_ip',
        'ip': req.ip,
        'success': True,
        'message': f'IP {req.ip} added to simulator blocklist'
    })
    return JSONResponse({'success': True, 'message': f'Blocked {req.ip}'})

@app.post("/api/action/mark-safe")
async def respond_mark_safe(req: MarkSafeRequest):
    if req.pid:
        state.safe_pids.add(req.pid)
    if req.alert_id:
        state.alerts = [a for a in state.alerts if a.get('id') != req.alert_id]
    state.metrics['threats_resolved'] += 1
    return JSONResponse({'success': True, 'message': 'Marked as safe in simulation'})

@app.post("/api/action/scan")
async def action_scan():
    await sio.emit('scan_status', {'running': True})

    async def do_scan():
        await asyncio.sleep(3)
        await sio.emit('scan_status', {'running': False})
        await sio.emit('scan_result', {
            'success': True,
            'message': 'Fake simulator scan completed',
            'processes_scanned': len(state.processes),
            'connections_scanned': len(state.connections),
            'threats_found': sum(1 for p in state.processes.values() if p['trust_score'] < 50),
        })

    asyncio.create_task(do_scan())
    return JSONResponse({'success': True, 'message': 'Scan started'})

# ─── Simulator State Handlers ───────────────────────────────────────────────

@app.post("/api/simulator/start")
async def sim_start(req: ScenarioRequest):
    if req.scenario not in ["beaconing", "exfiltration", "full-attack"]:
        return JSONResponse({'error': 'Invalid scenario'}, status_code=400)
    state.scenario = req.scenario
    return JSONResponse({'success': True, 'message': f'Started {req.scenario}'})

@app.post("/api/simulate/start")
async def compat_simulate_start(req: ScenarioRequest):
    # Compatibility with frontend
    if req.scenario not in ["beaconing", "exfiltration", "full-attack", "c2_beaconing", "port_scanning", "unauthorized_process", "data_exfiltration"]:
        return JSONResponse({'error': 'Unknown scenario'}, status_code=400)
    
    # Map frontend keys to simulator keys
    if req.scenario == "c2_beaconing": state.scenario = "beaconing"
    elif req.scenario == "data_exfiltration": state.scenario = "exfiltration"
    elif req.scenario in ["port_scanning", "unauthorized_process"]: state.scenario = "full-attack"
    else: state.scenario = req.scenario

    return JSONResponse({'success': True, 'scenario': state.scenario})

@app.post("/api/simulator/stop")
@app.post("/api/simulate/stop")
async def sim_stop():
    state.scenario = "normal"
    return JSONResponse({'success': True, 'message': 'Simulation stopped'})

@app.post("/api/simulator/reset")
async def sim_reset():
    state.scenario = "normal"
    state.alerts = []
    state.blocked_ips.clear()
    state.safe_pids.clear()
    state.metrics['threats_resolved'] = 0
    return JSONResponse({'success': True, 'message': 'Simulator reset'})

# ─── WebSocket Event Listeners ──────────────────────────────────────────────

@sio.on('connect')
async def connect(sid, environ):
    await sio.emit('traffic_history', state.traffic_history[-60:], to=sid)
    await sio.emit('recent_alerts', state.alerts[:20], to=sid)

@sio.on('ping_client')
async def ping(sid):
    await sio.emit('pong_server', {'time': datetime.now().isoformat()}, to=sid)

@sio.on('request_process_detail')
async def request_process_detail(sid, data):
    pid = data.get('pid')
    if pid and int(pid) in state.processes:
        proc = state.processes[int(pid)]
        await sio.emit('process_detail', proc, to=sid)

if __name__ == "__main__":
    uvicorn.run("simulator_api:socket_app", host="0.0.0.0", port=5000, reload=True)
