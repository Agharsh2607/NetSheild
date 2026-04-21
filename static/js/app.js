/**
 * NetShield AI – Shared JS (SocketIO + Actions)
 */
const socket = io();

socket.on('connect', () => {
    console.log('[NetShield] Connected to server');
});
socket.on('disconnect', () => {
    console.log('[NetShield] Disconnected');
});

// Toast notification helper
function showToast(message, type = 'success') {
    let toast = document.getElementById('ns-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'ns-toast';
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.className = 'toast ' + type;
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => toast.classList.remove('show'), 3500);
}

// Listen for action results
socket.on('action_result', (data) => {
    showToast(data.message, data.success ? 'success' : 'error');
});

// Mitigation actions
async function terminateProcess(pid) {
    if (!confirm(`Terminate process PID ${pid}?`)) return;
    try {
        const res = await fetch('/api/action/terminate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({pid})
        });
        const data = await res.json();
        if (data.success) showToast(data.message, 'success');
        else showToast(data.error || 'Failed', 'error');
    } catch(e) { showToast('Network error', 'error'); }
}

async function blockIP(ip) {
    if (!confirm(`Block IP ${ip}?`)) return;
    try {
        const res = await fetch('/api/action/block-ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip})
        });
        const data = await res.json();
        if (data.success) showToast(data.message, 'success');
        else showToast(data.error || 'Failed', 'error');
    } catch(e) { showToast('Network error', 'error'); }
}

async function markSafe(pid, alertId) {
    try {
        const res = await fetch('/api/action/mark-safe', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({pid, alert_id: alertId})
        });
        const data = await res.json();
        if (data.success) {
            showToast('Marked as safe', 'success');
            if (alertId) {
                const el = document.getElementById('alert-' + alertId);
                if (el) el.style.display = 'none';
            }
        }
    } catch(e) { showToast('Network error', 'error'); }
}

async function executeScan() {
    try {
        const res = await fetch('/api/action/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({})
        });
        const data = await res.json();
        showToast(data.message, 'success');
    } catch(e) { showToast('Scan failed', 'error'); }
}

socket.on('scan_result', (data) => {
    showToast(`Scan complete: ${data.threats_found} threats found in ${data.processes_scanned} processes`, data.threats_found > 0 ? 'error' : 'success');
});

// Format helpers
function timeAgo(timestamp) {
    return timestamp || 'Just now';
}

function riskBadge(risk) {
    const colors = {
        'Low': 'bg-[#00f2ff]/10 text-[#00f2ff]',
        'Med': 'bg-[#FF8E3C]/10 text-[#FF8E3C]',
        'High': 'bg-[#ffb4ab]/10 text-[#ffb4ab]',
    };
    return `<span class="px-2 py-1 ${colors[risk] || colors['Low']} text-[10px] font-bold rounded-full">${risk}</span>`;
}
