"""
UBNAD Integration for NetShield AI
Integrates advanced behavioral analysis and intent monitoring from UBNAD
"""
import threading
import time
import logging
from datetime import datetime
from queue import Queue, Empty
from collections import defaultdict, deque
import psutil

# Import UBNAD components
import sys
import os
sys.path.append('temp_ubnad')

try:
    from core.intent_monitor import get_intent_score, get_idle_time
    from core.process_mapper import get_process_state
    from core.behavior_model import update_profile, get_baseline
    from core.suspicion_engine import calculate_suspicion
    from core.alert_manager import generate_alert
    UBNAD_AVAILABLE = True
except ImportError as e:
    print(f"UBNAD components not available: {e}")
    UBNAD_AVAILABLE = False

class UBNADIntegration:
    """
    Integrates UBNAD's behavioral analysis into NetShield
    """
    
    def __init__(self, scanner_state):
        self.scanner_state = scanner_state
        self.running = False
        self.known_connections = set()
        self.poll_interval = 1.0  # Poll every second
        self.event_count = 0
        self.behavioral_profiles = defaultdict(dict)
        self.intent_history = deque(maxlen=100)
        
    def start(self):
        """Start UBNAD behavioral monitoring"""
        if not UBNAD_AVAILABLE:
            print("⚠️  UBNAD components not available - using basic monitoring")
            return False
            
        self.running = True
        thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        thread.start()
        print("🧠 UBNAD Behavioral Analysis started")
        return True
    
    def stop(self):
        """Stop UBNAD monitoring"""
        self.running = False
        
    def _monitoring_loop(self):
        """Main behavioral monitoring loop"""
        while self.running:
            try:
                self._analyze_behavior()
                time.sleep(self.poll_interval)
            except Exception as e:
                print(f"UBNAD monitoring error: {e}")
                time.sleep(1)
    
    def _analyze_behavior(self):
        """Analyze current system behavior using UBNAD techniques"""
        try:
            # Get current connections
            connections = psutil.net_connections(kind='inet')
            
            # Get user intent and idle time
            intent_score = get_intent_score() if UBNAD_AVAILABLE else 0.5
            idle_time = get_idle_time() if UBNAD_AVAILABLE else 0
            
            # Store intent history
            self.intent_history.append({
                'timestamp': time.time(),
                'intent': intent_score,
                'idle_time': idle_time
            })
            
            # Analyze each connection
            for conn in connections:
                if not conn.raddr or conn.status in ('LISTEN', 'NONE'):
                    continue
                    
                if self._is_local_ip(conn.raddr.ip):
                    continue
                
                # Create connection signature
                conn_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                
                if conn_key in self.known_connections:
                    continue
                    
                self.known_connections.add(conn_key)
                
                # Get process info
                process_name = self._get_process_name(conn.pid)
                
                # Behavioral analysis
                self._perform_behavioral_analysis(
                    process_name, conn.pid, conn.raddr.ip, 
                    conn.raddr.port, intent_score, idle_time
                )
                
        except Exception as e:
            print(f"Behavioral analysis error: {e}")
    
    def _perform_behavioral_analysis(self, process_name, pid, dest_ip, dest_port, intent, idle_time):
        """Perform detailed behavioral analysis on a connection"""
        try:
            # Estimate traffic (placeholder - could be enhanced)
            traffic_kb = 500
            
            # Update behavioral profile
            if UBNAD_AVAILABLE:
                update_profile(process_name, traffic_kb, intent)
                baseline = get_baseline(process_name)
                suspicion_score = calculate_suspicion(process_name, traffic_kb, intent, baseline)
            else:
                # Fallback scoring
                suspicion_score = self._calculate_basic_suspicion(
                    process_name, intent, idle_time
                )
            
            # Determine risk level
            risk_level = self._determine_risk_level(suspicion_score)
            
            # Create enhanced alert if suspicious
            if suspicion_score > 10:
                alert = {
                    'id': f'UBNAD-{int(time.time())}-{pid}',
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'process': process_name,
                    'pid': pid,
                    'dest_ip': dest_ip,
                    'dest_port': dest_port,
                    'severity': risk_level,
                    'suspicion_score': suspicion_score,
                    'intent_score': intent,
                    'idle_time': idle_time,
                    'reasons': self._get_suspicion_reasons(process_name, intent, idle_time),
                    'behavioral_analysis': True,
                    'trust_delta': -int(suspicion_score)
                }
                
                # Add to NetShield alerts
                self.scanner_state.add_suspicious(alert)
                
                # Generate UBNAD alert
                if UBNAD_AVAILABLE:
                    generate_alert(process_name, dest_ip, suspicion_score, idle_time)
                
                print(f"🚨 UBNAD Alert: {process_name} -> {dest_ip} (Score: {suspicion_score:.1f})")
            
            # Update behavioral profile
            self._update_process_profile(process_name, intent, idle_time, suspicion_score)
            
        except Exception as e:
            print(f"Behavioral analysis error: {e}")
    
    def _calculate_basic_suspicion(self, process_name, intent, idle_time):
        """Basic suspicion calculation when UBNAD is not available"""
        score = 0
        
        # User idle while process is active
        if idle_time > 30 and intent < 0.1:
            score += 15
        
        # Known silent applications
        silent_apps = ['calc.exe', 'notepad.exe', 'mspaint.exe', 'wordpad.exe']
        if any(app in process_name.lower() for app in silent_apps):
            score += 20
        
        # Unknown processes
        known_good = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'svchost.exe']
        if not any(app in process_name.lower() for app in known_good):
            score += 10
        
        return score
    
    def _determine_risk_level(self, score):
        """Determine risk level from suspicion score"""
        if score > 25:
            return "Critical"
        elif score > 15:
            return "High"
        elif score > 8:
            return "Med"
        else:
            return "Low"
    
    def _get_suspicion_reasons(self, process_name, intent, idle_time):
        """Get human-readable reasons for suspicion"""
        reasons = []
        
        if idle_time > 30 and intent < 0.1:
            reasons.append("User idle while process sends network traffic")
        
        silent_apps = ['calc.exe', 'notepad.exe', 'mspaint.exe']
        if any(app in process_name.lower() for app in silent_apps):
            reasons.append(f"Silent application {process_name} making network connections")
        
        if intent < 0.2:
            reasons.append("Low user activity during network transmission")
        
        if not reasons:
            reasons.append("Behavioral anomaly detected")
        
        return reasons
    
    def _update_process_profile(self, process_name, intent, idle_time, suspicion_score):
        """Update behavioral profile for a process"""
        if process_name not in self.behavioral_profiles:
            self.behavioral_profiles[process_name] = {
                'first_seen': time.time(),
                'connection_count': 0,
                'avg_intent': 0,
                'avg_suspicion': 0,
                'max_idle_time': 0
            }
        
        profile = self.behavioral_profiles[process_name]
        profile['connection_count'] += 1
        profile['avg_intent'] = (profile['avg_intent'] + intent) / 2
        profile['avg_suspicion'] = (profile['avg_suspicion'] + suspicion_score) / 2
        profile['max_idle_time'] = max(profile['max_idle_time'], idle_time)
        profile['last_seen'] = time.time()
    
    def get_behavioral_stats(self):
        """Get behavioral analysis statistics"""
        return {
            'profiles_tracked': len(self.behavioral_profiles),
            'intent_samples': len(self.intent_history),
            'avg_intent': sum(h['intent'] for h in self.intent_history) / len(self.intent_history) if self.intent_history else 0,
            'current_idle_time': get_idle_time() if UBNAD_AVAILABLE else 0,
            'ubnad_available': UBNAD_AVAILABLE,
            'monitoring_active': self.running
        }
    
    def _get_process_name(self, pid):
        """Get process name from PID"""
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"PID_{pid}"
    
    def _is_local_ip(self, ip):
        """Check if IP is local/private"""
        try:
            if ip.startswith(('127.', '192.168.', '10.', '172.')):
                return True
            if ip.startswith('169.254.'):
                return True
            return False
        except:
            return True

# Global UBNAD integration instance
ubnad_integration = None

def start_ubnad_integration(scanner_state):
    """Start UBNAD integration with NetShield"""
    global ubnad_integration
    
    if ubnad_integration is None:
        ubnad_integration = UBNADIntegration(scanner_state)
    
    return ubnad_integration.start()

def stop_ubnad_integration():
    """Stop UBNAD integration"""
    global ubnad_integration
    
    if ubnad_integration:
        ubnad_integration.stop()

def get_ubnad_stats():
    """Get UBNAD behavioral statistics"""
    global ubnad_integration
    
    if ubnad_integration:
        return ubnad_integration.get_behavioral_stats()
    
    return {'ubnad_available': False, 'monitoring_active': False}