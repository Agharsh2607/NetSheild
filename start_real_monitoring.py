#!/usr/bin/env python3
"""
Start NetShield with REAL system monitoring
This script ensures real-time detection is working
"""
import requests
import time
import json
import threading
from datetime import datetime

def test_api_endpoints():
    """Test if NetShield API is responding"""
    base_url = "http://localhost:5000"
    
    print("🔍 Testing NetShield API endpoints...")
    
    try:
        # Test basic status
        response = requests.get(f"{base_url}/api/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Status: {data.get('status', 'unknown')}")
            print(f"✅ Active Processes: {data.get('active_processes', 0)}")
            print(f"✅ Total Connections: {data.get('total_connections', 0)}")
        
        # Test scanner status
        response = requests.get(f"{base_url}/api/scanner/status", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Scanner Running: {data.get('running', False)}")
            print(f"✅ Total Packets: {data.get('total_packets', 0)}")
            print(f"✅ Scapy Available: {data.get('scapy_available', False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ API Error: {e}")
        return False

def start_scanner():
    """Start the network scanner for real-time monitoring"""
    print("\n🚀 Starting real-time network scanner...")
    
    try:
        response = requests.post("http://localhost:5000/api/scanner/start", timeout=10)
        if response.status_code == 200:
            print("✅ Network scanner started successfully!")
            return True
        else:
            data = response.json()
            error = data.get('error', 'Unknown error')
            print(f"❌ Scanner start failed: {error}")
            
            if 'scapy' in error.lower():
                print("💡 Try: pip install scapy")
            elif 'administrator' in error.lower() or 'permission' in error.lower():
                print("💡 Try running as Administrator (Windows) or with sudo (Linux/Mac)")
            
            return False
            
    except Exception as e:
        print(f"❌ Error starting scanner: {e}")
        return False

def monitor_real_time_data():
    """Monitor and display real-time system data"""
    print("\n📊 Monitoring real-time system data...")
    print("Press Ctrl+C to stop monitoring\n")
    
    try:
        while True:
            # Get current processes
            try:
                response = requests.get("http://localhost:5000/api/processes", timeout=5)
                if response.status_code == 200:
                    processes = response.json()
                    print(f"🔄 [{datetime.now().strftime('%H:%M:%S')}] Active Processes: {len(processes)}")
                    
                    # Show top 3 processes by connection count
                    top_processes = sorted(processes, key=lambda x: x.get('connection_count', 0), reverse=True)[:3]
                    for proc in top_processes:
                        print(f"   📋 {proc['name']} (PID: {proc['pid']}) - {proc['connection_count']} connections")
            except:
                pass
            
            # Get network connections
            try:
                response = requests.get("http://localhost:5000/api/connections", timeout=5)
                if response.status_code == 200:
                    connections = response.json()
                    print(f"🌐 [{datetime.now().strftime('%H:%M:%S')}] Network Connections: {len(connections)}")
                    
                    # Show recent connections
                    for conn in connections[:2]:
                        print(f"   🔗 {conn.get('process', 'Unknown')} -> {conn.get('remote_ip', 'N/A')}:{conn.get('remote_port', 'N/A')}")
            except:
                pass
            
            # Get scanner stats
            try:
                response = requests.get("http://localhost:5000/api/scanner/status", timeout=5)
                if response.status_code == 200:
                    stats = response.json()
                    if stats.get('running'):
                        print(f"📦 [{datetime.now().strftime('%H:%M:%S')}] Packets Captured: {stats.get('total_packets', 0)}")
                        print(f"🚨 [{datetime.now().strftime('%H:%M:%S')}] Suspicious Packets: {stats.get('suspicious_packets', 0)}")
            except:
                pass
            
            print("-" * 60)
            time.sleep(3)
            
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped.")

def main():
    print("🛡️  NetShield AI - Real-Time System Monitor")
    print("=" * 60)
    
    # Test if NetShield is running
    if not test_api_endpoints():
        print("\n❌ NetShield is not running or not accessible.")
        print("💡 Make sure NetShield is started with: python app.py")
        return
    
    # Start the network scanner
    scanner_started = start_scanner()
    
    if scanner_started:
        print("\n🎉 Real-time monitoring is now active!")
        print("🌐 Dashboard: http://localhost:5000/dashboard")
        print("📊 Scanner: http://localhost:5000/scanner")
    else:
        print("\n⚠️  Scanner couldn't start, but basic monitoring is available.")
        print("🌐 Dashboard: http://localhost:5000/dashboard")
    
    # Start real-time monitoring
    monitor_real_time_data()

if __name__ == "__main__":
    main()