"""
NetShield AI Local Agent
Runs on your local machine and sends data to the Vercel-hosted dashboard
"""
import requests
import json
import time
import threading
from network_scanner import scanner_state, start_scanner, monitor_loop

class LocalAgent:
    def __init__(self, dashboard_url="https://your-vercel-app.vercel.app"):
        self.dashboard_url = dashboard_url
        self.running = False
        
    def start_monitoring(self):
        """Start local monitoring and data transmission"""
        print("🚀 Starting NetShield AI Local Agent...")
        print(f"📡 Dashboard URL: {self.dashboard_url}")
        
        # Start local network scanner
        success = start_scanner()
        if not success:
            print("❌ Failed to start network scanner. Run as administrator.")
            return
            
        self.running = True
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        
        # Start data transmission thread
        transmission_thread = threading.Thread(target=self._transmission_loop, daemon=True)
        transmission_thread.start()
        
        print("✅ Local agent started successfully!")
        print("📊 Monitoring your system and sending data to dashboard...")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping local agent...")
            self.running = False
    
    def _monitor_loop(self):
        """Run the local monitoring loop"""
        while self.running:
            try:
                # Your existing monitor_loop logic here
                # This will populate scanner_state with real data
                pass
            except Exception as e:
                print(f"❌ Monitor error: {e}")
            time.sleep(3)
    
    def _transmission_loop(self):
        """Send local data to Vercel dashboard"""
        while self.running:
            try:
                # Get current system data
                stats = scanner_state.get_stats()
                alerts = list(scanner_state.suspicious_log)[-10:]  # Last 10 alerts
                packets = list(scanner_state.captured_packets)[-50:]  # Last 50 packets
                
                # Send to dashboard
                data = {
                    'stats': stats,
                    'alerts': alerts,
                    'packets': packets,
                    'timestamp': time.time()
                }
                
                # POST to your Vercel app's API endpoint
                response = requests.post(
                    f"{self.dashboard_url}/api/local-agent/update",
                    json=data,
                    timeout=10
                )
                
                if response.status_code == 200:
                    print(f"📤 Data sent successfully at {time.strftime('%H:%M:%S')}")
                else:
                    print(f"⚠️ Failed to send data: {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Transmission error: {e}")
            
            time.sleep(5)  # Send data every 5 seconds

if __name__ == "__main__":
    # Replace with your actual Vercel URL
    agent = LocalAgent("https://your-netshield-app.vercel.app")
    agent.start_monitoring()