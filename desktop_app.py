"""
NetShield AI Desktop Application
Standalone version that runs entirely on your local machine
"""
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
from datetime import datetime
from network_scanner import scanner_state, start_scanner, stop_scanner

class NetShieldDesktop:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NetShield AI - Desktop Monitor")
        self.root.geometry("1200x800")
        self.monitoring = False
        self.setup_ui()
        
    def setup_ui(self):
        """Create the desktop UI"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Status label
        self.status_label = ttk.Label(control_frame, text="Status: Stopped", foreground="red")
        self.status_label.pack(side=tk.LEFT, padx=(20, 0))
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="5")
        stats_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, width=40, height=20)
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Alerts frame
        alerts_frame = ttk.LabelFrame(main_frame, text="Recent Alerts", padding="5")
        alerts_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, width=40, height=20)
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
    def start_monitoring(self):
        """Start network monitoring"""
        success = start_scanner()
        if success:
            self.monitoring = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Running", foreground="green")
            
            # Start update thread
            update_thread = threading.Thread(target=self.update_display, daemon=True)
            update_thread.start()
            
            self.log_message("✅ Network monitoring started successfully!")
        else:
            self.log_message("❌ Failed to start monitoring. Run as administrator.")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        stop_scanner()
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", foreground="red")
        self.log_message("🛑 Network monitoring stopped.")
    
    def update_display(self):
        """Update the display with current data"""
        while self.monitoring:
            try:
                # Update statistics
                stats = scanner_state.get_stats()
                stats_text = f"""
📊 NETWORK STATISTICS
═══════════════════════
🔄 Running: {stats['running']}
⏸️  Paused: {stats['paused']}
📦 Total Packets: {stats['total_packets']:,}
🚨 Suspicious: {stats['suspicious_packets']:,}
🚫 Blocked: {stats['blocked_count']:,}
⏱️  Uptime: {stats['uptime_seconds']}s
📈 Buffer Usage: {stats['capture_buffer_utilization']}%

🔝 TOP DESTINATIONS:
"""
                for dest in stats['top_destinations'][:5]:
                    stats_text += f"   {dest['ip']}: {dest['count']} packets\n"
                
                stats_text += "\n🔝 TOP PROCESSES:\n"
                for proc in stats['top_processes'][:5]:
                    stats_text += f"   {proc['process']}: {proc['count']} packets\n"
                
                self.update_text_widget(self.stats_text, stats_text)
                
                # Update alerts
                alerts = list(scanner_state.suspicious_log)[-10:]  # Last 10 alerts
                alerts_text = "🚨 RECENT ALERTS\n═══════════════════════\n\n"
                
                for alert in reversed(alerts):  # Show newest first
                    alerts_text += f"🔴 {alert['timestamp']} - {alert['severity']}\n"
                    alerts_text += f"   Process: {alert['process']}\n"
                    alerts_text += f"   Destination: {alert['dest_ip']}:{alert['dest_port']}\n"
                    alerts_text += f"   Reason: {', '.join(alert['reasons'])}\n\n"
                
                if not alerts:
                    alerts_text += "No alerts detected.\n"
                
                self.update_text_widget(self.alerts_text, alerts_text)
                
            except Exception as e:
                self.log_message(f"❌ Update error: {e}")
            
            time.sleep(2)
    
    def update_text_widget(self, widget, text):
        """Thread-safe text widget update"""
        def update():
            widget.delete(1.0, tk.END)
            widget.insert(1.0, text)
        
        self.root.after(0, update)
    
    def log_message(self, message):
        """Log a message to the alerts area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        def update():
            self.alerts_text.insert(tk.END, log_entry)
            self.alerts_text.see(tk.END)
        
        self.root.after(0, update)
    
    def run(self):
        """Start the desktop application"""
        print("🖥️  Starting NetShield AI Desktop Application...")
        self.root.mainloop()

if __name__ == "__main__":
    app = NetShieldDesktop()
    app.run()