#!/usr/bin/env python3
"""
Test script to verify NetShield can detect your system
"""
import psutil
import os
import sys

def test_system_detection():
    print("🔍 NetShield AI - System Detection Test")
    print("=" * 50)
    
    try:
        # Test process detection
        processes = list(psutil.process_iter(['pid', 'name', 'memory_info']))
        print(f"✅ Processes detected: {len(processes)}")
        
        # Show some example processes
        print("\n📋 Sample processes:")
        for proc in processes[:5]:
            try:
                print(f"   - {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Test network connections
        connections = psutil.net_connections()
        print(f"\n✅ Network connections detected: {len(connections)}")
        
        # Show some example connections
        print("\n🌐 Sample connections:")
        for conn in connections[:5]:
            if conn.raddr:
                print(f"   - {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
        
        # Test system info
        print(f"\n✅ CPU cores: {psutil.cpu_count()}")
        print(f"✅ Memory: {psutil.virtual_memory().total // (1024**3)} GB")
        print(f"✅ Running as: {os.getenv('USERNAME', 'unknown')}")
        
        # Test scapy availability
        try:
            import scapy.all as scapy
            print("✅ Scapy available: YES (packet capture possible)")
        except ImportError:
            print("⚠️  Scapy available: NO (install with: pip install scapy)")
        
        print("\n🎉 System detection is working!")
        print("NetShield can monitor your system.")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_system_detection()
    if success:
        print("\n🚀 Ready to start NetShield with real system monitoring!")
    else:
        print("\n🔧 Please run as administrator for full system access.")