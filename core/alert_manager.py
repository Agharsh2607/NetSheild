def generate_alert(process_name, dest_ip, score, idle_time):
    """Generate alert for suspicious network activity."""
    try:
        if score > 15:
            severity = "CRITICAL"
        elif score > 10:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        
        alert_msg = f"[{severity}] {process_name} connecting to {dest_ip} (score: {score:.1f}, idle: {idle_time:.0f}s)"
        print(f"ALERT: {alert_msg}")
    except Exception as e:
        print(f"Alert error: {e}")
