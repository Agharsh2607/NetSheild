def calculate_suspicion(process_name, traffic_bytes, intent_score, baseline):
    """Calculate suspicion/risk score for network activity."""
    score = 0.0
    
    # Intent factor (user activity indicator)
    if intent_score < 0.2:
        score += 5.0
    elif intent_score < 0.5:
        score += 2.0
    
    # Traffic volume compared to baseline
    baseline_traffic = baseline.get('traffic_total', 500)
    if traffic_bytes > baseline_traffic * 2:
        score += 3.0
    
    # Connection frequency
    conn_count = baseline.get('connection_count', 0)
    if conn_count > 5:
        score += 1.0
    
    return score

def determine_risk_level(score):
    """Determine risk level from suspicion score."""
    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"
