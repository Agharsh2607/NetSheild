_profiles = {}

def update_profile(process_name, traffic_bytes, intent_score):
    """Update behavior profile for process."""
    if process_name not in _profiles:
        _profiles[process_name] = {
            'traffic_total': 0,
            'connection_count': 0,
            'avg_intent': 0.5
        }
    
    profile = _profiles[process_name]
    profile['traffic_total'] += traffic_bytes
    profile['connection_count'] += 1
    profile['avg_intent'] = (profile['avg_intent'] * 0.7) + (intent_score * 0.3)

def get_baseline(process_name):
    """Get behavior baseline for process."""
    if process_name not in _profiles:
        return {
            'traffic_total': 0,
            'connection_count': 0,
            'avg_intent': 0.5
        }
    return _profiles[process_name]
