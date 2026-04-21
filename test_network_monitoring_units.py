"""
Unit tests for Network Monitoring Integration
Tests specific examples and edge cases for the network monitoring system.
"""

import unittest
import threading
import time
from unittest.mock import Mock, patch, MagicMock
from collections import deque

# Import the modules to test
from network_scanner import (
    ScannerState, classify_packet, calculate_trust_score, 
    get_process_from_port, max_severity, get_severity_from_trust_score,
    validate_configuration, KNOWN_BAD_IPS, SUSPICIOUS_PORTS,
    get_health_status, _get_remediation_actions
)


class TestScannerStateUnits(unittest.TestCase):
    """Unit tests for ScannerState class."""
    
    def setUp(self):
        self.scanner = ScannerState()
    
    def test_initial_state(self):
        """Test that ScannerState initializes with correct default values."""
        assert self.scanner.running == False
        assert self.scanner.paused == False
        assert self.scanner.total_packets == 0
        assert self.scanner.suspicious_packets == 0
        assert len(self.scanner.captured_packets) == 0
        assert len(self.scanner.suspicious_log) == 0
    
    def test_add_packet_increments_counter(self):
        """Test that adding packets increments the total counter."""
        initial_count = self.scanner.total_packets
        
        packet = {"src_ip": "192.168.1.1", "dest_ip": "8.8.8.8"}
        self.scanner.add_packet(packet)
        
        assert self.scanner.total_packets == initial_count + 1
        assert packet in self.scanner.captured_packets
    
    def test_add_suspicious_increments_counter(self):
        """Test that adding suspicious packets increments the suspicious counter."""
        initial_count = self.scanner.suspicious_packets
        
        alert = {"id": "TEST-001", "severity": "High"}
        self.scanner.add_suspicious(alert)
        
        assert self.scanner.suspicious_packets == initial_count + 1
        assert alert in self.scanner.suspicious_log
    
    def test_event_queue_functionality(self):
        """Test that events are properly queued and drained."""
        self.scanner.emit_event("test_event", {"data": "test"})
        
        events = self.scanner.drain_events()
        assert len(events) == 1
        assert events[0]["type"] == "test_event"
        assert events[0]["data"]["data"] == "test"
        
        # Queue should be empty after draining
        events2 = self.scanner.drain_events()
        assert len(events2) == 0
    
    def test_reset_functionality(self):
        """Test that reset clears all state."""
        # Add some data
        self.scanner.add_packet({"test": "packet"})
        self.scanner.add_suspicious({"test": "alert"})
        self.scanner.emit_event("test", {})
        
        # Reset
        self.scanner.reset()
        
        # Verify everything is cleared
        assert self.scanner.total_packets == 0
        assert self.scanner.suspicious_packets == 0
        assert len(self.scanner.captured_packets) == 0
        assert len(self.scanner.suspicious_log) == 0
        assert len(self.scanner.drain_events()) == 0


class TestPacketClassificationUnits(unittest.TestCase):
    """Unit tests for packet classification logic."""
    
    def test_classify_safe_packet(self):
        """Test classification of a completely safe packet."""
        is_suspicious, reasons, severity, trust_delta = classify_packet(
            proc_name="chrome.exe",  # Whitelisted process
            pid=1234,
            dest_ip="8.8.8.8",      # Safe IP
            dest_port=443,          # Standard HTTPS port
            src_port=12345,
            packet_size=1024        # Normal size
        )
        
        # Should not be suspicious for whitelisted process to safe destination
        assert is_suspicious == False
        assert len(reasons) == 0
        assert severity == "Info"
        assert trust_delta == 0
    
    def test_classify_malicious_ip_packet(self):
        """Test classification of packet to known malicious IP."""
        malicious_ip = list(KNOWN_BAD_IPS)[0]
        
        is_suspicious, reasons, severity, trust_delta = classify_packet(
            proc_name="test.exe",
            pid=1234,
            dest_ip=malicious_ip,
            dest_port=443,
            src_port=12345,
            packet_size=1024
        )
        
        assert is_suspicious == True
        assert severity == "Critical"
        assert trust_delta <= -30
        assert any("malicious IP" in reason for reason in reasons)
    
    def test_classify_suspicious_port_packet(self):
        """Test classification of packet to suspicious port."""
        suspicious_port = 4444  # Known suspicious port
        
        is_suspicious, reasons, severity, trust_delta = classify_packet(
            proc_name="test.exe",
            pid=1234,
            dest_ip="8.8.8.8",
            dest_port=suspicious_port,
            src_port=12345,
            packet_size=1024
        )
        
        assert is_suspicious == True
        assert severity in ["High", "Med"]  # Could be Med due to non-whitelisted process
        assert trust_delta <= -15
        assert any("suspicious port" in reason for reason in reasons)
    
    def test_classify_large_packet(self):
        """Test classification of large packet (potential data exfiltration)."""
        is_suspicious, reasons, severity, trust_delta = classify_packet(
            proc_name="test.exe",
            pid=1234,
            dest_ip="8.8.8.8",
            dest_port=443,
            src_port=12345,
            packet_size=50000  # Large packet > 10KB
        )
        
        assert is_suspicious == True
        assert any("Large packet" in reason for reason in reasons)
        assert trust_delta <= -5
    
    def test_classify_browser_non_standard_port(self):
        """Test classification of browser using non-standard port."""
        is_suspicious, reasons, severity, trust_delta = classify_packet(
            proc_name="chrome.exe",
            pid=1234,
            dest_ip="8.8.8.8",
            dest_port=3000,  # Non-standard port (not in SUSPICIOUS_PORTS)
            src_port=12345,
            packet_size=1024
        )
        
        assert is_suspicious == True
        assert severity == "Low"
        assert any("non-standard port" in reason for reason in reasons)
    
    def test_classify_temp_directory_process(self):
        """Test classification of process running from temp directory."""
        is_suspicious, reasons, severity, trust_delta = classify_packet(
            proc_name="malware.exe",
            pid=1234,
            dest_ip="8.8.8.8",
            dest_port=443,
            src_port=12345,
            packet_size=1024,
            exe_path="C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe"
        )
        
        assert is_suspicious == True
        assert severity in ["High", "Med"]
        assert any("temp directory" in reason for reason in reasons)
        assert trust_delta <= -20


class TestTrustScoreUnits(unittest.TestCase):
    """Unit tests for trust score calculations."""
    
    def test_calculate_trust_score_normal_case(self):
        """Test normal trust score calculation."""
        result = calculate_trust_score(100, -30)
        assert result == 70
    
    def test_calculate_trust_score_lower_bound(self):
        """Test trust score calculation at lower bound."""
        result = calculate_trust_score(20, -50)
        assert result == 0  # Should not go below 0
    
    def test_calculate_trust_score_upper_bound(self):
        """Test trust score calculation at upper bound."""
        result = calculate_trust_score(90, 20)
        assert result == 100  # Should not go above 100
    
    def test_get_severity_from_trust_score_critical(self):
        """Test severity mapping for critical trust scores."""
        assert get_severity_from_trust_score(0) == "Critical"
        assert get_severity_from_trust_score(29) == "Critical"
    
    def test_get_severity_from_trust_score_high(self):
        """Test severity mapping for high risk trust scores."""
        assert get_severity_from_trust_score(30) == "High"
        assert get_severity_from_trust_score(49) == "High"
    
    def test_get_severity_from_trust_score_medium(self):
        """Test severity mapping for medium risk trust scores."""
        assert get_severity_from_trust_score(50) == "Med"
        assert get_severity_from_trust_score(69) == "Med"
    
    def test_get_severity_from_trust_score_low(self):
        """Test severity mapping for low risk trust scores."""
        assert get_severity_from_trust_score(70) == "Low"
        assert get_severity_from_trust_score(100) == "Low"


class TestSeverityHandlingUnits(unittest.TestCase):
    """Unit tests for severity level handling."""
    
    def test_max_severity_same_levels(self):
        """Test max_severity with same severity levels."""
        assert max_severity("High", "High") == "High"
        assert max_severity("Low", "Low") == "Low"
    
    def test_max_severity_different_levels(self):
        """Test max_severity with different severity levels."""
        assert max_severity("Low", "High") == "High"
        assert max_severity("High", "Low") == "High"
        assert max_severity("Med", "Critical") == "Critical"
        assert max_severity("Critical", "Med") == "Critical"
    
    def test_max_severity_all_combinations(self):
        """Test max_severity with all possible combinations."""
        levels = ["Info", "Low", "Med", "High", "Critical"]
        
        for i, level1 in enumerate(levels):
            for j, level2 in enumerate(levels):
                result = max_severity(level1, level2)
                expected = level1 if i >= j else level2
                assert result == expected, f"Failed for {level1} vs {level2}"


class TestRemediationActionsUnits(unittest.TestCase):
    """Unit tests for remediation action recommendations."""
    
    def test_critical_severity_remediation(self):
        """Test remediation actions for critical severity."""
        actions = _get_remediation_actions("Critical", 20)
        expected = ["Terminate Process", "Block Remote IP", "Isolate Host"]
        assert actions == expected
    
    def test_high_severity_remediation(self):
        """Test remediation actions for high severity."""
        actions = _get_remediation_actions("High", 40)
        expected = ["Terminate Process", "Block Target Port", "Investigate Logs"]
        assert actions == expected
    
    def test_medium_severity_remediation(self):
        """Test remediation actions for medium severity."""
        actions = _get_remediation_actions("Med", 60)
        expected = ["Restart Process", "Monitor", "Review Process"]
        assert actions == expected
    
    def test_low_severity_remediation(self):
        """Test remediation actions for low severity."""
        actions = _get_remediation_actions("Low", 80)
        expected = ["Monitor", "Log Event"]
        assert actions == expected
    
    def test_trust_score_based_remediation(self):
        """Test remediation actions based on trust score regardless of severity."""
        # Very low trust score should get critical actions
        actions = _get_remediation_actions("Low", 10)
        assert "Terminate Process" in actions
        assert "Isolate Host" in actions


class TestConfigurationValidationUnits(unittest.TestCase):
    """Unit tests for configuration validation."""
    
    def test_validate_empty_config(self):
        """Test validation of empty configuration."""
        errors = validate_configuration({})
        assert len(errors) == 0  # Empty config should be valid
    
    def test_validate_valid_ip_addresses(self):
        """Test validation of valid IP addresses."""
        config = {"whitelist_ips": ["127.0.0.1", "192.168.1.1", "8.8.8.8"]}
        errors = validate_configuration(config)
        assert len(errors) == 0
    
    def test_validate_invalid_ip_addresses(self):
        """Test validation of invalid IP addresses."""
        config = {"whitelist_ips": ["invalid.ip", "999.999.999.999", "not.an.ip"]}
        errors = validate_configuration(config)
        assert len(errors) == 3  # Should have 3 errors
        
        for error in errors:
            assert "Invalid IP address" in error
    
    def test_validate_valid_process_names(self):
        """Test validation of valid process names."""
        config = {"whitelist_processes": ["chrome.exe", "firefox.exe", "notepad.exe"]}
        errors = validate_configuration(config)
        assert len(errors) == 0
    
    def test_validate_invalid_process_names(self):
        """Test validation of invalid process names."""
        config = {"whitelist_processes": ["", None, 123, "  "]}
        errors = validate_configuration(config)
        assert len(errors) == 4  # Should have 4 errors
        
        for error in errors:
            assert "Invalid process name" in error


class TestHealthStatusUnits(unittest.TestCase):
    """Unit tests for health status reporting."""
    
    @patch('network_scanner.SCAPY_AVAILABLE', True)
    @patch('network_scanner.scanner_state')
    def test_healthy_status(self, mock_scanner):
        """Test health status when system is healthy."""
        mock_scanner.running = True
        mock_scanner.paused = False
        mock_scanner.start_time = time.time() - 100
        mock_scanner.captured_packets = deque(maxlen=500)
        mock_scanner.suspicious_log = deque(maxlen=200)
        mock_scanner.total_packets = 1000
        mock_scanner.suspicious_packets = 50
        mock_scanner._max_buffer_size = 500
        mock_scanner._max_alert_buffer_size = 200
        mock_scanner._lock = threading.Lock()
        
        health = get_health_status()
        
        assert health["status"] == "healthy"
        assert health["scapy_available"] == True
        assert health["running"] == True
        assert health["paused"] == False
        assert health["uptime_seconds"] >= 99
    
    @patch('network_scanner.SCAPY_AVAILABLE', False)
    def test_critical_status_no_scapy(self):
        """Test health status when scapy is not available."""
        health = get_health_status()
        
        assert health["status"] == "critical"
        assert health["scapy_available"] == False
        assert "Scapy not available" in health.get("issues", [])
    
    @patch('network_scanner.scanner_state')
    @patch('network_scanner._port_process_cache', {})
    @patch('network_scanner._cache_time', 0)
    def test_stopped_status(self, mock_scanner):
        """Test health status when scanner is stopped."""
        mock_scanner.running = False
        mock_scanner.paused = False
        mock_scanner.start_time = None
        mock_scanner.captured_packets = deque()
        mock_scanner.suspicious_log = deque()
        mock_scanner.rate_history = deque()
        mock_scanner.total_packets = 0
        mock_scanner.suspicious_packets = 0
        mock_scanner._max_buffer_size = 500
        mock_scanner._max_alert_buffer_size = 200
        mock_scanner._lock = threading.Lock()
        
        health = get_health_status()
        
        assert health["status"] == "stopped"
        assert health["running"] == False


if __name__ == "__main__":
    unittest.main()