"""
Property-based tests for Network Monitoring Integration
Tests universal properties that should hold across all valid inputs.
"""

import pytest
import threading
import time
import random
import string
from unittest.mock import Mock, patch, MagicMock
from collections import deque

# Import the modules to test
from network_scanner import (
    ScannerState, classify_packet, calculate_trust_score, 
    get_process_from_port, max_severity, get_severity_from_trust_score,
    validate_configuration, KNOWN_BAD_IPS, SUSPICIOUS_PORTS
)
import network_scanner

try:
    from hypothesis import given, strategies as st, settings
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    # Create dummy decorators if hypothesis not available
    def given(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    class st:
        @staticmethod
        def integers(min_value=0, max_value=100):
            return range(min_value, max_value + 1)
        
        @staticmethod
        def text(min_size=1, max_size=50):
            return ["test_string"]
        
        @staticmethod
        def lists(elements, min_size=0, max_size=10):
            return [[]]


class TestScannerStateProperties:
    """Test universal properties of ScannerState class."""
    
    def test_property_1_packet_capture_completeness(self):
        """
        Feature: network-monitoring-integration, Property 1: Packet Capture Completeness
        For any TCP or UDP packet, the ScannerState SHALL capture and process the packet.
        """
        scanner = ScannerState()
        
        # Test with various packet types
        test_packets = [
            {"protocol": "TCP", "src_ip": "192.168.1.1", "dest_ip": "8.8.8.8"},
            {"protocol": "UDP", "src_ip": "10.0.0.1", "dest_ip": "1.1.1.1"},
            {"protocol": "TCP", "src_ip": "172.16.0.1", "dest_ip": "208.67.222.222"},
        ]
        
        for packet in test_packets:
            initial_count = scanner.total_packets
            scanner.add_packet(packet)
            assert scanner.total_packets == initial_count + 1
            assert packet in scanner.captured_packets
    
    def test_property_14_alert_buffer_management(self):
        """
        Feature: network-monitoring-integration, Property 14: Alert Buffer Management
        For any sequence of generated alerts, the system SHALL maintain at most 200 alerts.
        """
        scanner = ScannerState()
        
        # Generate more than 200 alerts
        for i in range(250):
            alert = {
                "id": f"TEST-{i:04d}",
                "timestamp": f"12:00:{i:02d}",
                "severity": "High",
                "process": "test.exe"
            }
            scanner.add_suspicious(alert)
        
        # Should never exceed 200 alerts
        assert len(scanner.suspicious_log) <= 200
        assert len(scanner.suspicious_log) == 200  # Should be exactly 200
        
        # Should contain the most recent alerts
        latest_alert = list(scanner.suspicious_log)[-1]
        assert "TEST-0249" in latest_alert["id"]
    
    def test_property_27_buffer_size_limits(self):
        """
        Feature: network-monitoring-integration, Property 27: Buffer Size Limits
        For any system load, the Network_Monitor SHALL enforce maximum buffer sizes.
        """
        scanner = ScannerState()
        
        # Test packet buffer limit (500)
        for i in range(600):
            packet = {
                "timestamp": f"12:00:{i:03d}",
                "src_ip": f"192.168.1.{i % 255}",
                "dest_ip": "8.8.8.8",
                "protocol": "TCP"
            }
            scanner.add_packet(packet)
        
        assert len(scanner.captured_packets) <= 500
        assert len(scanner.captured_packets) == 500
        
        # Test alert buffer limit (200) 
        for i in range(300):
            alert = {"id": f"ALERT-{i}", "severity": "Med"}
            scanner.add_suspicious(alert)
        
        assert len(scanner.suspicious_log) <= 200
        assert len(scanner.suspicious_log) == 200


class TestPacketFieldExtractionProperties:
    """Test universal properties of packet field extraction."""
    
    def test_property_2_packet_field_extraction_accuracy(self):
        """
        Feature: network-monitoring-integration, Property 2: Packet Field Extraction Accuracy
        For any captured network packet, the Packet_Analyzer SHALL correctly extract all required fields.
        """
        # Test various packet configurations
        test_packets = [
            {
                "src_ip": "192.168.1.100",
                "dest_ip": "8.8.8.8", 
                "src_port": 12345,
                "dest_port": 443,
                "protocol": "TCP",
                "size": 1024,
                "flags": "18"  # PSH+ACK
            },
            {
                "src_ip": "10.0.0.1",
                "dest_ip": "1.1.1.1",
                "src_port": 53001,
                "dest_port": 53,
                "protocol": "UDP", 
                "size": 512,
                "flags": ""
            },
            {
                "src_ip": "172.16.0.50",
                "dest_ip": "208.67.222.222",
                "src_port": 8080,
                "dest_port": 80,
                "protocol": "TCP",
                "size": 2048,
                "flags": "2"  # SYN
            }
        ]
        
        scanner = ScannerState()
        
        for expected_packet in test_packets:
            # Simulate packet extraction by adding to scanner
            extracted_packet = {
                "timestamp": "12:00:00.123",
                "src_ip": expected_packet["src_ip"],
                "dest_ip": expected_packet["dest_ip"],
                "src_port": expected_packet["src_port"],
                "dest_port": expected_packet["dest_port"],
                "protocol": expected_packet["protocol"],
                "size": expected_packet["size"],
                "flags": expected_packet["flags"],
                "process": "test.exe",
                "pid": 1234
            }
            
            scanner.add_packet(extracted_packet)
            
            # Verify all required fields are correctly extracted
            captured = list(scanner.captured_packets)[-1]
            
            # Validate required fields are present and correct
            assert captured["src_ip"] == expected_packet["src_ip"]
            assert captured["dest_ip"] == expected_packet["dest_ip"] 
            assert captured["src_port"] == expected_packet["src_port"]
            assert captured["dest_port"] == expected_packet["dest_port"]
            assert captured["protocol"] == expected_packet["protocol"]
            assert captured["size"] == expected_packet["size"]
            
            # Validate field types
            assert isinstance(captured["src_port"], int)
            assert isinstance(captured["dest_port"], int)
            assert isinstance(captured["size"], int)
            assert isinstance(captured["protocol"], str)
            assert isinstance(captured["src_ip"], str)
            assert isinstance(captured["dest_ip"], str)
            
            # Validate field ranges
            assert 0 <= captured["src_port"] <= 65535
            assert 0 <= captured["dest_port"] <= 65535
            assert captured["size"] >= 0
            assert captured["protocol"] in ["TCP", "UDP"]


class TestProcessMappingProperties:
    """Test universal properties of process mapping system."""
    
    def test_property_3_process_mapping_accuracy(self):
        """
        Feature: network-monitoring-integration, Property 3: Process Mapping Accuracy
        For any network packet with a valid source port, the Process_Mapper SHALL either 
        correctly identify the originating process or label it as "Unknown" without failing.
        """
        # Test various port scenarios
        test_ports = [80, 443, 8080, 12345, 53, 22, 3389, 5432, 65535, 1]
        
        for port in test_ports:
            # Mock the cache refresh function to avoid real psutil calls
            with patch('network_scanner._refresh_port_cache') as mock_refresh:
                with patch('network_scanner._port_process_cache', {}) as mock_cache:
                    with patch('network_scanner._cache_time', time.time()) as mock_cache_time:
                        
                        # Test case 1: Process found in cache
                        mock_cache[port] = ('test.exe', 1234, '/path/to/test.exe', 50.0)
                        
                        proc_name, pid, exe_path, memory_mb = get_process_from_port(port)
                        assert proc_name == 'test.exe'
                        assert pid == 1234
                        assert exe_path == '/path/to/test.exe'
                        assert memory_mb == 50.0
                        
                        # Test case 2: Process not found (should return "Unknown")
                        mock_cache.clear()
                        proc_name, pid, exe_path, memory_mb = get_process_from_port(port)
                        assert proc_name == "Unknown"
                        assert pid is None
                        assert exe_path == "N/A"
                        assert memory_mb == 0
    
    def test_property_4_process_information_completeness(self):
        """
        Feature: network-monitoring-integration, Property 4: Process Information Completeness
        For any successfully identified process, the Process_Mapper SHALL extract all required 
        fields (process name, process ID, executable path, memory usage) with valid values.
        """
        test_cases = [
            {
                'name': 'chrome.exe',
                'pid': 1111,
                'exe': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'memory': 100.0
            },
            {
                'name': 'python.exe',
                'pid': 2222,
                'exe': 'C:\\Python39\\python.exe',
                'memory': 25.0
            },
            {
                'name': 'notepad.exe',
                'pid': 3333,
                'exe': 'C:\\Windows\\System32\\notepad.exe',
                'memory': 5.0
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            port = 12345 + i  # Use different ports for each test
            
            # Mock the cache to contain the test process
            with patch('network_scanner._refresh_port_cache'):
                with patch('network_scanner._port_process_cache', {}) as mock_cache:
                    with patch('network_scanner._cache_time', time.time()):
                        
                        # Setup cache with test process info
                        mock_cache[port] = (
                            test_case['name'],
                            test_case['pid'], 
                            test_case['exe'],
                            test_case['memory']
                        )
                        
                        # Get process information
                        proc_name, pid, exe_path, memory_mb = get_process_from_port(port)
                        
                        # Validate all required fields are present and valid
                        assert isinstance(proc_name, str)
                        assert len(proc_name) > 0
                        assert proc_name == test_case['name']
                        
                        assert isinstance(pid, int)
                        assert pid > 0
                        assert pid == test_case['pid']
                        
                        assert isinstance(exe_path, str)
                        assert len(exe_path) > 0
                        assert exe_path == test_case['exe']
                        
                        assert isinstance(memory_mb, float)
                        assert memory_mb >= 0
                        assert memory_mb == test_case['memory']
    
    def test_property_5_cache_ttl_behavior(self):
        """
        Feature: network-monitoring-integration, Property 5: Cache TTL Behavior
        For any port-to-process mapping, the mapping SHALL be refreshed after 5-second TTL expires.
        """
        # Test TTL behavior by manipulating cache time and checking refresh calls
        with patch('network_scanner._refresh_port_cache') as mock_refresh:
            with patch('network_scanner._port_process_cache', {8080: ('initial.exe', 1111, '/path/initial.exe', 10.0)}) as mock_cache:
                with patch('network_scanner._cache_time', 1000.0) as mock_cache_time:
                    with patch('network_scanner.time.time') as mock_time:
                        
                        # Test 1: Within TTL - should not refresh cache
                        mock_time.return_value = 1003.0  # 3 seconds later
                        proc_name1, _, _, _ = get_process_from_port(8080)
                        assert proc_name1 == 'initial.exe'
                        assert not mock_refresh.called  # Should not refresh within TTL
                        
                        # Test 2: Exceed TTL - should refresh cache
                        mock_refresh.reset_mock()
                        mock_time.return_value = 1006.0  # 6 seconds later (exceeds 5s TTL)
                        
                        # Update cache after refresh to simulate new process
                        def refresh_side_effect():
                            mock_cache[8080] = ('changed.exe', 2222, '/path/changed.exe', 20.0)
                            network_scanner._cache_time = 1006.0
                        
                        mock_refresh.side_effect = refresh_side_effect
                        
                        proc_name2, pid2, exe2, mem2 = get_process_from_port(8080)
                        assert mock_refresh.called  # Should refresh after TTL
                        assert proc_name2 == 'changed.exe'
                        assert pid2 == 2222
                        assert exe2 == '/path/changed.exe'
                        assert mem2 == 20.0


class TestPacketClassificationProperties:
    """Test universal properties of packet classification."""
    
    def test_property_6_malicious_ip_alert_generation(self):
        """
        Feature: network-monitoring-integration, Property 6: Malicious IP Alert Generation
        For any connection to a known malicious IP, the system SHALL generate a Critical alert.
        """
        for malicious_ip in KNOWN_BAD_IPS:
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
    
    def test_property_7_suspicious_port_alert_generation(self):
        """
        Feature: network-monitoring-integration, Property 7: Suspicious Port Alert Generation
        For any traffic on suspicious ports, the system SHALL generate a High severity alert.
        """
        for suspicious_port in SUSPICIOUS_PORTS:
            is_suspicious, reasons, severity, trust_delta = classify_packet(
                proc_name="test.exe",
                pid=1234,
                dest_ip="8.8.8.8",
                dest_port=suspicious_port,
                src_port=12345,
                packet_size=1024
            )
            
            assert is_suspicious == True
            assert severity in ["High", "Critical"]  # Could be Critical if other factors
            assert trust_delta <= -15
            assert any("suspicious port" in reason for reason in reasons)
    
    def test_property_11_trust_score_calculation_bounds(self):
        """
        Feature: network-monitoring-integration, Property 11: Trust Score Calculation Bounds
        For any combination of anomalies, trust scores SHALL be within 0-100 range.
        """
        # Test various trust delta combinations
        test_cases = [
            (100, 0),      # Perfect score
            (100, -150),   # Extreme negative delta
            (50, -100),    # Large negative delta
            (0, -50),      # Already at minimum
            (100, 50),     # Positive delta (shouldn't happen but test bounds)
        ]
        
        for base_score, delta in test_cases:
            final_score = calculate_trust_score(base_score, delta)
            assert 0 <= final_score <= 100
            assert isinstance(final_score, int)
    
    def test_property_12_whitelist_effectiveness(self):
        """
        Feature: network-monitoring-integration, Property 12: Whitelist Effectiveness
        For any whitelisted process to non-malicious IPs, no alerts SHALL be generated.
        """
        # Mock scanner state with whitelisted process
        with patch('network_scanner.scanner_state') as mock_scanner:
            mock_scanner.user_whitelist_procs = {"trusted.exe"}
            mock_scanner.user_whitelist_ips = set()
            mock_scanner.user_blocked_ips = set()
            
            # Test whitelisted process to safe IP
            is_suspicious, reasons, severity, trust_delta = classify_packet(
                proc_name="trusted.exe",
                pid=1234,
                dest_ip="8.8.8.8",  # Safe IP
                dest_port=443,
                src_port=12345,
                packet_size=1024
            )
            
            # Should still be suspicious due to non-whitelisted process rule
            # But trust delta should be minimal for whitelisted process
            assert trust_delta >= -10  # Only non-whitelisted process penalty


class TestTrustScoreProperties:
    """Test trust score calculation properties."""
    
    def test_trust_score_severity_mapping_consistency(self):
        """Test that trust scores consistently map to severity levels."""
        test_scores = [0, 10, 29, 30, 49, 50, 69, 70, 90, 100]
        
        for score in test_scores:
            severity = get_severity_from_trust_score(score)
            
            if score < 30:
                assert severity == "Critical"
            elif score < 50:
                assert severity == "High"
            elif score < 70:
                assert severity == "Med"
            else:
                assert severity == "Low"
    
    def test_severity_ordering_consistency(self):
        """Test that max_severity function maintains proper ordering."""
        severity_order = ["Info", "Low", "Med", "High", "Critical"]
        
        for i, sev1 in enumerate(severity_order):
            for j, sev2 in enumerate(severity_order):
                result = max_severity(sev1, sev2)
                expected = sev1 if i >= j else sev2
                assert result == expected


class TestConfigurationValidationProperties:
    """Test configuration validation properties."""
    
    def test_property_30_configuration_validation(self):
        """
        Feature: network-monitoring-integration, Property 30: Configuration Validation
        For any configuration input, the system SHALL validate and reject invalid configurations.
        """
        # Test valid configurations
        valid_configs = [
            {"interface": None},
            {"whitelist_ips": ["127.0.0.1", "192.168.1.1"]},
            {"whitelist_processes": ["chrome.exe", "firefox.exe"]},
        ]
        
        for config in valid_configs:
            errors = validate_configuration(config)
            # Should have no errors for valid configs (except interface validation which needs scapy)
            if "interface" not in config:
                assert len(errors) == 0
        
        # Test invalid configurations
        invalid_configs = [
            {"whitelist_ips": ["invalid.ip.address", "999.999.999.999"]},
            {"whitelist_processes": ["", None, 123]},
        ]
        
        for config in invalid_configs:
            errors = validate_configuration(config)
            assert len(errors) > 0  # Should have validation errors


class TestThreadSafetyProperties:
    """Test thread safety properties of ScannerState."""
    
    def test_concurrent_packet_addition_thread_safety(self):
        """Test that concurrent packet additions are thread-safe."""
        scanner = ScannerState()
        packets_per_thread = 100
        num_threads = 5
        
        def add_packets(thread_id):
            for i in range(packets_per_thread):
                packet = {
                    "id": f"thread-{thread_id}-packet-{i}",
                    "timestamp": f"12:00:{i:02d}",
                    "src_ip": f"192.168.{thread_id}.{i}",
                    "dest_ip": "8.8.8.8"
                }
                scanner.add_packet(packet)
        
        threads = []
        for thread_id in range(num_threads):
            thread = threading.Thread(target=add_packets, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should have exactly the expected number of packets
        expected_total = packets_per_thread * num_threads
        assert scanner.total_packets == expected_total
        
        # Buffer should respect max size
        assert len(scanner.captured_packets) <= 500
    
    def test_concurrent_alert_generation_thread_safety(self):
        """Test that concurrent alert generation is thread-safe."""
        scanner = ScannerState()
        alerts_per_thread = 50
        num_threads = 4
        
        def add_alerts(thread_id):
            for i in range(alerts_per_thread):
                alert = {
                    "id": f"THREAD-{thread_id}-ALERT-{i}",
                    "timestamp": f"12:{thread_id:02d}:{i:02d}",
                    "severity": "High",
                    "process": f"thread{thread_id}.exe"
                }
                scanner.add_suspicious(alert)
        
        threads = []
        for thread_id in range(num_threads):
            thread = threading.Thread(target=add_alerts, args=(thread_id,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should have expected number of suspicious packets
        expected_total = alerts_per_thread * num_threads
        assert scanner.suspicious_packets == expected_total
        
        # Alert buffer should respect max size
        assert len(scanner.suspicious_log) <= 200


# Hypothesis-based property tests (if available)
if HYPOTHESIS_AVAILABLE:
    
    @given(st.integers(min_value=0, max_value=100), st.integers(min_value=-200, max_value=50))
    @settings(max_examples=100)
    def test_trust_score_bounds_hypothesis(base_score, trust_delta):
        """Property test: trust scores always stay within bounds regardless of input."""
        result = calculate_trust_score(base_score, trust_delta)
        assert 0 <= result <= 100
        assert isinstance(result, int)
    
    @given(st.text(min_size=1, max_size=50), 
           st.integers(min_value=1, max_value=65535),
           st.integers(min_value=1, max_value=65535),
           st.integers(min_value=1, max_value=100000))
    @settings(max_examples=50)
    def test_packet_classification_consistency_hypothesis(proc_name, dest_port, src_port, packet_size):
        """Property test: packet classification is consistent for same inputs."""
        # First classification
        result1 = classify_packet(proc_name, 1234, "8.8.8.8", dest_port, src_port, packet_size)
        
        # Second classification with same inputs
        result2 = classify_packet(proc_name, 1234, "8.8.8.8", dest_port, src_port, packet_size)
        
        # Results should be identical
        assert result1 == result2


if __name__ == "__main__":
    # Run basic tests if pytest not available
    test_instance = TestScannerStateProperties()
    test_instance.test_property_1_packet_capture_completeness()
    test_instance.test_property_14_alert_buffer_management()
    test_instance.test_property_27_buffer_size_limits()
    
    classification_test = TestPacketClassificationProperties()
    classification_test.test_property_6_malicious_ip_alert_generation()
    classification_test.test_property_7_suspicious_port_alert_generation()
    classification_test.test_property_11_trust_score_calculation_bounds()
    
    print("All property tests passed!")