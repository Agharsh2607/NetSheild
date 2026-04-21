# Implementation Plan: Network Monitoring Integration

## Overview

This implementation plan converts the network monitoring integration design into actionable coding tasks. The feature integrates deep packet inspection using scapy with process mapping via psutil to provide real-time network monitoring capabilities within the existing Flask+SocketIO backend.

The implementation builds upon the existing NetShield AI architecture, adding a threaded network monitoring subsystem that captures packets, correlates them with processes, detects suspicious activity, and provides real-time alerts through the existing web interface.

## Tasks

- [x] 1. Set up network monitoring dependencies and core infrastructure
  - Install and verify scapy dependency for packet capture
  - Install and verify psutil dependency for process mapping
  - Create network monitoring module structure
  - Set up thread-safe state management classes
  - _Requirements: 8.4, 10.1_

- [x] 2. Implement core packet capture and analysis engine
  - [x] 2.1 Implement ScannerState class with thread-safe operations
    - Create thread-safe packet buffer management (max 500 packets)
    - Create thread-safe alert buffer management (max 200 alerts)
    - Implement event queue for SocketIO emissions
    - Add performance metrics tracking and calculation
    - _Requirements: 8.1, 5.3, 6.1_

  - [ ]* 2.2 Write property test for ScannerState buffer management
    - **Property 27: Buffer Size Limits**
    - **Validates: Requirements 8.1, 10.4**

  - [x] 2.3 Implement packet capture callback function
    - Create scapy packet callback with TCP/UDP filtering
    - Extract packet fields (IPs, ports, protocol, size, flags)
    - Integrate with process mapping for packet correlation
    - _Requirements: 1.1, 1.2, 1.5_

  - [ ]* 2.4 Write property test for packet field extraction
    - **Property 2: Packet Field Extraction Accuracy**
    - **Validates: Requirements 1.2**

- [x] 3. Implement process-to-network mapping system
  - [x] 3.1 Create process mapping cache with TTL management
    - Implement port-to-process resolution using psutil
    - Create 5-second TTL cache for performance optimization
    - Handle process termination and cache cleanup
    - _Requirements: 2.1, 2.3, 2.5_

  - [ ]* 3.2 Write property test for process mapping accuracy
    - **Property 3: Process Mapping Accuracy**
    - **Validates: Requirements 2.1, 2.4**

  - [x] 3.3 Implement process information extraction
    - Extract process name, PID, executable path, memory usage
    - Handle access denied and process termination gracefully
    - Provide "Unknown" fallback for unresolvable processes
    - _Requirements: 2.2, 2.4_

  - [ ]* 3.4 Write property test for process information completeness
    - **Property 4: Process Information Completeness**
    - **Validates: Requirements 2.2**

- [x] 4. Checkpoint - Ensure core monitoring components work
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement suspicious activity detection engine
  - [ ] 5.1 Create packet classification system
    - Implement malicious IP detection (Critical severity)
    - Implement suspicious port detection (High severity)
    - Implement non-whitelisted process detection (Medium severity)
    - Implement large packet detection for data exfiltration (Medium severity)
    - Implement browser non-standard port detection (Low severity)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [ ]* 5.2 Write property test for malicious IP alert generation
    - **Property 6: Malicious IP Alert Generation**
    - **Validates: Requirements 3.1, 5.1**

  - [ ]* 5.3 Write property test for suspicious port detection
    - **Property 7: Suspicious Port Alert Generation**
    - **Validates: Requirements 3.2**

  - [ ] 5.4 Implement trust score calculation system
    - Create trust score calculation with 0-100 bounds
    - Map trust scores to risk levels (Low/Med/High/Critical)
    - Implement severity-based remediation action recommendations
    - _Requirements: 3.6, 5.5_

  - [ ]* 5.5 Write property test for trust score bounds
    - **Property 11: Trust Score Calculation Bounds**
    - **Validates: Requirements 3.6**

- [ ] 6. Implement intelligent whitelisting system
  - [ ] 6.1 Create whitelist management system
    - Implement default process whitelist (chrome.exe, firefox.exe, etc.)
    - Implement default IP whitelist (localhost, multicast, broadcast)
    - Create user-defined whitelist management for processes and IPs
    - Implement whitelist persistence across application restarts
    - _Requirements: 4.1, 4.2, 4.3, 4.6_

  - [ ]* 6.2 Write property test for whitelist effectiveness
    - **Property 12: Whitelist Effectiveness**
    - **Validates: Requirements 4.4**

  - [ ] 6.3 Implement blocklist management
    - Create user-defined IP blocklist functionality
    - Integrate blocklist with packet classification
    - Track blocked connection attempts
    - _Requirements: 4.3_

  - [ ]* 6.4 Write property test for dynamic whitelist management
    - **Property 13: Dynamic Whitelist Management**
    - **Validates: Requirements 4.2, 4.3, 9.2**

- [ ] 7. Implement alert generation and management system
  - [ ] 7.1 Create alert generation engine
    - Generate structured alerts with unique IDs
    - Include process info, destination details, severity, and explanations
    - Add timestamp and remediation action recommendations
    - Implement alert deduplication to prevent duplicates
    - _Requirements: 5.1, 5.4, 5.5_

  - [ ]* 7.2 Write property test for alert ID uniqueness
    - **Property 15: Alert ID Uniqueness**
    - **Validates: Requirements 5.4**

  - [ ] 7.3 Implement alert buffer management
    - Maintain rolling buffer of 200 most recent alerts
    - Implement alert resolution and removal functionality
    - Track resolved alert count for metrics
    - _Requirements: 5.3, 5.6_

  - [ ]* 7.4 Write property test for alert resolution
    - **Property 17: Alert Resolution**
    - **Validates: Requirements 5.6**

- [ ] 8. Implement network traffic statistics and metrics
  - [ ] 8.1 Create traffic rate calculation system
    - Calculate packets-per-second rates every 3 seconds
    - Maintain 2-minute rolling history of traffic rates
    - Track total packets, suspicious packets, and blocked connections
    - _Requirements: 6.1, 6.2, 6.3_

  - [ ]* 8.2 Write property test for traffic rate calculation
    - **Property 19: Traffic Rate Calculation**
    - **Validates: Requirements 6.2**

  - [ ] 8.3 Implement top talkers tracking
    - Track top destination IPs by packet count
    - Track top processes by packet count
    - Provide uptime and buffer utilization metrics
    - _Requirements: 6.4, 6.5_

  - [ ]* 8.4 Write property test for network statistics accuracy
    - **Property 18: Network Statistics Accuracy**
    - **Validates: Requirements 6.1**

- [ ] 9. Checkpoint - Ensure detection and metrics work correctly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Integrate network monitoring with Flask backend
  - [ ] 10.1 Create Flask API endpoints for scanner control
    - Implement /api/scanner/start endpoint with interface selection
    - Implement /api/scanner/stop, /api/scanner/pause, /api/scanner/resume endpoints
    - Implement /api/scanner/reset endpoint for state cleanup
    - Add proper error handling and HTTP status codes
    - _Requirements: 7.1, 7.5_

  - [ ]* 10.2 Write property test for API state control
    - **Property 22: API State Control**
    - **Validates: Requirements 7.1**

  - [ ] 10.3 Create Flask API endpoints for data retrieval
    - Implement /api/scanner/status endpoint for current status and stats
    - Implement /api/scanner/packets endpoint for recent captured packets
    - Implement /api/scanner/alerts endpoint for suspicious packet alerts
    - Implement /api/scanner/rate-history endpoint for traffic rate history
    - _Requirements: 7.2_

  - [ ]* 10.4 Write property test for data retrieval API accuracy
    - **Property 23: Data Retrieval API Accuracy**
    - **Validates: Requirements 7.2**

  - [ ] 10.5 Create Flask API endpoints for whitelist/blocklist management
    - Implement /api/scanner/whitelist endpoint for adding processes and IPs
    - Implement /api/scanner/block endpoint for adding IPs to blocklist
    - Add input validation for IP addresses and process names
    - _Requirements: 7.3, 9.5_

  - [ ]* 10.6 Write property test for whitelist API integration
    - **Property 24: Whitelist API Integration**
    - **Validates: Requirements 7.3**

- [ ] 11. Implement SocketIO integration for real-time updates
  - [ ] 11.1 Create event emission system
    - Implement event queue draining in main monitor loop
    - Emit scanner_alert events for suspicious activity
    - Emit scanner_status events for status changes
    - Emit scanner_rate events for traffic rate updates
    - _Requirements: 7.4, 5.2_

  - [ ]* 11.2 Write property test for SocketIO event emission
    - **Property 25: SocketIO Event Emission**
    - **Validates: Requirements 7.4**

  - [ ] 11.3 Integrate scanner alerts with main alert system
    - Convert scanner alerts to main system format
    - Merge scanner alerts with existing alert management
    - Prevent duplicate alerts across systems
    - _Requirements: 7.6_

- [ ] 12. Implement error handling and resilience features
  - [ ] 12.1 Create graceful error handling
    - Handle scapy installation missing with informative errors
    - Handle permission errors with administrator privilege messages
    - Handle network interface errors with fallback mechanisms
    - _Requirements: 8.4, 10.1, 10.2_

  - [ ]* 12.2 Write property test for error resilience
    - **Property 29: Error Resilience**
    - **Validates: Requirements 8.5, 10.2**

  - [ ] 12.3 Implement automatic recovery mechanisms
    - Implement packet capture restart with 30-second delay
    - Handle process cache corruption with automatic refresh
    - Implement memory pressure handling with buffer cleanup
    - _Requirements: 10.3, 10.4_

  - [ ]* 12.4 Write property test for graceful shutdown
    - **Property 28: Graceful Shutdown**
    - **Validates: Requirements 8.3**

- [ ] 13. Implement configuration and health monitoring
  - [ ] 13.1 Create configuration validation system
    - Validate network interface names against available interfaces
    - Validate IP address formats for whitelist/blocklist entries
    - Validate process names for whitelist entries
    - _Requirements: 9.5_

  - [ ]* 13.2 Write property test for configuration validation
    - **Property 30: Configuration Validation**
    - **Validates: Requirements 9.5**

  - [ ] 13.3 Implement health check system
    - Create comprehensive health status reporting
    - Include buffer utilization, cache health, and performance metrics
    - Implement health check API endpoint
    - _Requirements: 10.5_

  - [ ]* 13.4 Write property test for health check accuracy
    - **Property 31: Health Check Accuracy**
    - **Validates: Requirements 10.5**

- [ ] 14. Implement performance optimization features
  - [ ] 14.1 Create thread management system
    - Implement scanner in separate daemon thread
    - Ensure non-blocking operation with main Flask application
    - Add proper thread cleanup on application shutdown
    - _Requirements: 8.2, 8.3_

  - [ ] 14.2 Optimize process cache performance
    - Implement efficient cache refresh strategies
    - Minimize psutil calls through intelligent caching
    - Handle high-frequency packet processing efficiently
    - _Requirements: 8.6_

  - [ ]* 14.3 Write property test for performance requirements
    - **Property 1: Packet Capture Completeness**
    - **Validates: Requirements 1.1, 1.5**

- [ ] 15. Final integration and testing
  - [ ] 15.1 Wire all components together
    - Integrate scanner with existing Flask monitor loop
    - Connect all API endpoints to scanner functionality
    - Ensure proper event flow from packet capture to web interface
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [ ]* 15.2 Write integration tests for end-to-end workflows
    - Test complete monitoring workflow from packet capture to alert resolution
    - Test API integration with various system states
    - Test WebSocket integration with connected clients

  - [ ] 15.3 Add comprehensive error notification system
    - Implement critical error WebSocket events for administrators
    - Add detailed logging for troubleshooting
    - Create user-friendly error messages for common issues
    - _Requirements: 10.6_

  - [ ]* 15.4 Write property test for critical error notification
    - **Property 32: Critical Error Notification**
    - **Validates: Requirements 10.6**

- [ ] 16. Final checkpoint - Ensure complete system integration
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation throughout development
- Property tests validate universal correctness properties from the design
- Unit tests validate specific examples and edge cases
- The implementation leverages existing Flask+SocketIO architecture for seamless integration
- All network monitoring functionality runs in separate threads to avoid blocking the main application
- Comprehensive error handling ensures graceful degradation when dependencies are missing or permissions are insufficient