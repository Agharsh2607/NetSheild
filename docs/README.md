# NetShield AI Documentation

This directory contains the complete project documentation for the NetShield AI network monitoring system.

## Documents

### 📋 [Requirements](requirements.md)
Comprehensive requirements document defining all functional and non-functional requirements for the network monitoring integration feature. Includes user stories, acceptance criteria, and detailed specifications.

### 🏗️ [Design](design.md)  
Technical design document covering system architecture, component interactions, API specifications, data models, and implementation patterns. Includes 32 correctness properties for comprehensive testing.

### ✅ [Tasks](tasks.md)
Detailed implementation plan with actionable tasks covering all aspects from dependency installation to full integration with the Flask backend, including testing and deployment considerations.

## Project Overview

NetShield AI is a behavior-aware network detection and response system that combines:

- **Real-time packet monitoring** using scapy for deep packet inspection
- **Process correlation** via psutil for behavior analysis  
- **Intelligent threat detection** with trust scoring algorithms
- **Interactive web dashboard** built with Flask + SocketIO
- **Comprehensive alerting system** with real-time notifications
- **Threat simulation capabilities** for testing and validation

## Architecture

The system follows a modular architecture with:
- **Flask Backend**: REST API and web interface
- **Network Monitor**: Thread-safe packet capture and analysis
- **Alert Engine**: Intelligent threat detection and scoring
- **Process Mapper**: Port-to-process correlation with caching
- **Whitelist Manager**: Dynamic whitelist/blocklist management
- **Real-time Dashboard**: Live monitoring and visualization

## Getting Started

1. Install dependencies: `pip install -r requirements.txt`
2. Run the application: `python app.py`
3. Access dashboard: http://localhost:5000/dashboard

For detailed implementation guidance, see the [Tasks](tasks.md) document.