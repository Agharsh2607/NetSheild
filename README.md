# NetShield AI - Network Monitoring System

A behavior-aware network detection and response system with real-time monitoring capabilities.

## 🚀 Features

- **Real-time Network Monitoring**: Deep packet inspection and analysis
- **Process Correlation**: Maps network connections to running processes
- **Intelligent Threat Detection**: Trust scoring and behavioral analysis
- **Interactive Dashboard**: Live monitoring with Flask + SocketIO
- **Threat Simulation**: Built-in attack scenario testing
- **Alert Management**: Comprehensive alerting and response system

## 🏗️ Architecture

- **Flask Backend**: REST API and web interface
- **Network Monitor**: Thread-safe packet capture (when available)
- **Alert Engine**: Intelligent threat detection and scoring
- **Process Mapper**: Port-to-process correlation with caching
- **Real-time Dashboard**: Live monitoring and visualization

## 🌐 Deployment Options

### Local Development
```bash
pip install -r requirements.txt
python app.py
```
Access at: http://localhost:5000

### Vercel Deployment
This application is configured for Vercel deployment with some limitations:

**Limitations on Vercel:**
- No real-time packet capture (scapy requires root privileges)
- No background monitoring threads (serverless limitations)
- Simulated data mode for demonstration purposes

**Deploy to Vercel:**
1. Fork this repository
2. Connect to Vercel
3. Deploy automatically

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Agharsh2607/NetSheild.git)

## 📁 Project Structure

```
├── app.py                 # Main Flask application
├── network_scanner.py     # Network monitoring engine
├── api/
│   └── index.py          # Vercel WSGI entry point
├── static/               # CSS, JS assets
├── templates/            # HTML templates
├── docs/                 # Project documentation
└── tests/               # Test suite
```

## 🔧 Configuration

The application automatically detects the deployment environment:
- **Local**: Full network monitoring capabilities
- **Vercel**: Web interface with simulated data

## 📚 Documentation

See the [docs/](docs/) directory for detailed documentation:
- [Requirements](docs/requirements.md)
- [Design](docs/design.md)
- [Implementation Tasks](docs/tasks.md)

## 🛡️ Security Note

This application is designed for educational and demonstration purposes. In production environments:
- Run with appropriate privileges for network monitoring
- Configure proper firewall rules
- Use HTTPS for web interface
- Implement proper authentication

## 📄 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 🐛 Issues

Report issues on the [GitHub Issues](https://github.com/Agharsh2607/NetSheild/issues) page.