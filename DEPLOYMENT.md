# NetShield AI - Deployment Guide

## 🌐 Vercel Deployment

### Quick Deploy
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/Agharsh2607/NetSheild.git)

### Manual Deployment Steps

1. **Fork the Repository**
   ```bash
   git clone https://github.com/Agharsh2607/NetSheild.git
   cd NetSheild
   ```

2. **Install Vercel CLI** (if not already installed)
   ```bash
   npm install -g vercel
   ```

3. **Login to Vercel**
   ```bash
   vercel login
   ```

4. **Deploy to Vercel**
   ```bash
   vercel --prod
   ```

### Configuration Files

The repository includes these Vercel-specific files:
- `vercel.json` - Vercel deployment configuration
- `api/index.py` - WSGI entry point for serverless
- `requirements.txt` - Python dependencies (Vercel-compatible)

### Environment Variables

No additional environment variables are required for basic deployment.

## 🚨 Important Notes for Vercel Deployment

### Limitations
- **No Real-time Packet Capture**: Scapy requires root privileges not available in serverless
- **No Background Threads**: Serverless functions don't support long-running processes
- **Simulated Data Mode**: The application runs with mock data for demonstration

### What Works on Vercel
- ✅ Web interface and dashboard
- ✅ All static pages and navigation
- ✅ API endpoints (with simulated data)
- ✅ Threat simulation scenarios
- ✅ Alert management interface
- ✅ Reports and analytics views

### What Doesn't Work on Vercel
- ❌ Real network packet capture
- ❌ Live process monitoring
- ❌ Real-time network statistics
- ❌ Background monitoring threads

## 🏠 Local Development (Full Features)

For full network monitoring capabilities, run locally:

```bash
# Install dependencies
pip install -r requirements.txt

# Run with admin privileges (for packet capture)
sudo python app.py  # Linux/Mac
# or run as Administrator on Windows

# Access at http://localhost:5000
```

## 🔧 Alternative Deployment Options

### Docker Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["python", "app.py"]
```

### Heroku Deployment
1. Create `Procfile`:
   ```
   web: python app.py
   ```
2. Deploy to Heroku (note: similar limitations as Vercel)

### VPS/Cloud Server (Recommended for Full Features)
- Deploy on DigitalOcean, AWS EC2, or similar
- Install with root privileges for full network monitoring
- Configure firewall and security groups appropriately

## 🛠️ Troubleshooting

### Common Issues

1. **Import Errors on Vercel**
   - Ensure all dependencies are in `requirements.txt`
   - Check Python version compatibility

2. **Static Files Not Loading**
   - Verify `vercel.json` static file routing
   - Check file paths in templates

3. **Function Timeout**
   - Vercel has 30-second timeout limit
   - Optimize heavy operations

### Getting Help

- Check [GitHub Issues](https://github.com/Agharsh2607/NetSheild/issues)
- Review Vercel deployment logs
- Test locally first to isolate issues

## 📊 Performance Considerations

### Vercel Limits
- Function execution: 30 seconds max
- Memory: 1024 MB max
- Cold start latency possible

### Optimization Tips
- Minimize import time
- Use caching where possible
- Optimize database queries
- Compress static assets