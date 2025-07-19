# 🛡️ PySniff & PyMal User Manual

Quick reference guide for using the PySniff & PyMal cybersecurity toolkit.

## 🚀 Quick Start

### 1. Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Run demo to verify installation
python run_demo.py
```

### 2. Start Dashboard (Recommended)
```bash
streamlit run dashboard/app.py
```

## 📡 Packet Sniffer (PySniff)

### Basic Usage
```bash
# Start packet capture
python sniffing/packet_sniffer.py

# Stop with Ctrl+C
```

### Advanced Options
```bash
# Capture on specific interface
python sniffing/packet_sniffer.py -i "Wi-Fi"

# Filter specific traffic
python sniffing/packet_sniffer.py -f "tcp port 80"

# Verbose output
python sniffing/packet_sniffer.py -v
```

### Configuration
- Edit `sniffing/ip_blacklist.txt` to add suspicious IPs (currently 13 IPs)
- Alerts are generated for:
  - Blacklisted IP addresses
  - Suspicious ports (4444, 23, 3389, 22, 80, 443, 8080)
  - Suspicious payload patterns

## 🔍 Static Analyzer (PyMal)

### Analyze PE Files
```bash
# Analyze test file (included)
python analysis/static_analyzer.py samples/test_notepad.exe

# Analyze executable
python analysis/static_analyzer.py suspicious.exe

# Analyze DLL
python analysis/static_analyzer.py malware.dll

# Verbose analysis
python analysis/static_analyzer.py file.exe -v
```

### What It Analyzes
- PE file headers and sections
- Imported/exported functions
- Suspicious API calls
- YARA rule matches
- File hashes (MD5, SHA1, SHA256)
- Section characteristics with suspicious section detection

### Custom YARA Rules
Edit `analysis/yara_rules.yar` to add custom detection patterns (currently 207 lines).

## 🧪 Dynamic Analyzer

### Monitor Specific Process
```bash
# Monitor by PID
python analysis/dynamic_analyzer.py -p 1234

# Monitor by process name (find PID first)
python analysis/dynamic_analyzer.py -p $(pgrep process_name)
```

### Run and Monitor Sample
```bash
# Run test script with monitoring
python analysis/dynamic_analyzer.py -s samples/test_script.py

# Run your own script
python analysis/dynamic_analyzer.py -s path/to/your/script.py
```

### System-wide Monitoring
```bash
# Monitor all processes
python analysis/dynamic_analyzer.py -w
```

### Test Alert System
```bash
# Run comprehensive alert test
python samples/test_alert_script.py
```

### What It Monitors
- Network connections
- File system activity
- Process creation
- Memory usage
- CPU usage
- Suspicious behaviors
- Real-time command line analysis

## 📊 Dashboard

### Start Dashboard
```bash
streamlit run dashboard/app.py
```

### Features
- **Packet Analysis**: View captured packets and alerts with Plotly charts
- **Dynamic Analysis**: Monitor process behaviors in real-time
- **Static Analysis**: View PE file analysis reports
- **System Status**: Monitor system resources
- **Control Panel**: Run tools directly from web interface
- **Alert Management**: View and manage alerts from all components

### Navigation
- Use tabs to switch between different analysis views
- Click on alerts for detailed information
- Use sidebar control panel to run tools
- Refresh data with the refresh button
- View interactive charts and visualizations

## 🔧 Common Tasks

### 1. Analyze Suspicious File
```bash
# Static analysis
python analysis/static_analyzer.py suspicious_file.exe

# Dynamic analysis (if it's a script)
python analysis/dynamic_analyzer.py -s suspicious_file.py
```

### 2. Monitor Network Activity
```bash
# Start packet sniffer
python sniffing/packet_sniffer.py

# Filter specific traffic
python sniffing/packet_sniffer.py -f "host 192.168.1.100"
```

### 3. Monitor Running Process
```bash
# Find process ID
tasklist | findstr process_name  # Windows
ps aux | grep process_name       # Linux/macOS

# Monitor the process
python analysis/dynamic_analyzer.py -p <PID>
```

### 4. Generate Full Report
```bash
# Run all analyses
python analysis/static_analyzer.py file.exe
python analysis/dynamic_analyzer.py -s file.py
python sniffing/packet_sniffer.py

# View results in dashboard
streamlit run dashboard/app.py
```

### 5. Test Complete System
```bash
# Run comprehensive demo
python run_demo.py

# Test alert system
python samples/test_alert_script.py
```

## 🧪 Testing Status

### ✅ All Components Tested and Working

**Static Analyzer**:
- ✅ Successfully analyzed `test_notepad.exe` (352KB PE file)
- ✅ Generated detailed PE analysis report
- ✅ YARA rules compiled and working
- ✅ Section analysis with suspicious section detection

**Dynamic Analyzer**:
- ✅ System monitoring functional
- ✅ Process behavior analysis working
- ✅ Successfully detecting suspicious command lines
- ✅ Alert generation working

**Packet Sniffer**:
- ✅ Blacklist loaded (13 IPs)
- ✅ Alert ports configured (7 ports)
- ✅ Suspicious pattern detection ready
- ✅ Layer 3 capture mode for Windows compatibility

**Dashboard**:
- ✅ Running successfully on port 8502
- ✅ All modules imported successfully
- ✅ Data visualization with Plotly charts
- ✅ Control panel functional

## ⚠️ Troubleshooting

### Permission Issues
```bash
# Windows: Run as Administrator
# Linux/macOS: Use sudo
sudo python sniffing/packet_sniffer.py
```

### Missing Dependencies
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Check installation
python -c "import scapy, psutil, pefile, yara, streamlit, pandas, matplotlib, colorama, rich; print('✅ All dependencies OK')"
```

### Dashboard Not Starting
```bash
# Check if port is available
streamlit run dashboard/app.py --server.port 8502

# Check Streamlit installation
pip install streamlit --upgrade
```

### Process Monitoring Fails
- Ensure target process is running
- Run with administrator privileges
- Check process permissions

### Static Analysis Issues
- Ensure file is a valid PE file
- Check file permissions
- Verify YARA rules are properly formatted

### Packet Capture Issues (Windows)
- Install Npcap from https://npcap.com/
- Run as Administrator
- Use Layer 3 capture mode (automatically configured)

## 📊 Sample Files

The project includes several test files:

- `samples/test_notepad.exe` (352KB) - PE file for static analysis testing
- `samples/test_alert_script.py` (101 lines) - Comprehensive alert testing
- `samples/test_script.py` (190 lines) - Dynamic behavior testing

## 🎯 Project Status

**✅ READY FOR USE** - All components are fully functional and tested!

The project is ready for cybersecurity analysis tasks with comprehensive testing completed on all components.

## 📞 Support

### Quick Help
1. Check this manual
2. Review README.md for detailed documentation
3. Run `python run_demo.py` for verification
4. Check troubleshooting section

### Common Commands Reference
```bash
# Quick verification
python run_demo.py

# Start all tools
streamlit run dashboard/app.py &
python sniffing/packet_sniffer.py &
python analysis/dynamic_analyzer.py -w &

# Stop all tools
pkill -f "python.*sniffer"
pkill -f "python.*analyzer"
pkill -f "streamlit"
```

---

**⚠️ Important**: This toolkit is for educational and authorized security testing only. Always ensure proper authorization before analyzing network traffic or files on systems you don't own. 