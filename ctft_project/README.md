# 🛡️ PySniff & PyMal: Python-Based Packet Sniffer and Malware Behavior Analyzer

A comprehensive cybersecurity toolkit for network packet analysis and malware detection without requiring Wireshark.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Components](#components)
- [Testing Status](#testing-status)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

PySniff & PyMal is a complete cybersecurity analysis toolkit that combines network packet sniffing with malware behavior analysis. Built entirely in Python, it provides both static and dynamic analysis capabilities for detecting malicious activities in network traffic and executable files.

### Key Capabilities

- **Real-time packet capture** with suspicious activity detection
- **Static malware analysis** of PE files using YARA rules
- **Dynamic behavior monitoring** of running processes
- **Interactive web dashboard** for visualization and control
- **Comprehensive logging** and reporting system
- **Multi-layered alert system** across all components

## ✨ Features

### 📡 Packet Sniffer (PySniff)
- Live network packet capture using Scapy
- Real-time alerting for suspicious IPs and ports
- Protocol analysis (TCP, UDP, ICMP, ARP)
- Payload pattern matching
- JSON-based logging system
- Configurable blacklists and filters
- Layer 3 capture mode for Windows compatibility

### 🔍 Static Analyzer (PyMal)
- PE file header analysis
- Import/Export function analysis
- Section characteristics examination
- YARA rule matching
- Hash calculation (MD5, SHA1, SHA256)
- Suspicious import detection
- Comprehensive reporting
- Detailed section analysis with suspicious section detection

### 🧪 Dynamic Analyzer
- Process behavior monitoring
- Network connection tracking
- File system activity analysis
- Memory and CPU usage monitoring
- Child process detection
- Suspicious behavior alerting
- System-wide process monitoring
- Real-time command line analysis

### 📊 Web Dashboard
- Real-time data visualization
- Interactive charts and graphs using Plotly
- Control panel for tool execution
- System status monitoring
- Alert management interface
- Packet analysis visualization
- Dynamic analysis results display
- Static analysis report viewer

## 📁 Project Structure

```
ctft_project/
├── sniffing/
│   ├── packet_sniffer.py         # Live packet capture & alerting
│   ├── ip_blacklist.txt          # Known malicious IP addresses (13 IPs)
│   └── packet_log.json           # Captured packet logs
├── analysis/
│   ├── static_analyzer.py        # PE file static analysis
│   ├── dynamic_analyzer.py       # Process behavior monitoring
│   ├── yara_rules.yar            # Custom malware detection rules
│   └── malware_reports/          # Analysis output directory
├── dashboard/
│   ├── app.py                    # Main Streamlit dashboard application
│   └── dashboard.py              # Dashboard utilities
├── samples/
│   ├── test_notepad.exe          # PE file for testing (352KB)
│   ├── test_alert_script.py      # Comprehensive alert testing script
│   └── test_script.py            # Dynamic behavior testing script
├── run_demo.py                   # Complete demo script
├── requirements.txt              # Python dependencies
├── README.md                     # This file
├── PROJECT_SUMMARY.md            # Technical project details
└── USER_MANUAL.md                # Detailed usage guide
```

## 🚀 Installation

### Prerequisites

- Python 3.8 or later
- Administrator/root privileges (for packet sniffing)
- Windows/Linux/macOS support

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd ctft_project
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
python -c "import scapy, psutil, pefile, yara, streamlit, pandas, matplotlib, colorama, rich; print('✅ All dependencies installed successfully!')"
```

## 📖 Usage

### 🎛️ Quick Start

1. **Start the Dashboard** (Recommended first step):
   ```bash
   streamlit run dashboard/app.py
   ```

2. **Run Complete Demo**:
   ```bash
   python run_demo.py
   ```

3. **Run Packet Sniffer**:
   ```bash
   # Basic usage
   python sniffing/packet_sniffer.py
   
   # With specific interface and filter
   python sniffing/packet_sniffer.py -i "Wi-Fi" -f "tcp port 80"
   ```

4. **Analyze a PE File**:
   ```bash
   python analysis/static_analyzer.py samples/test_notepad.exe
   ```

5. **Monitor Process Behavior**:
   ```bash
   # Monitor specific process
   python analysis/dynamic_analyzer.py -p <PID>
   
   # Run test script with monitoring
   python analysis/dynamic_analyzer.py -s samples/test_script.py
   
   # System-wide monitoring
   python analysis/dynamic_analyzer.py -w
   ```

6. **Test Alert System**:
   ```bash
   python samples/test_alert_script.py
   ```

### 📡 Packet Sniffer Commands

```bash
# Basic packet capture
python sniffing/packet_sniffer.py

# Capture on specific interface
python sniffing/packet_sniffer.py -i "Ethernet"

# Filter specific traffic
python sniffing/packet_sniffer.py -f "tcp port 443"

# Verbose output
python sniffing/packet_sniffer.py -v
```

### 🔍 Static Analysis Commands

```bash
# Analyze executable file
python analysis/static_analyzer.py malware.exe

# Verbose analysis
python analysis/static_analyzer.py malware.exe -v

# Analyze DLL file
python analysis/static_analyzer.py suspicious.dll
```

### 🧪 Dynamic Analysis Commands

```bash
# Monitor specific process by PID
python analysis/dynamic_analyzer.py -p 1234

# Run and monitor test script
python analysis/dynamic_analyzer.py -s samples/test_script.py

# System-wide process monitoring
python analysis/dynamic_analyzer.py -w

# Monitor all processes (alternative)
python analysis/dynamic_analyzer.py --system-wide
```

## 🧪 Testing Status

### ✅ Comprehensive Testing Completed

All components have been thoroughly tested and are working correctly:

**✅ Static Analyzer**
- Successfully analyzed `test_notepad.exe` (352KB PE file)
- Generated detailed PE analysis report with file hashes
- YARA rules compiled and working
- Section analysis with suspicious section detection
- Import analysis with detailed DLL and function imports

**✅ Dynamic Analyzer**
- System monitoring functional
- Process behavior analysis working
- Successfully detected suspicious command lines
- Alert generation working
- System monitoring results saved to JSON

**✅ Packet Sniffer**
- Blacklist loaded (13 IPs from `ip_blacklist.txt`)
- Alert ports configured (7 ports: 4444, 23, 3389, 22, 80, 443, 8080)
- Suspicious pattern detection ready
- Layer 3 capture mode for Windows compatibility

**✅ Dashboard**
- Running successfully on port 8502
- All modules imported successfully
- Data visualization with Plotly charts
- Control panel functional
- System status monitoring working

**✅ Dependencies**
- All core packages available: `streamlit`, `pandas`, `matplotlib`
- Security packages: `colorama`, `rich`, `yara`, `psutil`, `scapy`
- All imports successful

**✅ Sample Files**
- `test_notepad.exe` (352KB PE file for static analysis testing)
- `test_alert_script.py` (comprehensive alert testing script)
- `test_script.py` (dynamic behavior testing script)

**✅ Alert System**
- Static analysis alerts (suspicious imports, YARA matches, packed sections)
- Dynamic behavior alerts (suspicious command lines, high CPU/memory usage)
- Network packet alerts (blacklisted IPs, suspicious ports, payload patterns)

### 🎯 Project Ready for Use

The project is **fully functional** and ready for cybersecurity analysis tasks. All components are properly integrated and working as designed!

## 🔧 Components

### Packet Sniffer (packet_sniffer.py)

**Features:**
- Real-time packet capture using Scapy
- Protocol analysis (TCP, UDP, ICMP, ARP)
- Suspicious IP and port detection
- Payload pattern matching
- JSON logging system
- Graceful shutdown handling

**Key Functions:**
- `analyze_packet()`: Detects suspicious patterns
- `packet_callback()`: Processes each captured packet
- `load_blacklist()`: Loads IP blacklist from file

### Static Analyzer (static_analyzer.py)

**Features:**
- PE file header analysis
- Import/Export function examination
- Section characteristics analysis
- YARA rule matching
- Hash calculation
- Suspicious import detection

**Key Functions:**
- `analyze_pe_header()`: Examines PE file structure
- `analyze_imports()`: Checks for suspicious API calls
- `run_yara_scan()`: Applies YARA rules

### Dynamic Analyzer (dynamic_analyzer.py)

**Features:**
- Process behavior monitoring
- Network connection tracking
- File system activity analysis
- Memory and CPU usage monitoring
- Child process detection

**Key Functions:**
- `analyze_network_activity()`: Monitors network connections
- `analyze_file_activity()`: Tracks file operations
- `monitor_process()`: Monitors specific process

### Dashboard (dashboard.py)

**Features:**
- Real-time data visualization
- Interactive charts using Plotly
- Control panel for tool execution
- System status monitoring
- Alert management

**Key Functions:**
- `create_packet_visualizations()`: Packet analysis charts
- `create_dynamic_visualizations()`: Behavior analysis charts
- `create_control_panel()`: Tool execution interface

## 📸 Screenshots

### Dashboard Overview
![Dashboard](https://via.placeholder.com/800x400/0066cc/ffffff?text=PySniff+%26+PyMal+Dashboard)

### Packet Analysis
![Packet Analysis](https://via.placeholder.com/800x400/00cc66/ffffff?text=Packet+Analysis+View)

### Dynamic Analysis
![Dynamic Analysis](https://via.placeholder.com/800x400/cc6600/ffffff?text=Dynamic+Analysis+Results)

## 🛠️ Configuration

### IP Blacklist

Edit `sniffing/ip_blacklist.txt` to add known malicious IP addresses:

```
# Add suspicious IPs here
192.168.1.100
10.0.0.50
185.21.214.72
```

### YARA Rules

Customize `analysis/yara_rules.yar` to add new detection patterns:

```yara
rule CustomMalware
{
    strings:
        $suspicious_string = "malware_pattern"
    condition:
        $suspicious_string
}
```

### Alert Thresholds

Modify alert thresholds in the respective analyzer files:

- **Packet Sniffer**: Suspicious ports and patterns
- **Dynamic Analyzer**: Memory/CPU usage thresholds
- **Static Analyzer**: Suspicious import lists

## 🔍 Troubleshooting

### Common Issues

1. **Permission Denied for Packet Sniffing**
   ```bash
   # Windows: Run as Administrator
   # Linux/macOS: Use sudo
   sudo python sniffing/packet_sniffer.py
   ```

2. **YARA Rules Not Loading**
   ```bash
   # Check YARA installation
   pip install yara-python
   # Verify rules file exists
   ls analysis/yara_rules.yar
   ```

3. **Dashboard Not Starting**
   ```bash
   # Check Streamlit installation
   pip install streamlit
   # Verify port availability
   streamlit run dashboard/dashboard.py --server.port 8501
   ```

4. **Process Monitoring Access Denied**
   - Run with administrator privileges
   - Check process permissions
   - Verify target process is running

### Performance Optimization

- **Packet Sniffer**: Use filters to reduce packet volume
- **Dynamic Analyzer**: Increase monitoring intervals
- **Dashboard**: Limit data points for large datasets

## 📊 Sample Outputs

### Packet Sniffer Output
```
============================================================
PySniff - Python Packet Sniffer
============================================================
Interface: Default
Filter: All packets
Blacklist: 6 IPs loaded
Alert Ports: 7 ports monitored
Press Ctrl+C to stop
============================================================

[ALERT #1] Suspicious Activity Detected!
Source: 192.168.1.100:12345
Destination: 185.21.214.72:4444
  - Blacklisted IP: 192.168.1.100 -> 185.21.214.72
  - Suspicious port: 4444
Timestamp: 2024-01-15T10:30:45.123456
------------------------------------------------------------
```

### Static Analysis Output
```
============================================================
PyMal Static Analyzer
============================================================
File: malware.exe
Size: 245760 bytes
Analysis Time: 2024-01-15 10:30:45
============================================================

File Hashes:
MD5: a1b2c3d4e5f678901234567890123456
SHA1: 1234567890abcdef1234567890abcdef12345678
SHA256: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

============================================================
PE Header Analysis
============================================================
Machine: 0x14c
Number of Sections: 5
Time Date Stamp: 2024-01-15 10:30:45
Characteristics: 0x2102
Entry Point: 0x1000
Image Base: 0x400000
Size of Image: 245760
Subsystem: 2
[+] File is executable
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
pytest tests/

# Code formatting
black .

# Linting
flake8 .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy**: Network packet manipulation library
- **YARA**: Pattern matching tool for malware researchers
- **Streamlit**: Web application framework
- **psutil**: Cross-platform system monitoring library
- **pefile**: PE file parsing library

## 📞 Support

For support and questions:

- Create an issue on GitHub
- Check the troubleshooting section
- Review the documentation

---

**⚠️ Disclaimer**: This tool is for educational and research purposes only. Always ensure you have proper authorization before analyzing network traffic or files on systems you don't own.

**🛡️ Security Note**: This toolkit is designed for cybersecurity analysis and should be used responsibly and ethically. 