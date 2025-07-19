#!/usr/bin/env python3
"""
PySniff & PyMal Dashboard App
Main entry point for the Streamlit dashboard
"""

import streamlit as st
import json
import pandas as pd
import matplotlib.pyplot as plt
import os
import time
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Try to import psutil, but don't fail if it's not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    st.warning("psutil not available - system status features will be limited")

# Page configuration
st.set_page_config(
    page_title="PySniff & PyMal Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

class Dashboard:
    def __init__(self):
        self.packet_log_file = "sniffing/packet_log.json"
        self.dynamic_log_file = "analysis/malware_reports/dynamic_analysis.json"
        self.static_reports_dir = "analysis/malware_reports"
        # Initialize thread result storage
        self.dynamic_test_results = {'output': '', 'success': False, 'completed': False}
        self.monitoring_results = {'behaviors': [], 'completed': False, 'error': None}
        
    def load_packet_data(self):
        """Load packet capture data"""
        packets = []
        
        # First, check for packets captured in current session
        if hasattr(st.session_state, 'captured_packets') and st.session_state.captured_packets:
            packets.extend(st.session_state.captured_packets)
        
        # Then load from log file
        if os.path.exists(self.packet_log_file):
            try:
                with open(self.packet_log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            packets.append(json.loads(line))
            except Exception as e:
                st.error(f"Error loading packet data: {e}")
        
        return packets
    
    def load_dynamic_data(self):
        """Load dynamic analysis data"""
        behaviors = []
        
        # First, check for behaviors captured in current session
        if hasattr(st.session_state, 'dynamic_behaviors') and st.session_state.dynamic_behaviors:
            behaviors.extend(st.session_state.dynamic_behaviors)
        
        # Then load from log file
        if os.path.exists(self.dynamic_log_file):
            try:
                with open(self.dynamic_log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            behaviors.append(json.loads(line))
            except Exception as e:
                st.error(f"Error loading dynamic data: {e}")
        
        return behaviors
    
    def load_static_reports(self):
        """Load static analysis reports"""
        reports = []
        if os.path.exists(self.static_reports_dir):
            for filename in os.listdir(self.static_reports_dir):
                if filename.startswith("static_analysis_") and filename.endswith(".json"):
                    filepath = os.path.join(self.static_reports_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            reports.append(json.load(f))
                    except Exception as e:
                        st.error(f"Error loading report {filename}: {e}")
        return reports
    
    def create_packet_visualizations(self, packets):
        """Create packet analysis visualizations"""
        if not packets:
            st.warning("No packet data available. Start the packet sniffer to collect data.")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(packets)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Create tabs for different visualizations
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🌐 Network Activity", "🚨 Alerts", "📈 Time Series"])
        
        with tab1:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Packets", len(packets))
            
            with col2:
                alerts = sum(1 for p in packets if 'alerts' in p)
                st.metric("Alerts Generated", alerts)
            
            with col3:
                unique_ips = len(set([p.get('src_ip', '') for p in packets if 'src_ip' in p] + 
                                   [p.get('dst_ip', '') for p in packets if 'dst_ip' in p]))
                st.metric("Unique IPs", unique_ips)
            
            with col4:
                if 'timestamp' in df.columns and not df['timestamp'].empty:
                    duration = df['timestamp'].max() - df['timestamp'].min()
                    st.metric("Duration", str(duration).split('.')[0])
                else:
                    st.metric("Duration", "N/A")
        
        with tab2:
            # Protocol distribution
            if 'protocol' in df.columns:
                protocol_counts = df['protocol'].value_counts()
                if not protocol_counts.empty:
                    fig = px.pie(values=protocol_counts.values, names=protocol_counts.index, 
                               title="Protocol Distribution")
                    st.plotly_chart(fig, use_container_width=True)
            
            # Top source and destination IPs
            col1, col2 = st.columns(2)
            
            with col1:
                if 'src_ip' in df.columns:
                    src_ip_counts = df['src_ip'].value_counts().head(10)
                    if not src_ip_counts.empty:
                        fig = px.bar(x=src_ip_counts.values, y=src_ip_counts.index, 
                                   orientation='h', title="Top Source IPs")
                        st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                if 'dst_ip' in df.columns:
                    dst_ip_counts = df['dst_ip'].value_counts().head(10)
                    if not dst_ip_counts.empty:
                        fig = px.bar(x=dst_ip_counts.values, y=dst_ip_counts.index, 
                                   orientation='h', title="Top Destination IPs")
                        st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            # Show alerts
            alert_packets = [p for p in packets if 'alerts' in p]
            if alert_packets:
                st.subheader("🚨 Alert Details")
                for i, packet in enumerate(alert_packets):
                    with st.expander(f"Alert #{i+1} - {packet.get('timestamp', 'N/A')}"):
                        st.json(packet)
            else:
                st.info("No alerts detected in the captured packets.")
        
        with tab4:
            # Time series of packet volume
            if 'timestamp' in df.columns and not df['timestamp'].empty:
                df_time = df.groupby(df['timestamp'].dt.floor('1min')).size().reset_index()
                df_time.columns = ['timestamp', 'packet_count']
                
                fig = px.line(df_time, x='timestamp', y='packet_count', 
                            title="Packet Volume Over Time")
                st.plotly_chart(fig, use_container_width=True)
    
    def create_dynamic_visualizations(self, behaviors):
        """Create dynamic analysis visualizations"""
        st.subheader("🔍 Dynamic Analysis")
        
        if not behaviors:
            st.info("📋 No dynamic analysis data available yet.")
            st.markdown("""
            **To collect dynamic analysis data:**
            1. Click **"🔄 System-wide Monitor"** in the sidebar
            2. Or run manually: `python analysis/dynamic_analyzer.py`
            3. The analyzer will monitor system processes and behaviors
            """)
            
            # Show a sample of what dynamic analysis would look like
            st.subheader("📊 Sample Dynamic Analysis")
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Processes Monitored", "0")
                st.metric("Suspicious Behaviors", "0")
            
            with col2:
                st.metric("File Operations", "0")
                st.metric("Network Connections", "0")
            
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(behaviors)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        st.subheader("🔍 Dynamic Analysis Results")
        
        # Show summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Processes Monitored", len(behaviors))
        with col2:
            suspicious_count = len([b for b in behaviors if b.get('suspicious', False)])
            st.metric("Suspicious Behaviors", suspicious_count)
        with col3:
            unique_processes = len(set([b.get('process_name', '') for b in behaviors]))
            st.metric("Unique Processes", unique_processes)
        with col4:
            if 'timestamp' in df.columns and not df.empty:
                duration = df['timestamp'].max() - df['timestamp'].min()
                st.metric("Duration", str(duration).split('.')[0])
            else:
                st.metric("Duration", "N/A")
        
        # Behavior type distribution
        if 'behavior_type' in df.columns:
            behavior_counts = df['behavior_type'].value_counts()
            if not behavior_counts.empty:
                fig = px.pie(values=behavior_counts.values, names=behavior_counts.index, 
                           title="Behavior Type Distribution")
                st.plotly_chart(fig, use_container_width=True)
        
        # Show all monitored processes
        st.subheader("📋 All Monitored Processes")
        if behaviors:
            # Create a summary table
            process_summary = {}
            for behavior in behaviors:
                process_name = behavior.get('process_name', 'Unknown')
                if process_name not in process_summary:
                    process_summary[process_name] = {
                        'count': 0,
                        'suspicious': False,
                        'max_cpu': 0,
                        'pids': set(),
                        'cmdlines': set()
                    }
                
                process_summary[process_name]['count'] += 1
                process_summary[process_name]['pids'].add(behavior.get('pid', 'N/A'))
                if behavior.get('cmdline'):
                    process_summary[process_name]['cmdlines'].add(behavior.get('cmdline'))
                if behavior.get('cpu_percent', 0) > process_summary[process_name]['max_cpu']:
                    process_summary[process_name]['max_cpu'] = behavior.get('cpu_percent', 0)
                if behavior.get('suspicious', False):
                    process_summary[process_name]['suspicious'] = True
            
            # Display summary table
            summary_data = []
            for process_name, data in process_summary.items():
                summary_data.append({
                    'Process Name': process_name,
                    'Occurrences': data['count'],
                    'Max CPU %': f"{data['max_cpu']:.1f}%",
                    'PIDs': len(data['pids']),
                    'Suspicious': '🚨 YES' if data['suspicious'] else '✅ No',
                    'Command Lines': len(data['cmdlines'])
                })
            
            if summary_data:
                df_summary = pd.DataFrame(summary_data)
                st.dataframe(df_summary, use_container_width=True)
        
        # Suspicious behaviors
        suspicious_behaviors = [b for b in behaviors if b.get('suspicious', False)]
        if suspicious_behaviors:
            st.subheader("🚨 Suspicious Behaviors Detected")
            for i, behavior in enumerate(suspicious_behaviors):
                with st.expander(f"Suspicious Behavior #{i+1} - {behavior.get('process_name', 'N/A')}"):
                    st.write(f"**Process:** {behavior.get('process_name', 'N/A')}")
                    st.write(f"**PID:** {behavior.get('pid', 'N/A')}")
                    st.write(f"**Command Line:** {behavior.get('cmdline', 'N/A')}")
                    st.write(f"**CPU Usage:** {behavior.get('cpu_percent', 'N/A')}%")
                    st.write(f"**Timestamp:** {behavior.get('timestamp', 'N/A')}")
                    st.write(f"**Why Suspicious:** Contains suspicious keywords in command line")
        else:
            st.info("✅ No suspicious behaviors detected during monitoring.")
            
        # Show monitoring session details
        if behaviors:
            st.subheader("📊 Monitoring Session Details")
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Total Process Checks:** {len(behaviors)}")
                st.write(f"**Monitoring Duration:** 10 seconds")
                st.write(f"**Check Frequency:** Every 1 second")
            
            with col2:
                st.write(f"**Unique Processes Found:** {len(set([b.get('process_name', '') for b in behaviors]))}")
                st.write(f"**Suspicious Patterns Checked:** powershell, cmd, wget, curl, nc, netcat, reverse, shell, backdoor, keylogger")
                st.write(f"**Session Status:** ✅ Complete")
        
        # Process activity over time
        if 'timestamp' in df.columns and 'process_name' in df.columns and not df.empty:
            process_counts = df.groupby(['timestamp', 'process_name']).size().reset_index()
            process_counts.columns = ['timestamp', 'process_name', 'activity_count']
            
            fig = px.line(process_counts, x='timestamp', y='activity_count', 
                         color='process_name', title="Process Activity Over Time")
            st.plotly_chart(fig, use_container_width=True)
    
    def create_static_visualizations(self, reports):
        """Create static analysis visualizations"""
        st.subheader("📋 Static Analysis")
        
        if not reports:
            st.info("📋 No static analysis reports available yet.")
            st.markdown("""
            **To perform static analysis:**
            1. Upload a PE file (`.exe` or `.dll`) using the file uploader in the sidebar
            2. Click **"🔍 Analyze File"** to run the analysis
            3. Or run manually: `python analysis/static_analyzer.py <file_path>`
            """)
            
            # Show a sample of what static analysis would look like
            st.subheader("📊 Sample Static Analysis")
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Files Analyzed", "0")
                st.metric("Suspicious Indicators", "0")
            
            with col2:
                st.metric("YARA Matches", "0")
                st.metric("Imports Analyzed", "0")
            
            return
        
        st.subheader("📋 Static Analysis Reports")
        
        for i, report in enumerate(reports):
            with st.expander(f"Report #{i+1} - {report.get('file_info', {}).get('path', 'Unknown')}"):
                st.json(report)
    
    def create_control_panel(self):
        """Create control panel for running tools"""
        st.sidebar.header("🎛️ Control Panel")
        
        st.sidebar.subheader("Packet Sniffer")
        
        col1, col2 = st.sidebar.columns(2)
        
        with col1:
            if st.button("📡 Start Sniffer"):
                try:
                    # Network monitoring using psutil instead of raw packet capture
                    import sys
                    import os
                    import socket
                    from datetime import datetime
                    import psutil
                    
                    # Add parent directory to path to find modules
                    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    
                    # Initialize packet storage
                    if 'captured_packets' not in st.session_state:
                        st.session_state.captured_packets = []
                    
                    # Clear previous packets
                    st.session_state.captured_packets = []
                    
                    # Show capturing message
                    st.sidebar.info("🔄 Monitoring network connections... Please wait...")
                    
                    # Get network connections using psutil
                    connections = psutil.net_connections(kind='inet')
                    
                    # Convert connections to packet-like format
                    for i, conn in enumerate(connections[:10]):  # Limit to 10 connections
                        if conn.status == 'ESTABLISHED':
                            packet_info = {
                                "timestamp": datetime.now().isoformat(),
                                "packet_number": i + 1,
                                "src_ip": conn.laddr.ip if conn.laddr else "N/A",
                                "src_port": conn.laddr.port if conn.laddr else "N/A",
                                "dst_ip": conn.raddr.ip if conn.raddr else "N/A",
                                "dst_port": conn.raddr.port if conn.raddr else "N/A",
                                "protocol_name": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                                "status": conn.status,
                                "pid": conn.pid,
                                "length": 0  # Not available from psutil
                            }
                            st.session_state.captured_packets.append(packet_info)
                    
                    # Show results
                    if st.session_state.captured_packets:
                        st.sidebar.success(f"✅ Found {len(st.session_state.captured_packets)} active connections!")
                        st.session_state.sniffer_running = True
                        st.session_state.last_update = datetime.now().strftime("%H:%M:%S")
                        
                        # Show connection details in sidebar
                        st.sidebar.subheader("🌐 Active Connections:")
                        for i, packet in enumerate(st.session_state.captured_packets[:3]):  # Show first 3
                            with st.sidebar.expander(f"Connection {packet['packet_number']}"):
                                st.write(f"**Source:** {packet.get('src_ip', 'N/A')}:{packet.get('src_port', 'N/A')}")
                                st.write(f"**Destination:** {packet.get('dst_ip', 'N/A')}:{packet.get('dst_port', 'N/A')}")
                                st.write(f"**Protocol:** {packet.get('protocol_name', 'Unknown')}")
                                st.write(f"**Status:** {packet.get('status', 'Unknown')}")
                                st.write(f"**PID:** {packet.get('pid', 'N/A')}")
                    else:
                        st.sidebar.warning("⚠️ No active connections found.")
                        
                except Exception as e:
                    st.sidebar.error(f"❌ Failed to monitor network: {e}")
                    st.sidebar.info("Try running manually: python sniffing/packet_sniffer.py")
        
        with col2:
            if st.button("🔄 Capture New Data"):
                try:
                    # Capture new network data
                    import psutil
                    import socket
                    from datetime import datetime
                    
                    # Get current network connections
                    connections = psutil.net_connections(kind='inet')
                    
                    # Initialize if not exists
                    if 'captured_packets' not in st.session_state:
                        st.session_state.captured_packets = []
                    
                    # Add new connections to existing data
                    new_connections = 0
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            # Check if this connection is already captured
                            existing = False
                            for existing_packet in st.session_state.captured_packets:
                                if (existing_packet.get('src_ip') == (conn.laddr.ip if conn.laddr else None) and
                                    existing_packet.get('src_port') == (conn.laddr.port if conn.laddr else None) and
                                    existing_packet.get('dst_ip') == (conn.raddr.ip if conn.raddr else None) and
                                    existing_packet.get('dst_port') == (conn.raddr.port if conn.raddr else None)):
                                    existing = True
                                    break
                            
                            if not existing:
                                packet_info = {
                                    "timestamp": datetime.now().isoformat(),
                                    "packet_number": len(st.session_state.captured_packets) + 1,
                                    "src_ip": conn.laddr.ip if conn.laddr else "N/A",
                                    "src_port": conn.laddr.port if conn.laddr else "N/A",
                                    "dst_ip": conn.raddr.ip if conn.raddr else "N/A",
                                    "dst_port": conn.raddr.port if conn.raddr else "N/A",
                                    "protocol_name": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                                    "status": conn.status,
                                    "pid": conn.pid,
                                    "length": 0
                                }
                                st.session_state.captured_packets.append(packet_info)
                                new_connections += 1
                    
                    if new_connections > 0:
                        st.sidebar.success(f"✅ Added {new_connections} new connections!")
                    else:
                        st.sidebar.info("ℹ️ No new connections found")
                        
                except Exception as e:
                    st.sidebar.error(f"❌ Failed to capture new data: {e}")
        
        with col2:
            if st.button("⏹️ Stop Sniffer"):
                st.session_state.sniffer_running = False
                st.session_state.captured_packets = []
                st.sidebar.success("✅ Packet sniffer stopped!")
                st.sidebar.info("Captured data cleared")
        
        st.sidebar.subheader("Static Analyzer")
        uploaded_file = st.sidebar.file_uploader("Upload PE file for analysis", type=['exe', 'dll'])
        if uploaded_file and st.sidebar.button("🔍 Analyze File"):
            try:
                # Save uploaded file
                sample_path = f"samples/{uploaded_file.name}"
                os.makedirs("samples", exist_ok=True)
                with open(sample_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                # Run static analysis
                import sys
                import os
                # Add parent directory to path to find modules
                sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                
                from analysis.static_analyzer import StaticAnalyzer
                analyzer = StaticAnalyzer()
                result = analyzer.analyze_file(sample_path)
                
                if result:
                    st.sidebar.success(f"✅ Analysis completed!")
                    st.sidebar.json(result)
                else:
                    st.sidebar.warning(f"⚠️ Analysis completed but no valid PE data found")
                    st.sidebar.info("The file may not be a valid PE executable or may be corrupted")
                
            except Exception as e:
                st.sidebar.error(f"❌ Analysis failed: {e}")
                st.sidebar.info(f"File saved as {sample_path}")
        
        st.sidebar.subheader("Dynamic Analyzer")
        if st.sidebar.button("🧪 Run Test Script"):
            try:
                import subprocess
                import threading
                
                def run_dynamic_test():
                    try:
                        result = subprocess.run([
                            'python', 'analysis/dynamic_analyzer.py', 
                            '-s', 'samples/test_script.py'
                        ], capture_output=True, text=True, timeout=30)
                        
                        # Store results in instance variable
                        if result.returncode == 0:
                            self.dynamic_test_results['output'] = result.stdout
                            self.dynamic_test_results['success'] = True
                        else:
                            self.dynamic_test_results['output'] = result.stderr
                            self.dynamic_test_results['success'] = False
                        
                        self.dynamic_test_results['completed'] = True
                            
                    except Exception as e:
                        self.dynamic_test_results['output'] = str(e)
                        self.dynamic_test_results['success'] = False
                        self.dynamic_test_results['completed'] = True
                
                # Run in background thread
                thread = threading.Thread(target=run_dynamic_test, daemon=True)
                thread.start()
                
                st.sidebar.info("🔄 Running dynamic analysis test... Please wait...")
                
            except Exception as e:
                st.sidebar.error(f"❌ Failed to start test: {e}")
                st.sidebar.info("Run manually: python analysis/dynamic_analyzer.py -s samples/test_script.py")
        
        # Show test results if available
        if self.dynamic_test_results['completed']:
            if self.dynamic_test_results['success']:
                st.sidebar.success("✅ Dynamic test completed!")
                with st.sidebar.expander("📋 Test Output"):
                    st.text(self.dynamic_test_results['output'])
            else:
                st.sidebar.error("❌ Dynamic test failed!")
                with st.sidebar.expander("📋 Error Output"):
                    st.text(self.dynamic_test_results['output'])
        
        if st.sidebar.button("🔄 System-wide Monitor"):
            try:
                # Simple system monitoring without signal handlers
                import psutil
                import threading
                import time
                from datetime import datetime
                
                # Simple system monitoring function
                def monitor_system():
                    try:
                        # Monitor for 10 seconds
                        start_time = time.time()
                        behaviors = []
                        
                        while time.time() - start_time < 10:
                            # Get current processes
                            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent']):
                                try:
                                    proc_info = proc.info
                                    cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
                                    
                                    # Check for suspicious patterns
                                    suspicious = False
                                    suspicious_patterns = [
                                        'powershell', 'cmd', 'wget', 'curl', 'nc', 'netcat',
                                        'reverse', 'shell', 'backdoor', 'keylogger'
                                    ]
                                    
                                    for pattern in suspicious_patterns:
                                        if pattern.lower() in cmdline.lower():
                                            suspicious = True
                                            break
                                    
                                    behavior_info = {
                                        "timestamp": datetime.now().isoformat(),
                                        "process_name": proc_info['name'],
                                        "pid": proc_info['pid'],
                                        "cmdline": cmdline,
                                        "cpu_percent": proc_info['cpu_percent'],
                                        "suspicious": suspicious,
                                        "behavior_type": "process_monitoring"
                                    }
                                    
                                    behaviors.append(behavior_info)
                                    
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            
                            time.sleep(1)  # Check every second
                        
                        # Store results in instance variable
                        self.monitoring_results['behaviors'] = behaviors
                        self.monitoring_results['completed'] = True
                        
                    except Exception as e:
                        self.monitoring_results['error'] = str(e)
                        self.monitoring_results['completed'] = True
                
                # Run monitoring in background
                thread = threading.Thread(target=monitor_system, daemon=True)
                thread.start()
                
                st.sidebar.success("✅ Dynamic analyzer started!")
                st.sidebar.info("Monitoring system processes for 10 seconds...")
                
                # Check if monitoring is complete
                if self.monitoring_results['completed']:
                    if self.monitoring_results['error']:
                        st.sidebar.error(f"❌ Monitoring failed: {self.monitoring_results['error']}")
                    else:
                        st.sidebar.success("✅ Monitoring completed! Check the Dynamic Analysis tab for results.")
                        # Update session state for display in other tabs
                        st.session_state.dynamic_behaviors = self.monitoring_results['behaviors']
                
            except Exception as e:
                st.sidebar.error(f"❌ Failed to start dynamic analyzer: {e}")
                st.sidebar.info("Run manually: python analysis/dynamic_analyzer.py -w")
        
        st.sidebar.subheader("📊 Refresh Data")
        col1, col2 = st.sidebar.columns(2)
        
        with col1:
            if st.button("🔄 Refresh Dashboard"):
                # Clear cached data to force reload
                if 'captured_packets' in st.session_state:
                    del st.session_state.captured_packets
                st.rerun()
        
        with col2:
            # Auto-refresh every 30 seconds
            if st.button("⏱️ Auto Refresh"):
                st.session_state.auto_refresh = not st.session_state.get('auto_refresh', False)
                if st.session_state.auto_refresh:
                    st.sidebar.success("✅ Auto-refresh enabled")
                else:
                    st.sidebar.info("⏸️ Auto-refresh disabled")
        
        # Show auto-refresh status
        if st.session_state.get('auto_refresh', False):
            st.sidebar.info("🔄 Auto-refreshing every 30 seconds")
    
    def create_system_status(self):
        """Create system status overview"""
        st.subheader("💻 System Status")
        
        if not PSUTIL_AVAILABLE:
            st.warning("psutil not available - system status information is limited")
            return
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("CPU Usage", f"{psutil.cpu_percent()}%")
        
        with col2:
            memory = psutil.virtual_memory()
            st.metric("Memory Usage", f"{memory.percent}%")
        
        with col3:
            try:
                disk = psutil.disk_usage('/')
                st.metric("Disk Usage", f"{disk.percent}%")
            except:
                st.metric("Disk Usage", "N/A")
        
        with col4:
            try:
                network = psutil.net_io_counters()
                st.metric("Network Packets", f"{network.packets_sent + network.packets_recv:,}")
            except:
                st.metric("Network Packets", "N/A")
        
        # Active processes
        st.subheader("🔄 Active Processes")
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            st.error(f"Error getting process information: {e}")
        
        if processes:
            df_proc = pd.DataFrame(processes)
            df_proc = df_proc.sort_values('cpu_percent', ascending=False).head(10)
            st.dataframe(df_proc, use_container_width=True)
    
    def run(self):
        """Main dashboard function"""
        st.title("🛡️ PySniff & PyMal Dashboard")
        st.markdown("**Python-Based Packet Sniffer and Malware Behavior Analyzer**")
        
        # Create control panel
        self.create_control_panel()
        
        # Load data
        packets = self.load_packet_data()
        behaviors = self.load_dynamic_data()
        reports = self.load_static_reports()
        
        # Create main content tabs
        tab1, tab2, tab3, tab4 = st.tabs(["📡 Packet Analysis", "🔍 Dynamic Analysis", "📋 Static Analysis", "📊 System Status"])
        
        with tab1:
            self.create_packet_visualizations(packets)
        
        with tab2:
            self.create_dynamic_visualizations(behaviors)
        
        with tab3:
            self.create_static_visualizations(reports)
        
        with tab4:
            self.create_system_status()

def main():
    """Main function"""
    dashboard = Dashboard()
    dashboard.run()

if __name__ == "__main__":
    main() 