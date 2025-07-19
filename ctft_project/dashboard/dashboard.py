#!/usr/bin/env python3
"""
PySniff & PyMal Dashboard
Streamlit-based web interface for visualizing analysis results
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
        
        # Check if psutil is available
        try:
            import psutil
            self.psutil_available = True
            self.psutil = psutil
        except ImportError:
            self.psutil_available = False
            self.psutil = None
        
    def load_packet_data(self):
        """Load packet capture data"""
        packets = []
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
                if 'timestamp' in df.columns:
                    duration = df['timestamp'].max() - df['timestamp'].min()
                    st.metric("Duration", str(duration).split('.')[0])
        
        with tab2:
            # Protocol distribution
            if 'protocol' in df.columns:
                protocol_counts = df['protocol'].value_counts()
                fig = px.pie(values=protocol_counts.values, names=protocol_counts.index, 
                           title="Protocol Distribution")
                st.plotly_chart(fig, use_container_width=True)
            
            # Top source and destination IPs
            col1, col2 = st.columns(2)
            
            with col1:
                if 'src_ip' in df.columns:
                    src_ip_counts = df['src_ip'].value_counts().head(10)
                    fig = px.bar(x=src_ip_counts.values, y=src_ip_counts.index, 
                               orientation='h', title="Top Source IPs")
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                if 'dst_ip' in df.columns:
                    dst_ip_counts = df['dst_ip'].value_counts().head(10)
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
            if 'timestamp' in df.columns:
                df_time = df.groupby(df['timestamp'].dt.floor('1min')).size().reset_index()
                df_time.columns = ['timestamp', 'packet_count']
                
                fig = px.line(df_time, x='timestamp', y='packet_count', 
                            title="Packet Volume Over Time")
                st.plotly_chart(fig, use_container_width=True)
    
    def create_dynamic_visualizations(self, behaviors):
        """Create dynamic analysis visualizations"""
        if not behaviors:
            st.warning("No dynamic analysis data available. Run the dynamic analyzer to collect data.")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(behaviors)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        st.subheader("🔍 Dynamic Analysis Results")
        
        # Behavior type distribution
        if 'behavior_type' in df.columns:
            behavior_counts = df['behavior_type'].value_counts()
            fig = px.pie(values=behavior_counts.values, names=behavior_counts.index, 
                       title="Behavior Type Distribution")
            st.plotly_chart(fig, use_container_width=True)
        
        # Suspicious behaviors
        suspicious_behaviors = [b for b in behaviors if b.get('suspicious', False)]
        if suspicious_behaviors:
            st.subheader("🚨 Suspicious Behaviors Detected")
            for i, behavior in enumerate(suspicious_behaviors):
                with st.expander(f"Suspicious Behavior #{i+1} - {behavior.get('behavior_type', 'N/A')}"):
                    st.json(behavior)
        else:
            st.info("No suspicious behaviors detected.")
        
        # Process activity over time
        if 'timestamp' in df.columns and 'process_name' in df.columns:
            process_counts = df.groupby(['timestamp', 'process_name']).size().reset_index()
            process_counts.columns = ['timestamp', 'process_name', 'activity_count']
            
            fig = px.line(process_counts, x='timestamp', y='activity_count', 
                         color='process_name', title="Process Activity Over Time")
            st.plotly_chart(fig, use_container_width=True)
    
    def create_static_visualizations(self, reports):
        """Create static analysis visualizations"""
        if not reports:
            st.warning("No static analysis reports available. Run the static analyzer to generate reports.")
            return
        
        st.subheader("📋 Static Analysis Reports")
        
        for i, report in enumerate(reports):
            with st.expander(f"Report #{i+1} - {report.get('file_info', {}).get('path', 'Unknown')}"):
                st.json(report)
    
    def create_control_panel(self):
        """Create control panel for running tools"""
        st.sidebar.header("🎛️ Control Panel")
        
        st.sidebar.subheader("Packet Sniffer")
        if st.sidebar.button("📡 Start Sniffer"):
            st.sidebar.info("Run: python sniffing/packet_sniffer.py")
        
        st.sidebar.subheader("Static Analyzer")
        uploaded_file = st.sidebar.file_uploader("Upload PE file for analysis", type=['exe', 'dll'])
        if uploaded_file and st.sidebar.button("🔍 Analyze File"):
            # Save uploaded file
            sample_path = f"samples/{uploaded_file.name}"
            os.makedirs("samples", exist_ok=True)
            with open(sample_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            st.sidebar.success(f"File saved as {sample_path}")
            st.sidebar.info(f"Run: python analysis/static_analyzer.py {sample_path}")
        
        st.sidebar.subheader("Dynamic Analyzer")
        if st.sidebar.button("🧪 Run Test Script"):
            st.sidebar.info("Run: python analysis/dynamic_analyzer.py -s samples/test_script.py")
        
        if st.sidebar.button("🔄 System-wide Monitor"):
            st.sidebar.info("Run: python analysis/dynamic_analyzer.py -w")
        
        st.sidebar.subheader("📊 Refresh Data")
        if st.sidebar.button("🔄 Refresh Dashboard"):
            st.rerun()
    
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
    
    def create_system_status(self):
        """Create system status overview"""
        st.subheader("💻 System Status")
        
        if not self.psutil_available:
            st.warning("psutil not available - system status information is limited")
            return
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("CPU Usage", f"{self.psutil.cpu_percent()}%")
        
        with col2:
            memory = self.psutil.virtual_memory()
            st.metric("Memory Usage", f"{memory.percent}%")
        
        with col3:
            try:
                disk = self.psutil.disk_usage('/')
                st.metric("Disk Usage", f"{disk.percent}%")
            except:
                st.metric("Disk Usage", "N/A")
        
        with col4:
            try:
                network = self.psutil.net_io_counters()
                st.metric("Network Packets", f"{network.packets_sent + network.packets_recv:,}")
            except:
                st.metric("Network Packets", "N/A")
        
        # Active processes
        st.subheader("🔄 Active Processes")
        processes = []
        try:
            for proc in self.psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
                    pass
        except Exception as e:
            st.error(f"Error getting process information: {e}")
        
        if processes:
            df_proc = pd.DataFrame(processes)
            df_proc = df_proc.sort_values('cpu_percent', ascending=False).head(10)
            st.dataframe(df_proc, use_container_width=True)

def main():
    """Main function"""
    # Try to import psutil, but don't fail if it's not available
    try:
        import psutil
        PSUTIL_AVAILABLE = True
    except ImportError:
        PSUTIL_AVAILABLE = False
        st.warning("psutil not available - system status features will be limited")
    
    dashboard = Dashboard()
    dashboard.run()

if __name__ == "__main__":
    main() 