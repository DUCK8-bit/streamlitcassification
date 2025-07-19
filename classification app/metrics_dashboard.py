import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import re
import json
import os

# Page config
st.set_page_config(
    page_title="Fashion Classification Metrics",
    page_icon="📊",
    layout="wide"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        text-align: center;
        color: #1f2937;
        margin-bottom: 1rem;
    }
    .subtitle {
        text-align: center;
        color: #6b7280;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 15px;
        border: 1px solid #e0e0e0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        margin: 20px 0;
    }
    .stats-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 15px;
        text-align: center;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

def fetch_prometheus_metrics(port=9090):
    """Fetch metrics from Prometheus endpoint"""
    try:
        url = f"http://localhost:{port}/metrics"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            st.error(f"Failed to fetch metrics from port {port}")
            return None
    except requests.exceptions.RequestException as e:
        st.error(f"Error connecting to metrics server on port {port}: {e}")
        return None

def parse_prometheus_metrics(metrics_text):
    """Parse Prometheus metrics text into structured data"""
    if not metrics_text:
        return {}
    
    metrics = {}
    lines = metrics_text.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if line.startswith('#') or not line:  # Skip comments and empty lines
            continue
            
        # Parse metric line
        if '{' in line:
            # Metric with labels
            match = re.match(r'(\w+)\{([^}]+)\}\s+([0-9.]+)', line)
            if match:
                metric_name, labels, value = match.groups()
                if metric_name not in metrics:
                    metrics[metric_name] = []
                metrics[metric_name].append({
                    'labels': labels,
                    'value': float(value)
                })
        else:
            # Simple metric
            parts = line.split()
            if len(parts) >= 2:
                metric_name = parts[0]
                try:
                    value = float(parts[1])
                    if metric_name not in metrics:
                        metrics[metric_name] = []
                    metrics[metric_name].append({
                        'labels': '',
                        'value': value
                    })
                except ValueError:
                    continue
    
    return metrics

def create_metric_chart(metric_name, metric_data, chart_type="line"):
    """Create a Plotly chart for a metric"""
    if not metric_data:
        return None
    
    # Extract values and labels
    values = [item['value'] for item in metric_data]
    labels = [item['labels'] for item in metric_data]
    
    if chart_type == "line":
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            y=values,
            mode='lines+markers',
            name=metric_name,
            line=dict(color='#667eea', width=3),
            marker=dict(size=8)
        ))
        fig.update_layout(
            title=f"{metric_name.replace('_', ' ').title()}",
            xaxis_title="Time",
            yaxis_title="Value",
            height=400,
            showlegend=False
        )
    elif chart_type == "bar":
        fig = go.Figure(data=[
            go.Bar(x=list(range(len(values))), y=values, name=metric_name)
        ])
        fig.update_layout(
            title=f"{metric_name.replace('_', ' ').title()}",
            xaxis_title="Sample",
            yaxis_title="Value",
            height=400,
            showlegend=False
        )
    
    return fig

def display_metrics_dashboard():
    """Main function to display the metrics dashboard"""
    st.markdown('<h1 class="main-header">📊 Fashion Classification Metrics</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Real-time monitoring of classification performance and system metrics</p>', unsafe_allow_html=True)
    
    # Sidebar for configuration
    st.sidebar.header("⚙️ Configuration")
    port = st.sidebar.selectbox("Metrics Server Port", [9090, 9091, 9092, 8503, 8504], index=0)
    refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 5, 60, 10)
    
    # Auto-refresh
    if st.sidebar.button("🔄 Refresh Now"):
        st.rerun()
    
    # Load historical results from JSON file
    def load_classification_results():
        """Load classification results from JSON file"""
        try:
            if os.path.exists('results/classification_results.json'):
                with open('results/classification_results.json', 'r') as f:
                    results = json.load(f)
                    return results
            return []
        except Exception as e:
            print(f"Error loading results: {e}")
            return []
    
    historical_results = load_classification_results()
    total_classifications = len(historical_results)
    
    # Fetch metrics
    metrics_text = fetch_prometheus_metrics(port)
    if not metrics_text:
        st.error("❌ Could not connect to metrics server. Please ensure the main app is running.")
        st.info("💡 Make sure to run `streamlit run app.py` first to start the metrics server.")
        return
    
    # Parse metrics
    metrics = parse_prometheus_metrics(metrics_text)
    
    if not metrics:
        st.warning("⚠️ No metrics found. The application may not have processed any requests yet.")
        return
    
    # Display key metrics
    st.markdown("## 📈 Key Performance Indicators")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Total requests (from Prometheus metrics)
    total_requests = 0
    if 'requests_total' in metrics:
        total_requests = sum(item['value'] for item in metrics['requests_total'])
    
    with col1:
        st.markdown(f"""
        <div class="stats-card">
            <h3>📊 Total Requests</h3>
            <h2>{total_requests}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Total classifications (from JSON file)
    with col2:
        st.markdown(f"""
        <div class="stats-card">
            <h3>🔍 Total Classifications</h3>
            <h2>{total_classifications}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Average classification time (from JSON file)
    avg_classification_time = 0
    if historical_results:
        total_time = sum(result.get('processing_time', 0) for result in historical_results)
        avg_classification_time = total_time / len(historical_results)
    
    with col3:
        st.markdown(f"""
        <div class="stats-card">
            <h3>⏱️ Avg Classification Time</h3>
            <h2>{avg_classification_time:.3f}s</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Average confidence (from JSON file)
    avg_confidence = 0
    if historical_results:
        total_confidence = 0
        confidence_count = 0
        for result in historical_results:
            if 'predictions' in result and result['predictions']:
                # Get the top prediction confidence
                top_confidence = result['predictions'][0].get('confidence', 0)
                total_confidence += top_confidence
                confidence_count += 1
        if confidence_count > 0:
            avg_confidence = total_confidence / confidence_count
    
    with col4:
        st.markdown(f"""
        <div class="stats-card">
            <h3>🎯 Avg Confidence</h3>
            <h2>{avg_confidence:.1f}%</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Data source comparison
    st.markdown("## 📊 Data Sources Comparison")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔄 Real-time Metrics (Prometheus)")
        st.markdown(f"""
        <div class="metric-card">
            <h4>Current Session Metrics</h4>
            <p><strong>Requests:</strong> {total_requests}</p>
            <p><strong>Classifications:</strong> {sum(item['value'] for item in metrics.get('classification_time_seconds_count', [{'value': 0}]))}</p>
            <p><strong>Model Load Time:</strong> {sum(item['value'] for item in metrics.get('model_load_time_seconds_sum', [{'value': 0}])) / max(sum(item['value'] for item in metrics.get('model_load_time_seconds_count', [{'value': 1}])), 1):.3f}s</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("### 📁 Historical Data (JSON)")
        st.markdown(f"""
        <div class="metric-card">
            <h4>All-time Statistics</h4>
            <p><strong>Total Classifications:</strong> {total_classifications}</p>
            <p><strong>Average Processing Time:</strong> {avg_classification_time:.3f}s</p>
            <p><strong>Average Confidence:</strong> {avg_confidence:.1f}%</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Detailed metrics charts
    st.markdown("## 📈 Performance Charts")
    
    # Classification time histogram
    if 'classification_time_seconds_bucket' in metrics:
        st.markdown("### ⏱️ Classification Time Distribution")
        fig = create_metric_chart("classification_time_seconds", metrics['classification_time_seconds_bucket'], "bar")
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    # Confidence distribution
    if 'classification_confidence_percent_bucket' in metrics:
        st.markdown("### 🎯 Classification Confidence Distribution")
        fig = create_metric_chart("classification_confidence_percent", metrics['classification_confidence_percent_bucket'], "bar")
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    # Raw metrics data
    with st.expander("🔍 Raw Metrics Data"):
        st.code(metrics_text)
    
    # Auto-refresh
    time.sleep(refresh_interval)
    st.rerun()

if __name__ == "__main__":
    display_metrics_dashboard() 