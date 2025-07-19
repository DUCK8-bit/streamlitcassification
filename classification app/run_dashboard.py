import subprocess
import time
import sys
import os

def run_apps():
    """Run both the main app and metrics dashboard"""
    print("🚀 Starting Fashion Classification System...")
    print("=" * 50)
    
    # Start the main app
    print("📱 Starting main application...")
    main_app = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", "8501"])
    
    # Wait a moment for the main app to start
    time.sleep(3)
    
    # Start the metrics dashboard
    print("📊 Starting metrics dashboard...")
    metrics_dashboard = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "metrics_dashboard.py", "--server.port", "8502"])
    
    # Wait a moment for the metrics dashboard to start
    time.sleep(3)
    
    print("=" * 50)
    print("✅ Both applications are now running!")
    print("📱 Main App: http://localhost:8501")
    print("📊 Metrics Dashboard: http://localhost:8502")
    print("📈 Prometheus Metrics: http://localhost:9090/metrics")
    print("=" * 50)
    print("💡 Press Ctrl+C to stop both applications")
    
    try:
        # Keep the script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping applications...")
        main_app.terminate()
        metrics_dashboard.terminate()
        print("✅ Applications stopped")

if __name__ == "__main__":
    run_apps() 