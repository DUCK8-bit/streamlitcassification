import subprocess
import threading
import time
import sys
import os

def run_streamlit_app(app_file, port, name):
    """Run a Streamlit app on a specific port"""
    try:
        print(f"🚀 Starting {name} on port {port}...")
        subprocess.run([
            sys.executable, "-m", "streamlit", "run",
            app_file,
            "--server.port=" + str(port),
            "--server.address=0.0.0.0",
            "--server.headless=true"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error starting {name}: {e}")
    except KeyboardInterrupt:
        print(f"🛑 Stopping {name}...")

def main():
    print("🎉 Fashion Classification System - Multi-Dashboard Launcher")
    print("=" * 60)
    
    # Define the apps and their ports
    apps = [
        ("app.py", 8501, "Fashion Classifier"),
        ("metrics_dashboard.py", 8503, "Metrics Dashboard"),
        ("classification_results_dashboard.py", 8504, "Results Dashboard")
    ]
    
    # Start each app in a separate thread
    threads = []
    for app_file, port, name in apps:
        thread = threading.Thread(
            target=run_streamlit_app,
            args=(app_file, port, name),
            daemon=True
        )
        threads.append(thread)
        thread.start()
        time.sleep(2)  # Small delay between starts
    
    print("\n✅ All dashboards are starting up!")
    print("\n📱 Your Fashion Classification System:")
    print("   • Fashion Classifier: http://localhost:8501")
    print("   • Metrics Dashboard:  http://localhost:8503")
    print("   • Results Dashboard:  http://localhost:8504")
    
    print("\n💡 How to use:")
    print("   1. Upload images in the Fashion Classifier")
    print("   2. View detailed results in the Results Dashboard")
    print("   3. Monitor performance in the Metrics Dashboard")
    print("\n🔄 Press Ctrl+C to stop all dashboards")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down all dashboards...")
        sys.exit(0)

if __name__ == "__main__":
    main() 