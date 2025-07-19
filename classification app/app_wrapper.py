import threading
import subprocess
import sys
from flask import Flask
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# Create Flask app
app = Flask(__name__)

# Add prometheus wsgi middleware to route /metrics requests
app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {
    '/metrics': make_wsgi_app()
})

def run_streamlit():
    """Run the Streamlit app as a subprocess."""
    # Use the current Python executable to run streamlit module
    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "app.py",
        "--server.port=8501",
        "--server.address=0.0.0.0",
        "--server.headless=true"
    ])

if __name__ == '__main__':
    # Run Streamlit in a separate thread
    streamlit_thread = threading.Thread(target=run_streamlit)
    streamlit_thread.daemon = True
    streamlit_thread.start()

    # Run Flask app
    # The Flask app will serve on port 8080 and expose /metrics
    # The Streamlit app will serve on port 8501
    # In Kubernetes, we'll expose both via a single service.
    app.run(host='0.0.0.0', port=8080) 