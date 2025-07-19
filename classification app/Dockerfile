FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the necessary app files
COPY app.py .
COPY app_wrapper.py .
COPY metrics_dashboard.py .
COPY classification_results_dashboard.py .
COPY run_all_dashboards.py .
COPY results/ ./results/

# Expose the ports for Streamlit and metrics
EXPOSE 8501
EXPOSE 8080
EXPOSE 8503
EXPOSE 8504

# Healthcheck to see if streamlit is running
HEALTHCHECK CMD streamlit hello

# Default command: run all dashboards
CMD ["python", "run_all_dashboards.py"] 