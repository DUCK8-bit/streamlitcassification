# 🎉 Complete Fashion Classification System

This repository contains a comprehensive Fashion Classification System with multiple interactive dashboards, containerized with Docker and ready for deployment on Kubernetes with Helm.

## 📱 Overview

The system consists of three main applications that work together to provide a complete fashion classification experience:

### 🎯 Main Applications

1. **Fashion Classifier** (Port 8501)
   - Upload and classify fashion images using AI
   - Real-time classification with confidence scores
   - Stores results for dashboard analysis

2. **Metrics Dashboard** (Port 8503)
   - Shows aggregated performance metrics
   - Real-time charts and statistics
   - Prometheus integration for monitoring

3. **Results Dashboard** (Port 8504) ✨ **NEW**
   - Shows detailed results for each classification
   - Displays the actual image, predictions, and confidence scores
   - Beautiful visualizations with color-coded confidence levels
   - Filtering and sorting capabilities
   - Summary statistics and performance analysis

- **Week 1:** Foundation & Dockerization Planning
- **Week 2:** Docker Build & Local Testing
- **Week 3:** Kubernetes Deployment Setup
- **Week 4:** Helm & Autoscaling
- **Week 5:** Prometheus & Grafana Integration
- **Week 6:** Finalization & Handoff

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Docker (for containerized deployment)
- Kubernetes (e.g., minikube, Docker Desktop Kubernetes) - optional
- Helm - optional

### 🎯 Quick Start (Local Development)

#### Option 1: Easy Launcher (Recommended)
```bash
# Windows
start_dashboards.bat

# PowerShell
.\start_dashboards.ps1

# Python directly
python run_all_dashboards.py
```

#### Option 2: Manual Start
```bash
# Activate virtual environment
env\Scripts\activate  # Windows
source env/bin/activate  # Linux/Mac

# Start each dashboard in separate terminals
streamlit run app.py --server.port=8501
streamlit run metrics_dashboard.py --server.port=8503
streamlit run classification_results_dashboard.py --server.port=8504
```

#### Access Your Dashboards
- **Fashion Classifier**: [http://localhost:8501](http://localhost:8501)
- **Metrics Dashboard**: [http://localhost:8503](http://localhost:8503)
- **Results Dashboard**: [http://localhost:8504](http://localhost:8504)

### 🐳 Docker Deployment

1.  **Build the Docker image:**
    ```sh
    docker build -t fashion-classifier .
    ```

2.  **Run the Docker container:**
    ```sh
    docker run -d -p 8501:8501 -p 8080:8080 --name fashion-app fashion-classifier
    ```

3.  **Access the application:**
    - Streamlit UI: [http://localhost:8501](http://localhost:8501)
    - Metrics Endpoint: [http://localhost:8080/metrics](http://localhost:8080/metrics)

### Kubernetes Deployment with Helm

1.  **Install the Helm chart:**
    ```sh
    helm install my-release ./chart
    ```

2.  **Access the application:**
    - You will need to configure Ingress or use `kubectl port-forward` to access the application.
    - Example using port-forward:
      ```sh
      kubectl port-forward svc/my-release-fashion-classifier-svc 8501:80
      ```
      Then access [http://localhost:8501](http://localhost:8501).

## 📊 Dashboard Features

### 🎨 Results Dashboard

For Each Classification:
- 📸 **The uploaded image** (side by side with results)
- 🔍 **Top 3-5 predictions** with confidence scores
- ⏱️ **Processing time** (how long the AI took)
- 📅 **Timestamp** of when it was classified
- 🎨 **Color-coded confidence** (green = high, yellow = medium, red = low)

### 🛠️ Results Dashboard Features
- 🔍 **Filter by confidence level**
- 📊 **Sort by different criteria** (newest, highest confidence, etc.)
- 📈 **Summary statistics**
- 🗑️ **Clear results button**
- 🔄 **Auto-refresh every 5 seconds**

### 💡 Example of What You'll See

When you upload a sneaker image, you'll see:
- **Image**: The sneaker photo
- **Predictions**:
  - #1 Sneakers (85.2% confidence) 🟢
  - #2 Running Shoes (12.1% confidence) 🟡
  - #3 Athletic Footwear (2.7% confidence) 🔴
- **Processing Time**: 2.44 seconds
- **Timestamp**: 2025-07-06 10:15:30

### Customizing the Helm Chart

You can customize the deployment by modifying the `values.yaml` file or by providing values during installation.

**Example: Enable Autoscaling**
```sh
helm install my-release ./chart --set autoscaling.enabled=true --set autoscaling.maxReplicas=10
```

## 🔄 CI/CD

The repository includes a GitHub Actions workflow in `.github/workflows/ci.yaml` that automates building and pushing the Docker image to a container registry on pushes to the `main` branch. You will need to configure `DOCKER_USERNAME` and `DOCKER_PASSWORD` secrets in your repository settings. 