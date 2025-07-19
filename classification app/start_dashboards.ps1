# Fashion Classification System - Dashboard Launcher
Write-Host "🎉 Starting Fashion Classification System..." -ForegroundColor Green
Write-Host ""

# Check if virtual environment exists
if (Test-Path "env\Scripts\activate.ps1") {
    Write-Host "🔧 Activating virtual environment..." -ForegroundColor Yellow
    & "env\Scripts\activate.ps1"
} else {
    Write-Host "❌ Virtual environment not found. Please run 'python -m venv env' first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🚀 Starting all dashboards..." -ForegroundColor Cyan
Write-Host ""

# Start the multi-dashboard launcher
try {
    python run_all_dashboards.py
} catch {
    Write-Host "❌ Error starting dashboards: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "💡 Alternative: Start each dashboard manually:" -ForegroundColor Yellow
    Write-Host "   • Fashion Classifier: streamlit run app.py --server.port=8501" -ForegroundColor White
    Write-Host "   • Metrics Dashboard: streamlit run metrics_dashboard.py --server.port=8503" -ForegroundColor White
    Write-Host "   • Results Dashboard: streamlit run classification_results_dashboard.py --server.port=8504" -ForegroundColor White
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 