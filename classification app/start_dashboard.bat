@echo off
echo Starting Fashion Classification Metrics Dashboard...
echo.

REM Activate virtual environment if it exists
if exist "env\Scripts\activate.bat" (
    echo Activating virtual environment...
    call env\Scripts\activate.bat
)

REM Start the metrics dashboard
echo Starting metrics dashboard on http://localhost:8502
echo.
echo Make sure the main app is running first on http://localhost:8501
echo.
streamlit run metrics_dashboard.py --server.port 8502

pause 