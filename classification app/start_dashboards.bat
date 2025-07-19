@echo off
echo 🎉 Starting Fashion Classification System...
echo.

REM Activate virtual environment
echo 🔧 Activating virtual environment...
call env\Scripts\activate.bat

echo.
echo 🚀 Starting all dashboards...
echo.

REM Start the multi-dashboard launcher
python run_all_dashboards.py

pause 