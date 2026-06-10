@echo off
echo.
echo  ThreatScan — Universal Threat Detector
echo  ========================================
echo.

if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate

echo Installing dependencies...
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if not exist ".env" (
    echo Creating .env from template...
    copy .env.example .env
)

echo.
echo  Server starting at http://localhost:8000
echo  Press Ctrl+C to stop.
echo.

set PYTHONPATH=%cd%\backend
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
