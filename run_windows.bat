@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher was not found. Install an approved Python version or ask IT for guidance.
  pause
  exit /b 1
)
if not exist .venv\Scripts\python.exe (
  py -m venv .venv
  if errorlevel 1 goto :fail
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 goto :fail
python -m streamlit run app.py
if errorlevel 1 goto :fail
exit /b 0
:fail
echo PhishLens could not start. Check the error above and follow your organization's software policy.
pause
exit /b 1
