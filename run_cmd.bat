@echo off
if exist "%~dp0anonymizer.exe" (
  "%~dp0anonymizer.exe" %*
) else if exist "%~dp0.venv\Scripts\python.exe" (
  "%~dp0.venv\Scripts\python.exe" "%~dp0anonymize.py" %*
) else (
  python "%~dp0anonymize.py" %*
)
if errorlevel 1 pause
