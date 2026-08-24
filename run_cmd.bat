@echo off
if exist "%~dp0anonymizer.exe" (
  "%~dp0anonymizer.exe" %*
) else (
  python "%~dp0anonymize.py" %*
)
if errorlevel 1 pause
