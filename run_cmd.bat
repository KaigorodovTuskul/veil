@echo off
if exist "%~dp0anonymizer.exe" (
  "%~dp0anonymizer.exe" %*
) else if exist "%~dp0dist\anonymizer\anonymizer.exe" (
  "%~dp0dist\anonymizer\anonymizer.exe" %*
) else (
  python "%~dp0anonymize.py" %*
)
if errorlevel 1 pause
