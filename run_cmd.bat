@echo off
rem Veil launcher. Arguments are passed to the Python app or portable EXE.
rem Interactive Russian: run_cmd.bat
rem English UI:         run_cmd.bat --lang en
rem Chinese UI:         run_cmd.bat --lang zh
rem Automatic mode:     run_cmd.bat --auto --lang en
if exist "%~dp0anonymizer.exe" (
  "%~dp0anonymizer.exe" %*
) else if exist "%~dp0.venv\Scripts\python.exe" (
  "%~dp0.venv\Scripts\python.exe" "%~dp0anonymize.py" %*
) else (
  python "%~dp0anonymize.py" %*
)
if errorlevel 1 pause
