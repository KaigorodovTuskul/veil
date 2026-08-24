@echo off
setlocal
rem Veil launcher. Arguments are passed to the Python app or portable EXE.
rem With no arguments, show a mode/language menu.
if not "%~1"=="" goto run

echo Veil - choose processing mode
echo [1] Interactive - Russian
echo [2] Automatic   - Russian
echo [3] Interactive - English
echo [4] Automatic   - English
echo [5] Interactive - Chinese
echo [6] Automatic   - Chinese
choice /c 123456 /n /m "Select mode: "
if errorlevel 6 (
  set "VEIL_ARGS=--auto --lang zh"
) else if errorlevel 5 (
  set "VEIL_ARGS=--lang zh"
) else if errorlevel 4 (
  set "VEIL_ARGS=--auto --lang en"
) else if errorlevel 3 (
  set "VEIL_ARGS=--lang en"
) else if errorlevel 2 (
  set "VEIL_ARGS=--auto --lang ru"
) else (
  set "VEIL_ARGS=--lang ru"
)
call :run %VEIL_ARGS%
exit /b %ERRORLEVEL%

:run
if exist "%~dp0anonymizer.exe" (
  "%~dp0anonymizer.exe" %*
) else if exist "%~dp0.venv\Scripts\python.exe" (
  "%~dp0.venv\Scripts\python.exe" "%~dp0anonymize.py" %*
) else (
  python "%~dp0anonymize.py" %*
)
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" pause
exit /b %RC%
