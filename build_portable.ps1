$ErrorActionPreference = "Stop"
$python = if (Test-Path .venv\Scripts\python.exe) { (Resolve-Path .venv\Scripts\python.exe).Path } else { "python" }

& $python -m PyInstaller `
  --noconfirm `
  --clean `
  --onedir `
  --name anonymizer `
  --add-data "patterns.json;." `
  anonymize.py

Copy-Item patterns.json dist\anonymizer\patterns.json -Force
Copy-Item run_cmd.bat dist\anonymizer\run_cmd.bat -Force
Write-Host "Portable build: dist\anonymizer\anonymizer.exe"
