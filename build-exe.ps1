$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Create the project virtual environment first (see README.md).' }
& $python -m pip install -r (Join-Path $root 'requirements.txt') pyinstaller
if ($LASTEXITCODE -ne 0) { throw 'Could not install executable build dependencies.' }
& $python -m PyInstaller --noconfirm --clean --onefile --windowed --name AYNUO `
    --add-data "frontend;frontend" --collect-all uvicorn --collect-all paramiko `
    --collect-all reportlab --collect-all multipart --collect-all fastapi `
    (Join-Path $root 'aynuo_app.py')
if ($LASTEXITCODE -ne 0) { throw 'AYNUO executable build failed.' }
Write-Host "Built: $(Join-Path $root 'dist\AYNUO.exe')"

