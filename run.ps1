$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

function Test-AynuoHealth([int]$Port) {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:$Port/api/health" -TimeoutSec 1
        return $health.product -eq 'AYNUO' -and $health.status -eq 'ready'
    } catch {
        return $false
    }
}

function Test-PortAvailable([int]$Port) {
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    throw 'Python 3.11 or later was not found. Install it from python.org, then run this launcher again.'
}
$pythonExe = $pythonCommand.Source
$version = & $pythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0 -or -not $version) { throw 'Python could not be started.' }
if ([version]$version -lt [version]'3.11') {
    throw "AYNUO requires Python 3.11 or later; found $version."
}

$venv = Join-Path $root '.venv'
$py = Join-Path $venv 'Scripts\python.exe'
$venvValid = (Test-Path -LiteralPath (Join-Path $venv 'pyvenv.cfg')) -and (Test-Path -LiteralPath $py)
if ($venvValid) {
    & $py -c "import sys; assert sys.prefix != sys.base_prefix" 2>$null
    $venvValid = $LASTEXITCODE -eq 0
}
if (-not $venvValid) {
    if (Test-Path -LiteralPath $venv) {
        $resolvedVenv = (Resolve-Path -LiteralPath $venv).Path
        if ($resolvedVenv -ne $venv) { throw "Refusing to remove unexpected environment path: $resolvedVenv" }
        Write-Warning 'The AYNUO virtual environment is incomplete; rebuilding it.'
        Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
    }
    & $pythonExe -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the AYNUO virtual environment.' }
}

Write-Host 'Checking AYNUO dependencies...'
& $py -m pip install --disable-pip-version-check -q -r (Join-Path $root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Review the pip error above.' }

if (Test-AynuoHealth 8765) {
    $url = 'http://127.0.0.1:8765'
    Start-Process $url
    Write-Host "AYNUO is already running at $url."
    return
}

$port = $null
foreach ($candidate in 8765..8775) {
    if (Test-PortAvailable $candidate) { $port = $candidate; break }
}
if (-not $port) { throw 'Ports 8765 through 8775 are occupied. Stop another service and try again.' }
if ($port -ne 8765) { Write-Warning "Port 8765 is occupied; AYNUO will use port $port." }

$dataDir = Join-Path $root 'data'
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
$stdoutLog = Join-Path $dataDir 'server.stdout.log'
$stderrLog = Join-Path $dataDir 'server.stderr.log'
$arguments = @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', [string]$port)
$process = Start-Process -FilePath $py -ArgumentList $arguments -WorkingDirectory $root `
    -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog
$url = "http://127.0.0.1:$port"

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) { break }
        if (Test-AynuoHealth $port) { $ready = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        $details = @()
        if (Test-Path $stderrLog) { $details += Get-Content -LiteralPath $stderrLog -Raw }
        if (Test-Path $stdoutLog) { $details += Get-Content -LiteralPath $stdoutLog -Raw }
        throw "The AYNUO web server did not become ready.`n$($details -join "`n")"
    }
    Start-Process $url
    Write-Host "AYNUO is running at $url. Close this window or press Ctrl+C to stop it."
    while (-not $process.HasExited) { Start-Sleep -Seconds 1 }
    if ($process.ExitCode -ne 0) {
        throw "AYNUO stopped unexpectedly. See $stderrLog"
    }
} finally {
    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
}

