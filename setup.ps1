# CAS Cortex - one-step Windows setup. Free and local: no API key, no account.
# Run from the cas-cortex folder:   powershell -ExecutionPolicy Bypass -File .\setup.ps1
# (or just double-click setup.bat)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User")
}

# 1. Python ------------------------------------------------------------------
Step "Checking Python"
$py = $null
foreach ($c in @("py", "python")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) {
        $v = & $c -c "import sys; print(sys.version_info >= (3, 10))" 2>$null
        if ($v -eq "True") { $py = $c; break }
    }
}
if (-not $py) {
    Write-Host "Python 3.10+ not found - installing Python 3.12 with winget..."
    winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements
    Refresh-Path
    $py = "py"
}
& $py --version

# 2. Virtual environment -----------------------------------------------------
Step "Creating virtual environment (.venv)"
if (-not (Test-Path ".venv\Scripts\python.exe")) { & $py -m venv .venv }
$vpy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $vpy -m pip install --quiet --upgrade pip
& $vpy -m pip install --quiet -r requirements.txt

# 3. Ollama (free local model runner) ----------------------------------------
Step "Checking Ollama"
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Ollama with winget (about 1.5 GB)..."
    winget install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements
    Refresh-Path
}
$up = $false
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-RestMethod "http://localhost:11434/api/tags" -TimeoutSec 2 | Out-Null; $up = $true; break }
    catch {
        if ($i -eq 0) {
            Write-Host "Starting Ollama..."
            $exe = (Get-Command ollama -ErrorAction SilentlyContinue).Source
            if ($exe) { Start-Process -FilePath $exe -ArgumentList "serve" -WindowStyle Hidden }
        }
        Start-Sleep -Seconds 2
    }
}
if (-not $up) {
    Write-Host "Ollama didn't start. Open 'Ollama' from the Start menu, then re-run this script." -ForegroundColor Yellow
    exit 1
}

# 4. Pick a model that suits this PC and download it ---------------------------
Step "Choosing and downloading a local model for this PC (one-off download)"
& $vpy -m cortex doctor --pull
if ($LASTEXITCODE -ne 0) { exit 1 }

# 5. Self-test ---------------------------------------------------------------
Step "Running self-tests"
& $vpy -m pytest -q

# 6. Desktop shortcut ----------------------------------------------------------
Step "Creating desktop and Start menu shortcuts"
& (Join-Path $PSScriptRoot "create_shortcut.ps1")

Step "Done"
Write-Host @"
Open CAS Cortex from the new 'CAS Cortex' icon on your desktop
(or double-click 'Start CAS Cortex.bat' in this folder).

Command-line use is still available from this folder, for example:
  .\cortex status
  .\cortex eval --split holdout     # baseline before learning
  .\cortex train --rounds 3
  .\cortex eval
  .\cortex report
  .\cortex watch examples\sample_auth.log
"@ -ForegroundColor Green

$open = Read-Host "Open CAS Cortex now? (Y/n)"
if ($open -ne "n") { Start-Process -FilePath (Join-Path $PSScriptRoot ".venv\Scripts\pythonw.exe") -ArgumentList "`"$(Join-Path $PSScriptRoot 'launch_gui.pyw')`"" -WorkingDirectory $PSScriptRoot }
