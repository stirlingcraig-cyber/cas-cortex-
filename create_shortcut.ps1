# Creates "CAS Cortex" shortcuts on the Desktop and in the Start menu.
# Run:  powershell -ExecutionPolicy Bypass -File .\create_shortcut.ps1
$ErrorActionPreference = "Stop"
$root    = $PSScriptRoot
$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
$script  = Join-Path $root "launch_gui.pyw"
$icon    = Join-Path $root "assets\cortex.ico"
if (-not (Test-Path $pythonw)) { Write-Host "Run setup.bat first (no .venv found)." -ForegroundColor Yellow; exit 1 }

$shell = New-Object -ComObject WScript.Shell
$places = @(
    [Environment]::GetFolderPath("Desktop"),
    (Join-Path ([Environment]::GetFolderPath("Programs")) "CAS Solutions")
)
foreach ($dir in $places) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $lnk = $shell.CreateShortcut((Join-Path $dir "CAS Cortex.lnk"))
    $lnk.TargetPath       = $pythonw
    $lnk.Arguments        = "`"$script`""
    $lnk.WorkingDirectory = $root
    $lnk.IconLocation     = "$icon,0"
    $lnk.Description      = "CAS Cortex - self-learning engineering agent"
    $lnk.Save()
    Write-Host "Shortcut created: $dir\CAS Cortex.lnk"
}
