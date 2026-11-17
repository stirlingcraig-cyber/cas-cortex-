# CAS Cortex - turn the nightly autopilot on or off (Windows Task Scheduler).
#   On:  powershell -ExecutionPolicy Bypass -File .\install_autopilot.ps1
#   Off: powershell -ExecutionPolicy Bypass -File .\install_autopilot.ps1 -Remove
# Runs every night at the chosen time as you (no admin rights), and catches up after the PC
# was off or asleep. Ollama must be running (it starts with Windows by default).
param([switch]$Remove, [string]$At = "02:30")
$ErrorActionPreference = "Stop"
$name = "CAS Cortex Autopilot"
if ($Remove) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Nightly autopilot turned off." -ForegroundColor Green
    exit 0
}
$root = $PSScriptRoot
$pyw = Join-Path $root ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $pyw)) { Write-Host "Run setup.bat first." -ForegroundColor Yellow; exit 1 }
$action = New-ScheduledTaskAction -Execute $pyw -Argument "-m cortex --home `"$root\cortex_data`" autopilot" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings `
    -Description "CAS Cortex continuous learning: imports iPhone feedback, learns approved Claude-history skills, trains your focus areas, evaluates weekly, publishes to iPhone." -Force | Out-Null
Write-Host "Nightly autopilot is ON ($At). Log: $root\cortex_data\autopilot.log" -ForegroundColor Green
