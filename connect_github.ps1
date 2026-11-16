# CAS Cortex - one-off: connect this folder to your GitHub repo so the PC can
# publish progress to the iPhone app. Safe to run again.
# Run: double-click connect_github.bat
param([string]$Repo = "cas-cortex-")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Refresh-Path { $env:Path = [Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [Environment]::GetEnvironmentVariable("Path","User") }

Step "Checking Git and the GitHub CLI"
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    winget install --id Git.Git -e --accept-package-agreements --accept-source-agreements; Refresh-Path }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    winget install --id GitHub.cli -e --accept-package-agreements --accept-source-agreements; Refresh-Path }

Step "Signing in to GitHub (a browser window opens the first time)"
gh auth status 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { gh auth login --hostname github.com --git-protocol https --web }
gh auth setup-git
$owner = (gh api user --jq .login).Trim()
$url = "https://github.com/$owner/$Repo.git"
Write-Host "Signed in as $owner - repository $url"

Step "Linking this folder to GitHub"
if (-not (Test-Path ".git")) {
    git init -b main | Out-Null
    git remote add origin $url
} else {
    git remote set-url origin $url 2>$null; if ($LASTEXITCODE -ne 0) { git remote add origin $url }
}
git fetch origin main
if ($LASTEXITCODE -ne 0) { Write-Host "Couldn't read $url - check the repository exists." -ForegroundColor Red; exit 1 }
git reset --mixed origin/main | Out-Null      # adopt GitHub's history, keep your files as they are
git branch --set-upstream-to=origin/main main | Out-Null

Step "Turning on the iPhone web app (GitHub Pages)"
gh api "repos/$owner/$Repo/pages" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    gh api -X POST "repos/$owner/$Repo/pages" -f "source[branch]=main" -f "source[path]=/docs" | Out-Null
}

Step "Publishing your current progress"
& ".venv\Scripts\python.exe" -m cortex --home "$PSScriptRoot\cortex_data" publish

Write-Host "`nDone. On your iPhone open https://$($owner.ToLower()).github.io/$Repo/ in Safari," -ForegroundColor Green
Write-Host "then Share > Add to Home Screen. From now on use 'Publish to iPhone' on the Progress tab." -ForegroundColor Green
