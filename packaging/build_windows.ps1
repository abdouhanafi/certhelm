# Builds the desktop app, the agent and the agent installer into ./dist
# Usage (from the repository root):  powershell -File packaging/build_windows.ps1 [-Python path\to\python.exe]
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$work = Join-Path $root "build"

function Run($label, [scriptblock]$cmd) {
    Write-Host "== $label"
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$label failed (exit $LASTEXITCODE)" }
}

Run "CertHelm (desktop app)" { & $Python -m PyInstaller --noconfirm --distpath $dist --workpath "$work\app" "$PSScriptRoot\certhelm.spec" }
Run "CertHelmAgent" { & $Python -m PyInstaller --noconfirm --onefile --name CertHelmAgent --hidden-import pystray._win32 --distpath "$dist\agent" --workpath "$work\agent" --specpath $work "$root\agent\certhelm_agent.py" }
Run "CertHelmAgent_Setup (asks for administrator rights)" { & $Python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name CertHelmAgent_Setup --distpath "$dist\agent" --workpath "$work\setup" --specpath $work "$root\agent\installer_windows.py" }
Write-Host "Done. Output in $dist"
