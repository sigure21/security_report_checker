$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -m venv .venv
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\pip.exe install -r requirements.txt
& .\.venv\Scripts\pyinstaller.exe --noconfirm --clean --windowed --name VulnTracker main.py
Write-Host "Built: $PSScriptRoot\dist\VulnTracker\VulnTracker.exe"
