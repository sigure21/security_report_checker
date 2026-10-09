$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -m venv .venv
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
& .\.venv\Scripts\pip.exe install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }

# Keep unrelated tools' ICU/CRT DLLs out of the application bundle.
$buildOriginalPath = $env:PATH
$buildPythonRoot = & .\.venv\Scripts\python.exe -c "import sys; print(sys.base_prefix)"
if ($LASTEXITCODE -ne 0) { throw "Python runtime detection failed" }
$buildSystemDirectory = [Environment]::SystemDirectory
$buildWindowsDirectory = Split-Path -Parent $buildSystemDirectory
try {
    $env:PATH = @(
        (Join-Path $PSScriptRoot '.venv\Scripts'),
        $buildPythonRoot,
        $buildSystemDirectory,
        $buildWindowsDirectory
    ) -join [IO.Path]::PathSeparator
    & .\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --windowed --name VulnTracker main.py
    if ($LASTEXITCODE -ne 0) { throw "EXE build failed" }
} finally {
    $env:PATH = $buildOriginalPath
}
Write-Host "Built: $PSScriptRoot\dist\VulnTracker\VulnTracker.exe"
