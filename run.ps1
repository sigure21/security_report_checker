$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$venvPath = Join-Path $PSScriptRoot ".venv"
$pythonPath = Join-Path $venvPath "Scripts\python.exe"
$requirementsPath = Join-Path $PSScriptRoot "requirements.txt"
$installMarker = Join-Path $venvPath ".requirements.sha256"

if (-not (Test-Path -LiteralPath $pythonPath)) {
    py -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { throw "Python environment creation failed" }
}

$requirementsHash = (Get-FileHash -LiteralPath $requirementsPath -Algorithm SHA256).Hash
$installedHash = if (Test-Path -LiteralPath $installMarker) {
    (Get-Content -LiteralPath $installMarker -Raw).Trim()
} else { "" }

if ($installedHash -eq $requirementsHash) {
    & $pythonPath -c "import PySide6.QtWidgets, requests, keyring, openpyxl"
}
if ($installedHash -ne $requirementsHash -or $LASTEXITCODE -ne 0) {
    & $pythonPath -m pip install -r $requirementsPath
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed" }
    Set-Content -LiteralPath $installMarker -Value $requirementsHash -NoNewline
}

& $pythonPath main.py
