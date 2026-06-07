$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"

Write-Host "Starting ShivShakti backend on http://127.0.0.1:8000" -ForegroundColor Cyan
Start-Process `
  -FilePath powershell `
  -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd `"$backend`"; python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
  ) `
  -WindowStyle Normal

Start-Sleep -Seconds 2

Write-Host "Starting ShivShakti frontend on http://127.0.0.1:5173" -ForegroundColor Cyan
Set-Location $frontend
npm run dev
