$ErrorActionPreference = "Stop"

Write-Host "ShivShakti demo sequence" -ForegroundColor Cyan

$attacks = @("prompt_injection", "credential_leak", "unsafe_tool", "browser_attack")
foreach ($attack in $attacks) {
  Write-Host "Simulating $attack" -ForegroundColor Yellow
  Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/api/demo/simulate" `
    -Method Post `
    -ContentType "application/json" `
    -Body (@{ attack_type = $attack } | ConvertTo-Json)
}

Write-Host "Recent security events:" -ForegroundColor Green
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/events?limit=5" | Format-Table title,severity,decision,rule,confidence

