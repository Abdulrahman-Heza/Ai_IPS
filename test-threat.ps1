# ============================================================
# IPS Threat Test Script
# Run with: .\test-threat.ps1
# ============================================================

$BASE = "http://localhost:3000"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  IPS Threat Detection Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ── STEP 1: Login ────────────────────────────────────────────
Write-Host "`n[1/3] Logging in..." -ForegroundColor Yellow

$loginBody = '{"email":"admin@gmail.com","password":"Admin123!"}'

try {
    $loginRes = Invoke-RestMethod `
        -Uri "$BASE/api/v1/auth/login" `
        -Method POST `
        -ContentType "application/json" `
        -Body $loginBody

    $token = $loginRes.data.token
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    Write-Host "    Login successful! Role: $($loginRes.data.user.role)" -ForegroundColor Green

} catch {
    Write-Host "    Login FAILED: $_" -ForegroundColor Red
    exit 1
}

# ── STEP 2: Send DDoS Threat ─────────────────────────────────
Write-Host "`n[2/3] Sending DDoS threat (risk: CRITICAL)..." -ForegroundColor Yellow

$features = @(80,1000,50000,0,7500000,0,1500,1500,1500,0,0,0,0,0,9999999,50000,
              20,5,100,0,1000,20,5,100,0,0,0,0,0,0,20000,0,50000,0,1500,1500,
              1500,0,0,0,45000,0,0,5000,0,0,1500,65535,0,0)

$threatBody = @{
    flow_id          = "ddos-$(Get-Random)"
    source_ip        = "192.168.1.100"
    destination_ip   = "10.0.0.1"
    source_port      = 45678
    destination_port = 80
    protocol         = "TCP"
    duration         = 0.001
    forward_packets  = 50000
    forward_bytes    = 7500000
    features         = $features
} | ConvertTo-Json

try {
    $threatRes = Invoke-RestMethod `
        -Uri "$BASE/api/v1/threats/process" `
        -Method POST `
        -Headers $headers `
        -Body $threatBody

    $d = $threatRes.data
    Write-Host "    Attack Type : $($d.attack_type)" -ForegroundColor Red
    Write-Host "    Risk Score  : $($d.risk_score)/100" -ForegroundColor Red
    Write-Host "    Risk Level  : $($d.risk_level.ToUpper())" -ForegroundColor Red
    Write-Host "    Actions     : $($d.auto_response -join ', ')" -ForegroundColor Magenta

} catch {
    Write-Host "    Threat send FAILED: $_" -ForegroundColor Red
}

# ── STEP 3: Send Port Scan Threat ────────────────────────────
Write-Host "`n[3/3] Sending Port Scan threat..." -ForegroundColor Yellow

$features2 = @(0,100000,1000,0,20000,0,20,20,20,0,0,0,0,0,200000,10000,
               100,50,500,0,100,100,50,500,0,0,0,0,0,0,2000,0,10000,0,
               20,20,20,0,0,0,1000,500,0,100,0,0,20,1024,0,0)

$threatBody2 = @{
    flow_id          = "scan-$(Get-Random)"
    source_ip        = "10.10.10.50"
    destination_ip   = "10.0.0.5"
    source_port      = 12345
    destination_port = 22
    protocol         = "TCP"
    duration         = 100
    forward_packets  = 1000
    forward_bytes    = 20000
    features         = $features2
} | ConvertTo-Json

try {
    $scanRes = Invoke-RestMethod `
        -Uri "$BASE/api/v1/threats/process" `
        -Method POST `
        -Headers $headers `
        -Body $threatBody2

    $d2 = $scanRes.data
    Write-Host "    Attack Type : $($d2.attack_type)" -ForegroundColor DarkYellow
    Write-Host "    Risk Score  : $($d2.risk_score)/100" -ForegroundColor DarkYellow
    Write-Host "    Risk Level  : $($d2.risk_level.ToUpper())" -ForegroundColor DarkYellow

} catch {
    Write-Host "    Port scan send FAILED: $_" -ForegroundColor Red
}

# ── Done ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Done! Check your browser:" -ForegroundColor Cyan
Write-Host "  http://localhost:3000" -ForegroundColor White
Write-Host "  -> You should see sound + popup + redirect" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
