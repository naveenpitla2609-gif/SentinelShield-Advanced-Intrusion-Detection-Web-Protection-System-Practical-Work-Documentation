$Host.UI.RawUI.WindowTitle = "SentinelShield | Security Headers Test"

Clear-Host
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       SENTINELSHIELD | SECURITY HEADERS" -ForegroundColor Cyan
Write-Host "            PROTECTION VERIFICATION" -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan

try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:5000/health" -UseBasicParsing
    $contentType = $r.Headers["X-Content-Type-Options"]
    $frame = $r.Headers["X-Frame-Options"]
    $cache = $r.Headers["Cache-Control"]

    Write-Host "[+] Health Endpoint    : HTTP $([int]$r.StatusCode)" -ForegroundColor Green
    Write-Host "[+] Content-Type Guard : $contentType" -ForegroundColor Green
    Write-Host "[+] Clickjacking Guard : $frame" -ForegroundColor Green
    Write-Host "[+] Cache Protection   : $cache" -ForegroundColor Green

    if ($r.StatusCode -eq 200 -and $contentType -eq "nosniff" -and $frame -eq "DENY" -and $cache -eq "no-store") {
        Write-Host "[+] SECURITY HEADERS TEST: PASS" -ForegroundColor Green
    } else {
        Write-Host "[-] SECURITY HEADERS TEST: CHECK REQUIRED" -ForegroundColor Red
    }
}
catch {
    Write-Host "[-] Server unavailable. Start it using: python app.py" -ForegroundColor Red
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
