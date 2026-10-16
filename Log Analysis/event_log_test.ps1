$Host.UI.RawUI.WindowTitle = "SentinelShield | Event Log Verification"
Clear-Host

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       SENTINELSHIELD | EVENT LOGGING" -ForegroundColor Cyan
Write-Host "             SECURITY LOG VERIFICATION" -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan

$LogFile = ".\logs\security_events.jsonl"

if (Test-Path $LogFile) {
    $events = Get-Content $LogFile
    Write-Host "[+] Log File           : FOUND" -ForegroundColor Green
    Write-Host "[+] Total Events       : $($events.Count)" -ForegroundColor Green

    if ($events.Count -gt 0) {
        Write-Host "[+] Latest Event:" -ForegroundColor Yellow
        $events[-1] | Write-Host -ForegroundColor White
        Write-Host "[+] EVENT LOG TEST     : PASS" -ForegroundColor Green
    } else {
        Write-Host "[!] Log file is empty; send a request to /inspect first." -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] Log file not found: $LogFile" -ForegroundColor Red
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
