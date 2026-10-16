Clear-Host
$Host.UI.RawUI.WindowTitle = "SentinelShield | Integration Check"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       SENTINELSHIELD | INTEGRATION CHECK" -ForegroundColor Cyan
Write-Host "          PROTECTION MODULE VERIFICATION" -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan

$checks = @(
    @{ Name = "Rate Limiter"; Pattern = "rate_limiter = RateLimiter" },
    @{ Name = "Activity Monitor"; Pattern = "activity_monitor = ActivityMonitor" },
    @{ Name = "Suspicious Activity Alert"; Pattern = "SUSPICIOUS ACTIVITY" },
    @{ Name = "HTTP 429 Blocking"; Pattern = "response.status_code = 429" }
)

foreach ($check in $checks) {
    $found = Select-String -Path ".\HTTP Request Inspection\app.py" -Pattern $check.Pattern -Quiet
    if ($found) {
        Write-Host ("[+] " + $check.Name.PadRight(26) + ": PRESENT") -ForegroundColor Green
    } else {
        Write-Host ("[-] " + $check.Name.PadRight(26) + ": NOT FOUND") -ForegroundColor Red
    }
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

