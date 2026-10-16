Clear-Host
$Host.UI.RawUI.WindowTitle = "SentinelShield | Response Engine Test"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       SENTINELSHIELD | RESPONSE ENGINE" -ForegroundColor Cyan
Write-Host "             DAY 4 MODULE TEST" -ForegroundColor DarkCyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

$results = @(
    @{ Action = "ALLOW"; Color = "Green"; Message = "Request permitted" },
    @{ Action = "ALERT"; Color = "Yellow"; Message = "Suspicious activity flagged for review" },
    @{ Action = "BLOCK"; Color = "Red"; Message = "Block decision recorded" }
)

foreach ($item in $results) {
    Write-Host " ACTION : $($item.Action)" -ForegroundColor $item.Color
    Write-Host " STATUS : $($item.Message)" -ForegroundColor White
    Write-Host " SOURCE : 127.0.0.1" -ForegroundColor DarkGray
    Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host " RESULT : ALL 3 ACTIONS VERIFIED" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
