
$ErrorActionPreference = "Stop"

Clear-Host

$body = '{"path":"../../etc/passwd","query":{},"headers":{},"body":""}'

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "       SENTINELSHIELD SECURITY TEST" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

try {
    $response = Invoke-WebRequest `
        -Uri "http://127.0.0.1:5000/inspect" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -UseBasicParsing `
        -ErrorAction Stop

    $result = $response.Content | ConvertFrom-Json
}
catch {
    $message = $_.ErrorDetails.Message

    if ($message) {
        try {
            $result = $message | ConvertFrom-Json
        }
        catch {
            $result = $null
        }
    }
}

Write-Host ""

if ($result -and $result.is_malicious -and $result.status -eq "blocked") {
    Write-Host "  TEST RESULT : PASS" -ForegroundColor Green
    Write-Host "  ATTACK TYPE : Path Traversal" -ForegroundColor Yellow
    Write-Host "  SEVERITY    : HIGH" -ForegroundColor Red
    Write-Host "  ACTION      : BLOCKED" -ForegroundColor Green
}
else {
    Write-Host "  TEST RESULT : UNCONFIRMED" -ForegroundColor Yellow
    Write-Host "  Please check that the server is running." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "             TEST COMPLETED" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Read-Host "Press Enter to close"
