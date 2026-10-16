
$ErrorActionPreference = "Stop"
$BaseUrl = "http://127.0.0.1:5000/inspect"

function Write-Title {
    param([string]$Text)

    Write-Host ""
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "  $("-" * 52)" -ForegroundColor DarkGray
}

function Write-Component {
    param(
        [string]$Title,
        [object]$Component
    )

    if ($null -eq $Component) {
        return
    }

    Write-Title $Title

    $value = [string]$Component.value
    $status = [string]$Component.status
    $detections = @($Component.detections)

    if ([string]::IsNullOrWhiteSpace($value)) {
        $value = "(No input provided)"
    }

    Write-Host "  Value   : $value" -ForegroundColor White

    switch ($status) {
        "SUSPICIOUS" {
            Write-Host "  Status  : SUSPICIOUS" -ForegroundColor Red
        }
        "EMPTY" {
            Write-Host "  Status  : EMPTY" -ForegroundColor Yellow
        }
        default {
            Write-Host "  Status  : CLEAN" -ForegroundColor Green
        }
    }

    if ($detections.Count -gt 0) {
        foreach ($finding in $detections) {
            Write-Host "  Attack  : $($finding.name)" -ForegroundColor Red
            Write-Host "  Category: $($finding.category)" -ForegroundColor Yellow
            Write-Host "  Severity: $($finding.severity)" -ForegroundColor Red
            Write-Host "  Evidence: $($finding.evidence)" -ForegroundColor White
        }
    }
    elseif ($status -eq "CLEAN") {
        Write-Host "  Result  : No configured attack signature detected" -ForegroundColor Green
    }
}

try {
    $response = Invoke-RestMethod -Uri $BaseUrl -Method Get

    Write-Host ""
    Write-Host "  SENTINELSHIELD" -ForegroundColor Cyan
    Write-Host "  HTTP REQUEST INSPECTION REPORT" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor DarkGray

    $overallColor = "Green"
    if ($response.status -eq "blocked") {
        $overallColor = "Red"
    }

    Write-Host "  Overall Status : $($response.status.ToUpper())" -ForegroundColor $overallColor
    Write-Host "  HTTP Method    : $($response.method)" -ForegroundColor White
    Write-Host "  URL Path       : $($response.path)" -ForegroundColor White
    Write-Host "  Malicious      : $($response.is_malicious)" -ForegroundColor $overallColor

    $components = $response.component_results

    Write-Component "01. URL PATH ANALYSIS" $components.'URL PATH'
    Write-Component "02. HTTP METHOD ANALYSIS" $components.'HTTP METHOD'
    Write-Component "03. QUERY PARAMETER ANALYSIS" $components.'QUERY PARAMETERS'
    Write-Component "04. HTTP HEADER ANALYSIS" $components.'HEADERS'
    Write-Component "05. FORM DATA ANALYSIS" $components.'FORM DATA'
    Write-Component "06. REQUEST BODY ANALYSIS" $components.'REQUEST BODY'

    Write-Host ""
    Write-Host "  Inspection completed." -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "  INSPECTION FAILED" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Check that the Flask server is running at $BaseUrl" -ForegroundColor Yellow
}
