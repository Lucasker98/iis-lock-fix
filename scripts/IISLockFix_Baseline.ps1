param(
    [string]$SitePath      = "C:\dev\iis-lock-fix\site",
    [string]$UrlHttp       = "http://iislock.localtest.me",
    [string]$PolicyPath    = "C:\dev\iis-lock-fix\policy.json",
    [string]$ReportsFolder = "C:\dev\iis-lock-fix\reports"
)

# ------------ Load policy JSON ------------
function Get-Policy {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Policy file not found: $Path"
    }

    $json = Get-Content $Path -Raw | ConvertFrom-Json
    return $json
}

# ------------ HTTP headers scan (baseline) ------------
function Get-HttpHeadersReport {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$Phase  # "before" / "after"
    )

    Write-Host "[*] Running HTTP scan ($Phase) on $Url"

    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
    } catch {
        $msg = "Error: could not reach $Url : $($_.Exception.Message)"
        Write-Host $msg
        $msg | Set-Content $OutputPath

        $summary = @(
            [PSCustomObject]@{
                Phase    = $Phase
                Category = 'HTTP'
                Check    = 'Reachability'
                Status   = 'Error'
                IsIssue  = 1
            }
        )
        $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, ".summary.csv")
        $summary | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        return
    }

    $headers = $resp.Headers

    # ----- Text report -----
    "=== IIS Lock & Fix - HTTP headers report ($Phase) ===" | Set-Content $OutputPath
    "Target: $Url" | Add-Content $OutputPath
    "Date:   $(Get-Date)" | Add-Content $OutputPath
    "" | Add-Content $OutputPath

    Add-Content $OutputPath "Received headers:"
    foreach ($key in $headers.Keys) {
        Add-Content $OutputPath ("  {0}: {1}" -f $key, $headers[$key])
    }
    Add-Content $OutputPath ""
    Add-Content $OutputPath "Basic security checks:"
    Add-Content $OutputPath "----------------------"

    # ----- Structured summary for CSV -----
    $summary = @()

    # HSTS
    $hasHsts = [bool]$headers["Strict-Transport-Security"]
    if ($hasHsts) {
        Add-Content $OutputPath "[OK] HSTS present: $($headers["Strict-Transport-Security"])"
    } else {
        Add-Content $OutputPath "[X] Missing HSTS (Strict-Transport-Security)"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'HSTS'
        Status   = $(if ($hasHsts) { 'OK' } else { 'Missing' })
        IsIssue  = $(if ($hasHsts) { 0 } else { 1 })
    }

    # Clickjacking: X-Frame-Options or CSP frame-ancestors
    $hasXfo = [bool]$headers["X-Frame-Options"]
    $hasFrameAncestors = $false
    if ($headers["Content-Security-Policy"]) {
        if ($headers["Content-Security-Policy"] -match "frame-ancestors") {
            $hasFrameAncestors = $true
        }
    }
    $clickjackOk = $hasXfo -or $hasFrameAncestors

    if ($clickjackOk) {
        Add-Content $OutputPath "[OK] Clickjacking protection present (X-Frame-Options and/or CSP frame-ancestors)"
    } else {
        Add-Content $OutputPath "[X] No Clickjacking protection (no X-Frame-Options and no CSP frame-ancestors)"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'Clickjacking'
        Status   = $(if ($clickjackOk) { 'OK' } else { 'Missing' })
        IsIssue  = $(if ($clickjackOk) { 0 } else { 1 })
    }

    # X-Content-Type-Options
    $hasXcto = $headers["X-Content-Type-Options"] -and $headers["X-Content-Type-Options"] -match "nosniff"
    if ($hasXcto) {
        Add-Content $OutputPath "[OK] X-Content-Type-Options: nosniff present"
    } else {
        Add-Content $OutputPath "[X] Missing X-Content-Type-Options: nosniff"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'X-Content-Type-Options'
        Status   = $(if ($hasXcto) { 'OK' } else { 'Missing' })
        IsIssue  = $(if ($hasXcto) { 0 } else { 1 })
    }

    # Referrer-Policy
    $hasRefPol = [bool]$headers["Referrer-Policy"]
    if ($hasRefPol) {
        Add-Content $OutputPath "[OK] Referrer-Policy present: $($headers["Referrer-Policy"])"
    } else {
        Add-Content $OutputPath "[X] Missing Referrer-Policy header"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'Referrer-Policy'
        Status   = $(if ($hasRefPol) { 'OK' } else { 'Missing' })
        IsIssue  = $(if ($hasRefPol) { 0 } else { 1 })
    }

    # Content-Security-Policy (overall presence)
    $hasCsp = [bool]$headers["Content-Security-Policy"]
    if ($hasCsp) {
        Add-Content $OutputPath "[OK] Content-Security-Policy present"
    } else {
        Add-Content $OutputPath "[X] Missing Content-Security-Policy header"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'Content-Security-Policy'
        Status   = $(if ($hasCsp) { 'OK' } else { 'Missing' })
        IsIssue  = $(if ($hasCsp) { 0 } else { 1 })
    }

    # Fingerprinting: Server header
    $server = $headers["Server"]
    if ($server) {
        Add-Content $OutputPath "[!] Server header present: $server"
        Add-Content $OutputPath "    Recommendation: hide or generalize this value."
    } else {
        Add-Content $OutputPath "[OK] No Server header"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'Server header'
        Status   = $(if ($server) { 'Present' } else { 'Not present' })
        IsIssue  = $(if ($server) { 1 } else { 0 })
    }

    # Fingerprinting: X-Powered-By
    $xPoweredBy = $headers["X-Powered-By"]
    if ($xPoweredBy) {
        Add-Content $OutputPath "[!] X-Powered-By header present: $xPoweredBy"
        Add-Content $OutputPath "    Recommendation: remove it to reduce fingerprinting."
    } else {
        Add-Content $OutputPath "[OK] No X-Powered-By header"
    }
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'X-Powered-By'
        Status   = $(if ($xPoweredBy) { 'Present' } else { 'Not present' })
        IsIssue  = $(if ($xPoweredBy) { 1 } else { 0 })
    }

    Add-Content $OutputPath ""
    Add-Content $OutputPath "=== End of report ($Phase) ==="

    # total issues for charts
    $issueCount = ($summary | Where-Object { $_.IsIssue -eq 1 }).Count
    $summary += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'HTTP'
        Check    = 'TotalIssues'
        Status   = "$issueCount"
        IsIssue  = $issueCount
    }

    $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, ".summary.csv")
    $summary | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
}
# ------------ TLS scan (baseline only) ------------
function Run-TlsScan {
    param(
        [string]$TargetHost,
        [int]$Port,
        [string]$OutputPathPrefix,
        [string]$Phase
    )

    Write-Host "[*] Running TLS scan ($Phase) on $TargetHost`:$Port"

    $nmapOut   = "${OutputPathPrefix}nmap${Phase}.txt"
    $sslyzeOut = "${OutputPathPrefix}sslyze${Phase}.txt"

    # ----- Nmap -----
    try {
        $nmapCmdExists = Get-Command nmap -ErrorAction SilentlyContinue
        if ($null -eq $nmapCmdExists) {
            "Nmap not found on PATH. Please install Nmap or add it to PATH." | Set-Content $nmapOut
        } else {
            $cmd = "nmap -p $Port --script ssl-enum-ciphers $TargetHost"
            Write-Host "   Nmap: $cmd"
            cmd /c $cmd > $nmapOut 2>&1
        }
    } catch {
        "Nmap scan failed: $($_.Exception.Message)" | Set-Content $nmapOut
    }

    # ----- SSLyze -----
    try {
        $cmd2 = "python -m sslyze $TargetHost`:$Port"
        Write-Host "   SSLyze: $cmd2"
        cmd /c $cmd2 2>&1 | Out-File -FilePath $sslyzeOut -Encoding UTF8
    } catch {
        "SSLyze scan failed or not installed correctly: $($_.Exception.Message)" | Set-Content $sslyzeOut
    }
}

function Summarize-TlsProtocolsFromNmap {
    param(
        [string]$NmapOutputPath,
        [string]$SummaryCsvPath,
        [string]$Phase
    )

    $protocols = @{
        'SSL 2.0' = $false
        'SSL 3.0' = $false
        'TLS 1.0' = $false
        'TLS 1.1' = $false
        'TLS 1.2' = $false
        'TLS 1.3' = $false
    }

    if (-not (Test-Path $NmapOutputPath)) {
        $rows = @(
            [PSCustomObject]@{
                Phase    = $Phase
                Category = 'TLS'
                Check    = 'Scan'
                Status   = 'No data (Nmap output missing)'
                IsIssue  = 1
            }
        )
        $rows | Export-Csv -Path $SummaryCsvPath -NoTypeInformation -Encoding UTF8
        return
    }

    $content = Get-Content $NmapOutputPath

    foreach ($line in $content) {
        if ($line -match 'SSLv2')    { $protocols['SSL 2.0'] = $true }
        if ($line -match 'SSLv3')    { $protocols['SSL 3.0'] = $true }
        if ($line -match 'TLSv1\.0') { $protocols['TLS 1.0'] = $true }
        if ($line -match 'TLSv1\.1') { $protocols['TLS 1.1'] = $true }
        if ($line -match 'TLSv1\.2') { $protocols['TLS 1.2'] = $true }
        if ($line -match 'TLSv1\.3') { $protocols['TLS 1.3'] = $true }
    }

    $rows = @()

    foreach ($name in $protocols.Keys) {
        $supported = $protocols[$name]
        $status = if ($supported) { 'Supported' } else { 'Not supported' }

        # weak = SSL2, SSL3, TLS1.0, TLS1.1
        $isIssue =
            if ($name -in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') -and $supported) { 1 }
            else { 0 }

        # modern = TLS1.2 / TLS1.3 – אם חסרים, נסמן את זה בהמשך, לא כאן

        $rows += [PSCustomObject]@{
            Phase    = $Phase
            Category = 'TLS'
            Check    = $name
            Status   = $status
            IsIssue  = $isIssue
        }
    }

    $anyTls    = $protocols.Values -contains $true
    $weak      = ($protocols['SSL 2.0'] -or $protocols['SSL 3.0'] -or
                  $protocols['TLS 1.0'] -or $protocols['TLS 1.1'])
    $modernOk  = ($protocols['TLS 1.2'] -or $protocols['TLS 1.3'])

    # שורה שמסבירה אם בכלל יש TLS
    $rows += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'TLS'
        Check    = 'AnyTlsSupported'
        Status   = $(if ($anyTls) { 'YES' } else { 'NO' })
        IsIssue  = $(if ($anyTls) { 0 } else { 1 })   # אין TLS בכלל = Issue
    }

    # שורה שמסבירה אם יש פרוטוקולים חלשים
    $rows += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'TLS'
        Check    = 'WeakProtocolsEnabled'
        Status   = $(if ($weak) { 'YES' } else { 'NO' })
        IsIssue  = $(if ($weak) { 1 } else { 0 })
    }

    # שורה שמסבירה אם יש TLS מודרני (1.2/1.3)
    $rows += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'TLS'
        Check    = 'ModernTlsPresent'
        Status   = $(if ($modernOk) { 'YES' } else { 'NO' })
        IsIssue  = $(if ($modernOk) { 0 } else { 1 })  # אין 1.2/1.3 = Issue
    }

    # כאן אנחנו עושים מה שביקשת:
    # אם TLS לא תקין (אין TLS / יש חלשים / אין מודרני) -> TotalIssues = 1
    # אם הכול טוב (רק 1.2/1.3, בלי ישנים) -> TotalIssues = 0
    $anyIssues = ($rows | Where-Object { $_.IsIssue -eq 1 }).Count
    $overallIssue = if ($anyIssues -gt 0) { 1 } else { 0 }

    $rows += [PSCustomObject]@{
        Phase    = $Phase
        Category = 'TLS'
        Check    = 'TotalIssues'
        Status   = "$overallIssue"
        IsIssue  = $overallIssue
    }

    $rows | Export-Csv -Path $SummaryCsvPath -NoTypeInformation -Encoding UTF8
}



function New-BaselineChartHtml {
    param(
        [string]$HttpCsvPath,
        [string]$TlsCsvPath,
        [string]$OutputHtmlPath
    )

    $httpIssues = 0
    if (Test-Path $HttpCsvPath) {
        $httpData = Import-Csv $HttpCsvPath | Where-Object { $_.Check -eq 'TotalIssues' }
        if ($httpData) {
            [int]$httpIssues = [int]$httpData.Status
        }
    }

    $tlsIssues = 0
    if (Test-Path $TlsCsvPath) {
        $tlsData = Import-Csv $TlsCsvPath | Where-Object { $_.Check -eq 'TotalIssues' }
        if ($tlsData) {
            [int]$tlsIssues = [int]$tlsData.Status
        }
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8' />
  <title>IIS Lock & Fix - Baseline chart</title>
  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
</head>
<body style='font-family: Arial, sans-serif; margin: 40px;'>
  <h2>IIS Lock & Fix - Baseline issues (before hardening)</h2>
  <p>This chart shows the number of findings before applying any hardening.</p>
  <canvas id='baselineChart' width='700' height='400'></canvas>
  <script>
    const ctx = document.getElementById('baselineChart').getContext('2d');
    const chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['HTTP issues (before)', 'TLS issues (before)'],
        datasets: [{
          label: 'Number of issues',
          data: [$httpIssues, $tlsIssues]
        }]
      },
      options: {
        responsive: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0,
              stepSize: 1
            }
          }
        }
      }
    });
  </script>
</body>
</html>
"@

    $html | Set-Content -Path $OutputHtmlPath -Encoding UTF8
    Write-Host "[*] Baseline chart generated at $OutputHtmlPath"
}


# ------------ MAIN: Baseline only ------------
if (-not (Test-Path $ReportsFolder)) {
    New-Item -ItemType Directory -Path $ReportsFolder | Out-Null
}

$policy = Get-Policy -Path $PolicyPath

# 1) HTTP baseline
$baselineHttpReport = Join-Path $ReportsFolder "baseline_http.txt"
Get-HttpHeadersReport -Url $UrlHttp -OutputPath $baselineHttpReport -Phase "before"

# 2) TLS baseline (if enabled in policy.json)
$tlsSummaryCsv = $null
if ($policy.TlsScan.Enabled -eq $true) {
    $tlsPrefix = Join-Path $ReportsFolder "tls"
    Run-TlsScan -TargetHost $policy.TlsScan.Host -Port $policy.TlsScan.Port -OutputPathPrefix $tlsPrefix -Phase "before"

    $nmapPath     = "${tlsPrefix}_nmap_before.txt"
    $tlsSummaryCsv = "${tlsPrefix}_summary_before.csv"
    Summarize-TlsProtocolsFromNmap -NmapOutputPath $nmapPath -SummaryCsvPath $tlsSummaryCsv -Phase "before"
}

# 3) Generate HTML chart from CSV summaries
$httpCsv = [System.IO.Path]::ChangeExtension($baselineHttpReport, ".summary.csv")
$chartHtml = Join-Path $ReportsFolder "baseline_chart.html"
New-BaselineChartHtml -HttpCsvPath $httpCsv -TlsCsvPath $tlsSummaryCsv -OutputHtmlPath $chartHtml

Write-Host ""
Write-Host "=== IIS Lock & Fix - baseline completed ==="
Write-Host "HTTP baseline report: $baselineHttpReport"
Write-Host "HTTP summary CSV:     $httpCsv"
if ($tlsSummaryCsv) {
    Write-Host "TLS summary CSV:      $tlsSummaryCsv"
}
Write-Host "Baseline chart HTML:  $chartHtml"