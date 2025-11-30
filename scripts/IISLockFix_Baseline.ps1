param(
    [string]$SitePath      = "C:\dev\iis-lock-fix\site",
    [string]$UrlHttp       = "http://iislock.localtest.me:8080",
    [string]$PolicyPath    = "C:\dev\iis-lock-fix\policy.json",
    [string]$ReportsFolder = "C:\dev\iis-lock-fix\reports"
)

# ------------ Dictionary for Non-Experts ------------
$SecurityDescriptions = @{
    'HSTS'                     = 'Ensures users always connect via secure HTTPS, preventing attacks that strip security.'
    'Clickjacking'             = 'Prevents hackers from hiding your website inside a fake frame to trick users into clicking buttons.'
    'X-Content-Type-Options'   = 'Stops the browser from guessing the file type, preventing malicious scripts disguised as images.'
    'Referrer-Policy'          = 'Controls how much user data is sent to other websites when clicking links.'
    'Content-Security-Policy'  = 'A powerful shield that prevents malicious scripts (XSS) from running on your site.'
    'Server header'            = 'Reveals exactly which software version you run, making it easier for hackers to find specific exploits.'
    'X-Powered-By'             = 'Reveals the technology (e.g., ASP.NET) used, helping attackers tailor their attacks.'
    'WeakProtocolsEnabled'     = 'Using old encryption (SSL/TLS 1.0) allows attackers to spy on data. Plain text is even worse.'
    'ModernTlsPresent'         = 'Modern encryption (TLS 1.2/1.3) is required for secure communication.'
    'AnyTlsSupported'          = 'Without TLS (HTTPS), all data is sent as plain text and can be stolen.'
}

# ------------ Load policy JSON ------------
function Get-Policy {
    param([string]$Path)
    if (-not (Test-Path $Path)) { throw "Policy file not found: $Path" }
    return Get-Content $Path -Raw | ConvertFrom-Json
}

# ------------ HTTP headers scan (baseline) ------------
function Get-HttpHeadersReport {
    param(
        [string]$Url,
        [string]$OutputPath,
        [string]$Phase  # "before" / "after"
    )

    Write-Host "[*] Running HTTP scan ($Phase) on $Url" -ForegroundColor Cyan

    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Host "Error accessing $Url : $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $headers = $resp.Headers
    $summary = @()

    # Define checks logic helper
    function Add-CheckResult {
        param($Category, $Name, $Condition, $GoodMsg, $BadMsg, $IsReverseLogic=$false)
        
        $StatusStr = if ($IsReverseLogic) { 
            if ($Condition) { 'Issue Found' } else { 'OK' }
        } else {
            if ($Condition) { 'OK' } else { 'Missing' }
        }

        $IsIssue = if ($IsReverseLogic) {
            if ($Condition) { 1 } else { 0 }
        } else {
            if ($Condition) { 0 } else { 1 }
        }

        $Message = if ($IsIssue -eq 0) { $GoodMsg } else { $BadMsg }
        
        return [PSCustomObject]@{
            Phase       = $Phase
            Category    = $Category
            Check       = $Name
            Status      = $StatusStr
            IsIssue     = $IsIssue
            Details     = $Message
            Description = $script:SecurityDescriptions[$Name]
        }
    }

    # 1. HSTS
    $summary += Add-CheckResult "HTTP" "HSTS" ([bool]$headers["Strict-Transport-Security"]) "Enabled" "Not configured"

    # 2. Clickjacking
    $hasXfo = [bool]$headers["X-Frame-Options"]
    $hasCspFrame = ($headers["Content-Security-Policy"] -match "frame-ancestors")
    $summary += Add-CheckResult "HTTP" "Clickjacking" ($hasXfo -or $hasCspFrame) "Protected" "Vulnerable"

    # 3. X-Content-Type-Options
    $hasXcto = ($headers["X-Content-Type-Options"] -match "nosniff")
    $summary += Add-CheckResult "HTTP" "X-Content-Type-Options" $hasXcto "Enabled (nosniff)" "Missing"

    # 4. Referrer-Policy
    $summary += Add-CheckResult "HTTP" "Referrer-Policy" ([bool]$headers["Referrer-Policy"]) "Configured" "Missing"

    # 5. CSP
    $summary += Add-CheckResult "HTTP" "Content-Security-Policy" ([bool]$headers["Content-Security-Policy"]) "Enabled" "Missing"

    # 6. Server Header (Reverse Logic: It's bad if present)
    $summary += Add-CheckResult "HTTP" "Server header" ([bool]$headers["Server"]) "Hidden" "Visible ($($headers['Server']))" $true

    # 7. X-Powered-By (Reverse Logic)
    $summary += Add-CheckResult "HTTP" "X-Powered-By" ([bool]$headers["X-Powered-By"]) "Hidden" "Visible ($($headers['X-Powered-By']))" $true

    # Save details to text file
    $reportContent = "=== Report ($Phase) ===`r`n"
    foreach ($item in $summary) {
        $mark = if ($item.IsIssue -eq 1) { "[X]" } else { "[OK]" }
        $reportContent += "$mark $($item.Check): $($item.Details)`r`n"
    }
    $reportContent | Set-Content $OutputPath

    # Export CSV
    $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, ".summary.csv")
    $summary | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    return $summary
}

# ------------ TLS scan ------------
function Run-TlsScan {
    param(
        [string]$TargetHost,
        [int]$Port,
        [string]$OutputPathPrefix,
        [string]$Phase
    )

    Write-Host "[*] Running TLS scan ($Phase) on $TargetHost`:$Port" -ForegroundColor Cyan
    
    $nmapOut   = "${OutputPathPrefix}nmap${Phase}.txt"
    
    # Run Nmap
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        # Using --script ssl-enum-ciphers. 
        $cmd = "nmap -Pn -p $Port --script ssl-enum-ciphers $TargetHost" 
        Write-Host "   Running Nmap..."
        try {
            cmd /c $cmd > $nmapOut 2>&1
        } catch {
            Write-Host "   [!] Nmap execution had issues, but continuing..." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   [!] Nmap not found in PATH." -ForegroundColor Red
    }

    # Parsing Nmap for Summary
    $protocols = @{ 'SSL 2.0'=$false; 'SSL 3.0'=$false; 'TLS 1.0'=$false; 'TLS 1.1'=$false; 'TLS 1.2'=$false; 'TLS 1.3'=$false }
    $foundAnyProtocol = $false

    if (Test-Path $nmapOut) {
        $content = Get-Content $nmapOut
        if ($content -match 'SSLv2')    { $protocols['SSL 2.0'] = $true; $foundAnyProtocol = $true }
        if ($content -match 'SSLv3')    { $protocols['SSL 3.0'] = $true; $foundAnyProtocol = $true }
        if ($content -match 'TLSv1\.0') { $protocols['TLS 1.0'] = $true; $foundAnyProtocol = $true }
        if ($content -match 'TLSv1\.1') { $protocols['TLS 1.1'] = $true; $foundAnyProtocol = $true }
        if ($content -match 'TLSv1\.2') { $protocols['TLS 1.2'] = $true; $foundAnyProtocol = $true }
        if ($content -match 'TLSv1\.3') { $protocols['TLS 1.3'] = $true; $foundAnyProtocol = $true }
    }

    $rows = @()
    
    # CHECK 1: Is TLS even enabled?
    $rows += [PSCustomObject]@{
        Phase = $Phase; Category = 'TLS'; Check = 'AnyTlsSupported'; 
        Status = $(if ($foundAnyProtocol) { 'YES' } else { 'NO' }); 
        IsIssue = $(if ($foundAnyProtocol) { 0 } else { 1 });
        Details = $(if ($foundAnyProtocol) { 'TLS layer detected' } else { 'No TLS detected (Plain HTTP)' })
        Description = $script:SecurityDescriptions['AnyTlsSupported']
    }

    # CHECK 2: Weak Protocols
    $hasWeak = ($protocols['SSL 2.0'] -or $protocols['SSL 3.0'] -or $protocols['TLS 1.0'] -or $protocols['TLS 1.1'])
    
    $weakStatus = ""
    $weakIsIssue = 0

    if (-not $foundAnyProtocol) {
        # CRITICAL: No protocols = Plain Text = Issue!
        $weakIsIssue = 1
        $weakStatus = "CRITICAL: Plain Text (No Encryption)"
    } elseif ($hasWeak) {
        $weakIsIssue = 1
        $weakStatus = "Weak protocols enabled (SSL2/3/TLS1.0/1.1)"
    } else {
        $weakIsIssue = 0
        $weakStatus = "No weak protocols detected"
    }

    $rows += [PSCustomObject]@{
        Phase = $Phase; Category = 'TLS'; Check = 'WeakProtocolsEnabled'; 
        Status = $(if ($weakIsIssue -eq 1) { 'YES' } else { 'NO' }); 
        IsIssue = $weakIsIssue;
        Details = $weakStatus
        Description = $script:SecurityDescriptions['WeakProtocolsEnabled']
    }

    # CHECK 3: Modern TLS
    $hasModern = ($protocols['TLS 1.2'] -or $protocols['TLS 1.3'])
    $rows += [PSCustomObject]@{
        Phase = $Phase; Category = 'TLS'; Check = 'ModernTlsPresent'; 
        Status = $(if ($hasModern) { 'YES' } else { 'NO' }); 
        IsIssue = $(if ($hasModern) { 0 } else { 1 });
        Details = $(if ($hasModern) { 'Modern TLS (1.2/1.3) available' } else { 'Modern TLS missing' })
        Description = $script:SecurityDescriptions['ModernTlsPresent']
    }

    $rows | Export-Csv -Path "${OutputPathPrefix}_summary_${Phase}.csv" -NoTypeInformation -Encoding UTF8
}

# ------------ VISUAL REPORT GENERATOR ------------
function New-VisualHtmlReport {
    param(
        [string]$HttpCsvPath,
        [string]$TlsCsvPath,
        [string]$OutputHtmlPath
    )

    $results = @()
    if (Test-Path $HttpCsvPath) { $results += Import-Csv $HttpCsvPath }
    if (Test-Path $TlsCsvPath)  { $results += Import-Csv $TlsCsvPath }

    $totalChecks = $results.Count
    if ($totalChecks -eq 0) { $totalChecks = 1 } 
    $totalIssues = ($results | Where-Object { $_.IsIssue -eq '1' }).Count
    $passCount   = $totalChecks - $totalIssues
    
    # Calculate Score (0/10)
    $rawScore = ($passCount / $totalChecks) * 10
    $score    = [math]::Round($rawScore, 1)

    $gradeColor = switch ($score) {
        {$_ -ge 8} { '#10b981' } # Emerald Green
        {$_ -ge 5} { '#f59e0b' } # Amber
        default    { '#ef4444' } # Red
    }
    
    # 1. Marketing Text Logic
    $marketingText = if ($score -lt 8) {
        "<div class='marketing-alert'>
            <h3>&#9888; Your IIS Server is Exposed</h3>
            <p>Our audit detected critical vulnerabilities that leave your organization open to <strong>Ransomware</strong>, <strong>Data Theft</strong>, and <strong>Man-in-the-Middle attacks</strong>.</p>
            <p><strong>IISLock&Fix</strong> automatically hardens your server infrastructure in seconds, ensuring enterprise-grade compliance.</p>
        </div>"
    } else {
        "<div class='marketing-success'>
            <h3>&#128737; System Secure</h3>
            <p>Excellent work. Your server is hardened according to <strong>IISLock&Fix</strong> best practices.</p>
            <p>Your infrastructure is resilient against modern web threats.</p>
        </div>"
    }

    # Build Table Rows
    $tableRows = ""
    foreach ($r in $results) {
        $statusClass = if ($r.IsIssue -eq '1') { 'issue' } else { 'pass' }
        $badgeClass  = if ($r.IsIssue -eq '1') { 'badge-fail' } else { 'badge-pass' }
        $badgeText   = if ($r.IsIssue -eq '1') { 'FAILED' } else { 'SECURE' }
        
        $tableRows += "
        <tr class='$statusClass'>
            <td><span class='category-tag'>$($r.Category)</span></td>
            <td>
                <div class='check-name'>$($r.Check)</div>
                <div class='desc'>$($r.Description)</div>
            </td>
            <td><span class='badge $badgeClass'>$badgeText</span></td>
            <td class='details'>$($r.Details)</td>
        </tr>"
    }

    # HTML Template
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IISLock&Fix Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --primary: #1e293b;
            --secondary: #3b82f6;
            --bg: #f1f5f9;
            --card-bg: #ffffff;
            --text-main: #334155;
            --text-light: #64748b;
            --danger: #ef4444;
            --success: #10b981;
        }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text-main); margin: 0; padding: 0; }
        
        /* Header */
        .header { background: var(--primary); color: white; padding: 20px 0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        .header-content { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 20px; }
        .brand { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
        .brand span { color: var(--secondary); }
        .date { font-size: 14px; opacity: 0.8; }

        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        
        /* Dashboard Grid - Now 3 Columns! */
        .dashboard { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .card { background: var(--card-bg); border-radius: 12px; padding: 30px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
        
        /* Score Section */
        .score-wrapper { text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; }
        .grade-number { font-size: 72px; font-weight: 800; color: $gradeColor; line-height: 1; margin-bottom: 10px; }
        .grade-label { font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-light); font-weight: 600; }
        .issues-count { margin-top: 10px; font-weight: 600; font-size: 16px; }

        /* Chart Section */
        .chart-container { position: relative; width: 100%; height: 200px; display: flex; justify-content: center; align-items: center; }

        /* Marketing Section */
        .marketing-alert { border-left: 5px solid var(--danger); padding-left: 20px; height: 100%; display: flex; flex-direction: column; justify-content: center; }
        .marketing-success { border-left: 5px solid var(--success); padding-left: 20px; height: 100%; display: flex; flex-direction: column; justify-content: center; }
        .marketing-alert h3 { color: var(--danger); margin: 0 0 10px 0; font-size: 18px; }
        .marketing-success h3 { color: var(--success); margin: 0 0 10px 0; font-size: 18px; }
        .marketing-alert p, .marketing-success p { font-size: 14px; line-height: 1.5; margin: 5px 0; }

        /* Table */
        .table-card { background: var(--card-bg); border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
        .table-header { padding: 20px 30px; border-bottom: 1px solid #e2e8f0; background: #f8fafc; font-weight: 600; color: var(--primary); font-size: 18px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 20px 30px; text-align: left; border-bottom: 1px solid #f1f5f9; }
        tr:last-child td { border-bottom: none; }
        
        .check-name { font-weight: 600; color: var(--text-main); margin-bottom: 4px; }
        .desc { font-size: 12px; color: var(--text-light); }
        .category-tag { background: #e2e8f0; color: var(--text-light); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        
        .badge { padding: 6px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }
        .badge-fail { background: #fee2e2; color: #991b1b; }
        .badge-pass { background: #d1fae5; color: #065f46; }
        
        .details { font-family: 'Consolas', monospace; font-size: 13px; color: var(--text-main); }

        .footer { text-align: center; margin-top: 50px; color: var(--text-light); font-size: 12px; padding-bottom: 20px; }
    </style>
</head>
<body>

    <div class="header">
        <div class="header-content">
            <div class="brand">IISLock<span>&</span>Fix</div>
            <div class="date">Audit Date: $(Get-Date -Format "yyyy-MM-dd HH:mm")</div>
        </div>
    </div>

    <div class="container">
        
        <div class="dashboard">
            <!-- 1. Score Card -->
            <div class="card">
                <div class="score-wrapper">
                    <div class="grade-number">$score / 10</div>
                    <div class="grade-label">Security Score</div>
                    <div class="issues-count"><strong>$totalIssues</strong> Issues Found</div>
                </div>
            </div>
            
            <!-- 2. Chart Card -->
            <div class="card">
                <div class="chart-container">
                    <canvas id="statusChart"></canvas>
                </div>
            </div>

            <!-- 3. Status/Marketing Card -->
            <div class="card">
                $marketingText
            </div>
        </div>

        <!-- Findings Table -->
        <div class="table-card">
            <div class="table-header">Detailed Security Audit</div>
            <table>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by IISLock&Fix &#8226; Automated Server Hardening Solution
        </div>
    </div>

    <script>
        const ctx = document.getElementById('statusChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Secure Checks', 'Issues Found'],
                datasets: [{
                    data: [$passCount, $totalIssues],
                    backgroundColor: ['#10b981', '#ef4444'],
                    hoverBackgroundColor: ['#059669', '#dc2626'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            font: { family: "'Inter', sans-serif", size: 11 },
                            usePointStyle: true,
                            boxWidth: 8
                        }
                    }
                },
                cutout: '60%'
            }
        });
    </script>
</body>
</html>
"@

    $html | Set-Content $OutputHtmlPath -Encoding UTF8
    Write-Host "[*] Visual report generated: $OutputHtmlPath" -ForegroundColor Magenta
}

# ------------ MAIN EXECUTION ------------

if (-not (Test-Path $ReportsFolder)) { New-Item -ItemType Directory -Path $ReportsFolder | Out-Null }
$policy = Get-Policy -Path $PolicyPath

# 1. HTTP Scan
$httpReportFile = Join-Path $ReportsFolder "scan_http.txt"
Get-HttpHeadersReport -Url $UrlHttp -OutputPath $httpReportFile -Phase "before"
$httpCsv = [System.IO.Path]::ChangeExtension($httpReportFile, ".summary.csv")

# 2. TLS Scan
$tlsPrefix = Join-Path $ReportsFolder "scan_tls"
if ($policy.TlsScan.Enabled) {
    Run-TlsScan -TargetHost $policy.TlsScan.Host -Port $policy.TlsScan.Port -OutputPathPrefix $tlsPrefix -Phase "before"
}
$tlsCsv = "${tlsPrefix}_summary_before.csv"

# 3. Generate Fancy HTML
$htmlReport = Join-Path $ReportsFolder "SecurityReport.html"
New-VisualHtmlReport -HttpCsvPath $httpCsv -TlsCsvPath $tlsCsv -OutputHtmlPath $htmlReport

Write-Host "`n=== DONE ===" -ForegroundColor Green
Invoke-Item $htmlReport # Opens the report automatically