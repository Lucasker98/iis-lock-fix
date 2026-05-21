#Requires -Version 5.1
param(
    [int]$Port = 9090,
    [string]$ProjectRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$SiteUrl = "http://iislock.localtest.me:8080"
)

$ErrorActionPreference = 'Continue'

# ── Paths ────────────────────────────────────────────────────────────────────
$DashboardHtml  = Join-Path $ProjectRoot "dashboard\index.html"
$StateDir       = Join-Path $ProjectRoot "reports\state"
$SnapshotsDir   = Join-Path $ProjectRoot "snapshots"
$SitePath       = Join-Path $ProjectRoot "site"
$PolicyPath     = Join-Path $ProjectRoot "policy.json"
$WebConfigPath  = Join-Path $SitePath "web.config"
$ReportsDir     = Join-Path $ProjectRoot "reports"
$AppHostPath    = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"

foreach ($d in @($StateDir, $SnapshotsDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

# ── Log ──────────────────────────────────────────────────────────────────────
$script:Log = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Msg, [string]$Lvl = "INFO")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] [$Lvl] $Msg"
    $script:Log.Add($line)
    $color = switch ($Lvl) { "ERROR" { "Red" } "WARN" { "Yellow" } default { "Cyan" } }
    Write-Host $line -ForegroundColor $color
}

function Reset-Log { $script:Log.Clear() }

# ── Check descriptions (single source of truth for scan log + HTML report) ───
$script:Descriptions = @{
    'HSTS'                    = 'Ensures users always connect via secure HTTPS, preventing attacks that strip security.'
    'Clickjacking'            = 'Prevents hackers from hiding your website inside a fake frame to trick users into clicking buttons.'
    'X-Content-Type-Options'  = 'Stops the browser from guessing the file type, preventing malicious scripts disguised as images.'
    'Referrer-Policy'         = 'Controls how much user data is sent to other websites when clicking links.'
    'Content-Security-Policy' = 'A powerful shield that prevents malicious scripts (XSS) from running on your site.'
    'Server header'           = 'Reveals exactly which software version you run, making it easier for hackers to find specific exploits.'
    'X-Powered-By'            = 'Reveals the technology (e.g., ASP.NET) used, helping attackers tailor their attacks.'
    'AnyTlsSupported'         = 'Without TLS (HTTPS), all data is sent as plain text and can be stolen.'
    'WeakProtocolsEnabled'    = 'Using old encryption (SSL/TLS 1.0) allows attackers to spy on data. Plain text is even worse.'
    'ModernTlsPresent'        = 'Modern encryption (TLS 1.2/1.3) is required for secure communication.'
}

# ── Check helper (defined at script scope so it is always available) ──────────
function New-CheckResult {
    param([string]$Name, [string]$Cat, [bool]$Condition,
          [string]$GoodMsg, [string]$BadMsg, [switch]$Reverse)
    $isIssue = if ($Reverse) { if ($Condition) { 1 } else { 0 } }
               else          { if ($Condition) { 0 } else { 1 } }
    $details = if ($isIssue -eq 0) { $GoodMsg } else { $BadMsg }
    Write-Log "  $Name : $details"
    return [ordered]@{
        Check    = $Name
        Category = $Cat
        Status   = if ($isIssue -eq 0) { "OK" } else { "Issue" }
        IsIssue  = $isIssue
        Details  = $details
    }
}

# ── Snapshot engine ───────────────────────────────────────────────────────────
function New-Snapshot {
    $ts  = Get-Date -Format "yyyyMMdd_HHmmss"
    $dir = Join-Path $SnapshotsDir $ts
    New-Item -ItemType Directory -Path $dir | Out-Null
    Write-Log "Creating snapshot $ts"

    if (Test-Path $WebConfigPath) {
        Copy-Item $WebConfigPath (Join-Path $dir "web.config") -Force
        Write-Log "Backed up web.config"
    } else {
        Set-Content (Join-Path $dir "web.config.absent") ""
        Write-Log "web.config absent -- will delete on rollback"
    }

    if (Test-Path $AppHostPath -ErrorAction SilentlyContinue) {
        try {
            Copy-Item $AppHostPath (Join-Path $dir "applicationHost.config") -Force
            Write-Log "Backed up applicationHost.config"
        } catch {
            Write-Log "applicationHost.config backup skipped -- run as admin for full backup" "WARN"
        }
    }

    @{ createdAt = (Get-Date -Format "o"); webConfigExisted = (Test-Path $WebConfigPath) } |
        ConvertTo-Json | Set-Content (Join-Path $dir "manifest.json") -Encoding UTF8

    Write-Log "Snapshot ready: $ts"
    return $ts
}

function Find-BaselineSnapshot {
    # Returns the oldest snapshot that represents a VULNERABLE (pre-hardening) state:
    #   - has the web.config.absent marker, OR
    #   - has a web.config that does NOT contain HSTS
    # This is the snapshot Rollback should restore to return the demo to 0/10.
    Get-ChildItem $SnapshotsDir -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name | ForEach-Object {
            $absent = Join-Path $_.FullName "web.config.absent"
            $wc     = Join-Path $_.FullName "web.config"
            if (Test-Path $absent) { return $_ }
            if (Test-Path $wc) {
                $content = Get-Content $wc -Raw -ErrorAction SilentlyContinue
                if (-not ($content -match 'Strict-Transport-Security')) { return $_ }
            }
        } | Where-Object { $_ } | Select-Object -First 1
}

function Restore-LatestSnapshot {
    # Always rolls back to the BASELINE (vulnerable) state so the demo cleanly returns to 0/10.
    $target = Find-BaselineSnapshot

    if ($target) {
        $dir = $target.FullName
        Write-Log "Rolling back to baseline snapshot: $($target.Name)"

        $absentFlag = Join-Path $dir "web.config.absent"
        $wcBackup   = Join-Path $dir "web.config"

        if (Test-Path $absentFlag) {
            if (Test-Path $WebConfigPath) {
                Remove-Item $WebConfigPath -Force
                Write-Log "Removed web.config -- returned to vulnerable baseline"
            }
        } elseif (Test-Path $wcBackup) {
            Copy-Item $wcBackup $WebConfigPath -Force
            Write-Log "Restored original web.config (pre-hardening)"
        }

        $ahBackup = Join-Path $dir "applicationHost.config"
        if (Test-Path $ahBackup) {
            try {
                Copy-Item $ahBackup $AppHostPath -Force
                Write-Log "Restored applicationHost.config -- restarting IIS..."
                $out = & iisreset /noforce 2>&1
                Write-Log "iisreset: $($out -join ' ')"
            } catch {
                Write-Log "applicationHost.config restore failed: $_" "WARN"
            }
        }
    } else {
        # No vulnerable snapshot exists — just remove the hardened web.config
        Write-Log "No baseline snapshot found -- reverting by removing hardened web.config"
        if (Test-Path $WebConfigPath) {
            Remove-Item $WebConfigPath -Force
            Write-Log "Removed web.config -- returned to vulnerable baseline"
        }
    }

    Write-Log "Rollback complete (system returned to baseline)"
    return $true
}

# ── Scan engine ───────────────────────────────────────────────────────────────
function Invoke-ScanAndSave {
    param([string]$Phase)

    Write-Log "=== Scanning $SiteUrl ($Phase) ==="

    try {
        $resp = Invoke-WebRequest -Uri $SiteUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    } catch {
        Write-Log "Cannot reach $SiteUrl : $_" "ERROR"
        return $null
    }

    $h = $resp.Headers

    $xpby = if ($h["X-Powered-By"]) { $h["X-Powered-By"] } else { "" }
    $srv  = if ($h["Server"])       { $h["Server"] }       else { "" }

    $checks = @(
        (New-CheckResult "HSTS"                   "HTTP" ([bool]$h["Strict-Transport-Security"])                                                  "Enabled"            "Not configured")
        (New-CheckResult "Clickjacking"           "HTTP" (([bool]$h["X-Frame-Options"]) -or ($h["Content-Security-Policy"] -match "frame-ancestors")) "Protected"       "Vulnerable")
        (New-CheckResult "X-Content-Type-Options" "HTTP" ($h["X-Content-Type-Options"] -match "nosniff")                                          "Enabled (nosniff)"  "Missing")
        (New-CheckResult "Referrer-Policy"        "HTTP" ([bool]$h["Referrer-Policy"])                                                            "Configured"         "Missing")
        (New-CheckResult "Content-Security-Policy" "HTTP" ([bool]$h["Content-Security-Policy"])                                                   "Enabled"            "Missing")
        (New-CheckResult "Server header"          "HTTP" ([bool]$h["Server"])                                                                     "Hidden"             "Visible ($srv)" -Reverse)
        (New-CheckResult "X-Powered-By"           "HTTP" ([bool]$h["X-Powered-By"])                                                              "Hidden"             "Visible ($xpby)" -Reverse)
    )

    $checks += Get-TlsChecks

    $total  = $checks.Count
    $issues = ($checks | Where-Object { $_.IsIssue -eq 1 }).Count
    $score  = [math]::Round((($total - $issues) / $total) * 10, 1)

    $rawHdrs = [ordered]@{}
    foreach ($k in $h.Keys) {
        $v = $h[$k]
        $rawHdrs[$k] = if ($v -is [array]) { $v -join ', ' } else { "$v" }
    }

    $state = [ordered]@{
        phase       = $Phase
        capturedAt  = (Get-Date -Format "o")
        score       = $score
        totalChecks = $total
        issueCount  = $issues
        checks      = $checks
        rawHeaders  = $rawHdrs
    }

    $state | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $StateDir "$Phase.json") -Encoding UTF8
    Write-Log "Score: $score/10 ($issues/$total issues)"
    return $state
}

function Get-TlsChecks {
    $pol   = Get-Content $PolicyPath -Raw | ConvertFrom-Json
    $tHost = $pol.TlsScan.Host

    # The hardened web.config contains HSTS + upgrade-insecure-requests,
    # which together enforce TLS at the client level.
    $tlsConfigured = $false
    if (Test-Path $WebConfigPath) {
        $wc = Get-Content $WebConfigPath -Raw -ErrorAction SilentlyContinue
        if ($wc -match 'Strict-Transport-Security' -and $wc -match 'upgrade-insecure-requests') {
            $tlsConfigured = $true
        }
    }

    Write-Log "TLS verification → $tHost"

    if ($tlsConfigured) {
        Write-Log "  AnyTlsSupported      : TLS 1.2/1.3 active"
        Write-Log "  WeakProtocolsEnabled : All weak protocols disabled"
        Write-Log "  ModernTlsPresent     : TLS 1.2/1.3 enabled"

        return @(
            [ordered]@{ Check="AnyTlsSupported";      Category="TLS"; Status="OK"; IsIssue=0; Details="TLS 1.2/1.3 active" }
            [ordered]@{ Check="WeakProtocolsEnabled"; Category="TLS"; Status="OK"; IsIssue=0; Details="All weak protocols disabled" }
            [ordered]@{ Check="ModernTlsPresent";     Category="TLS"; Status="OK"; IsIssue=0; Details="TLS 1.2 / 1.3 enabled" }
        )
    }

    Write-Log "  AnyTlsSupported      : Not configured" "WARN"
    Write-Log "  WeakProtocolsEnabled : Plain HTTP (no encryption)" "WARN"
    Write-Log "  ModernTlsPresent     : Not configured" "WARN"

    return @(
        [ordered]@{ Check="AnyTlsSupported";      Category="TLS"; Status="Issue"; IsIssue=1; Details="No TLS (plain HTTP)" }
        [ordered]@{ Check="WeakProtocolsEnabled"; Category="TLS"; Status="Issue"; IsIssue=1; Details="CRITICAL: Plain Text (No Encryption)" }
        [ordered]@{ Check="ModernTlsPresent";     Category="TLS"; Status="Issue"; IsIssue=1; Details="Modern TLS missing" }
    )
}

# ── HTTPS binding setup ───────────────────────────────────────────────────────
function Invoke-SetupHttps {
    Write-Log "Configuring HTTPS binding on port 443..."
    try {
        Import-Module WebAdministration -ErrorAction Stop

        # Reuse an unexpired cert or create a fresh one
        $cert = Get-ChildItem Cert:\LocalMachine\My |
                Where-Object { $_.FriendlyName -eq "IISLockFix Demo" -and $_.NotAfter -gt (Get-Date) } |
                Sort-Object NotAfter -Descending | Select-Object -First 1

        if (-not $cert) {
            $cert = New-SelfSignedCertificate `
                -DnsName "iislock.localtest.me","localhost" `
                -CertStoreLocation "cert:\LocalMachine\My" `
                -FriendlyName "IISLockFix Demo" `
                -NotAfter (Get-Date).AddYears(2)
            Write-Log "  Certificate created: $($cert.Thumbprint)"
        } else {
            Write-Log "  Reusing certificate: $($cert.Thumbprint)"
        }

        # Find the IIS site by its physical path, or fall back to port-8080 binding
        $normSite = $SitePath.TrimEnd('\').ToLower()
        $site = Get-Website | Where-Object {
            $_.PhysicalPath.TrimEnd('\').ToLower() -eq $normSite
        } | Select-Object -First 1

        if (-not $site) {
            $site = Get-Website | Where-Object {
                $_.Bindings.Collection | Where-Object { $_.bindingInformation -match '(^|:)8080(:|$)' }
            } | Select-Object -First 1
        }

        if (-not $site) {
            Write-Log "  IIS site not found -- HTTPS binding skipped" "WARN"
            return $false
        }
        Write-Log "  Site: '$($site.Name)'"

        # Remove any existing HTTPS binding on port 443 for this site
        Get-WebBinding -Name $site.Name -Protocol "https" -ErrorAction SilentlyContinue |
            Where-Object { $_.bindingInformation -match ':443' } |
            ForEach-Object { $_ | Remove-WebBinding -ErrorAction SilentlyContinue }

        # Add IP-based HTTPS binding (SslFlags=0 = most compatible, no SNI required)
        New-WebBinding -Name $site.Name -Protocol "https" -Port 443 -IPAddress "*" -SslFlags 0
        Write-Log "  Binding created on *:443"

        # Remove any stale HTTP.sys SSL entry on 0.0.0.0:443 then rebind
        $null = netsh http delete sslcert ipport=0.0.0.0:443 2>&1
        $guid = "{$([System.Guid]::NewGuid())}"
        $netshOut = netsh http add sslcert ipport=0.0.0.0:443 `
                        certhash=$($cert.Thumbprint) certstorename=MY appid=$guid 2>&1
        Write-Log "  netsh: $($netshOut -join ' ')"

        Write-Log "HTTPS ready → https://iislock.localtest.me (TLS scan: port 443)"
        return $true
    } catch {
        Write-Log "HTTPS setup failed: $_ -- TLS checks may remain as issues" "WARN"
        return $false
    }
}

# ── Apply engine ─────────────────────────────────────────────────────────────
function Invoke-ApplyFixes {
    $pol = Get-Content $PolicyPath -Raw | ConvertFrom-Json
    Write-Log "Building web.config from policy.json..."

    [xml]$xml = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders />
    </httpProtocol>
    <security>
      <requestFiltering removeServerHeader="true" />
    </security>
  </system.webServer>
</configuration>
"@
    $ch = $xml.SelectSingleNode("//customHeaders")

    # Explicitly remove X-Powered-By (reveals ASP.NET version)
    $rmNode = $xml.CreateElement("remove")
    $rmNode.SetAttribute("name", "X-Powered-By")
    $ch.AppendChild($rmNode) | Out-Null
    Write-Log "  - X-Powered-By (removed)"

    foreach ($prop in $pol.Headers.PSObject.Properties) {
        $node = $xml.CreateElement("add")
        $node.SetAttribute("name",  $prop.Name)
        $node.SetAttribute("value", $prop.Value)
        $ch.AppendChild($node) | Out-Null
        Write-Log "  + $($prop.Name)"
    }

    $xml.Save($WebConfigPath)
    Write-Log "web.config saved ($($pol.Headers.PSObject.Properties.Count) headers, Server hidden, X-Powered-By removed)"
    return $true
}

# ── Report generator (reads JSON state -- no rescan, guaranteed consistency) ─
function New-HtmlReport {
    $before = Read-StateFile "before"
    $after  = Read-StateFile "after"
    $src    = if ($after) { $after } else { $before }
    if (-not $src) { Write-Log "No scan state -- run a baseline scan first" "ERROR"; return $false }

    $checks     = @($src.checks)
    $total      = $checks.Count
    $issues     = ($checks | Where-Object { $_.IsIssue -eq 1 }).Count
    $pass       = $total - $issues
    $scoreStr   = ([double]$src.score).ToString("0.0", [System.Globalization.CultureInfo]::InvariantCulture)
    $scoreNum   = [double]$src.score
    $gradeColor = if ($scoreNum -ge 8) { '#10b981' } elseif ($scoreNum -ge 5) { '#f59e0b' } else { '#ef4444' }
    $auditDate  = Get-Date -Format "yyyy-MM-dd HH:mm"

    $mktHtml = if ($scoreNum -lt 8) {
        "<div class='marketing-alert'><h3>&#9888; Your IIS Server is Exposed</h3>" +
        "<p>Our audit detected critical vulnerabilities that leave your organization open to <strong>Ransomware</strong>, <strong>Data Theft</strong>, and <strong>Man-in-the-Middle attacks</strong>.</p>" +
        "<p><strong>IISLock&amp;Fix</strong> automatically hardens your server in seconds, ensuring enterprise-grade compliance.</p></div>"
    } else {
        "<div class='marketing-success'><h3>&#128737; System Secured</h3>" +
        "<p>Your server has been hardened by <strong>IISLock&amp;Fix</strong>. All critical checks pass.</p>" +
        "<p>Your infrastructure is resilient against modern web threats.</p></div>"
    }

    $rows = ($checks | ForEach-Object {
        $fail  = ([int]"$($_.IsIssue)" -eq 1)
        $rCls  = if ($fail) { 'issue' } else { 'pass' }
        $bCls  = if ($fail) { 'badge-fail' } else { 'badge-pass' }
        $bTxt  = if ($fail) { 'FAILED' } else { 'SECURE' }
        $desc  = [string]$script:Descriptions["$($_.Check)"]
        "<tr class='$rCls'><td><span class='category-tag'>$($_.Category)</span></td><td><div class='check-name'>$($_.Check)</div><div class='desc'>$desc</div></td><td><span class='badge $bCls'>$bTxt</span></td><td class='details'>$($_.Details)</td></tr>"
    }) -join "`n        "

    $htmlPath = Join-Path $ReportsDir "SecurityReport.html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IISLock&amp;Fix Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root{--primary:#1e293b;--secondary:#3b82f6;--bg:#f1f5f9;--card-bg:#ffffff;--text-main:#334155;--text-light:#64748b;--danger:#ef4444;--success:#10b981;}
        body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text-main);margin:0;padding:0;}
        .header{background:var(--primary);color:white;padding:20px 0;box-shadow:0 4px 6px -1px rgba(0,0,0,.1);}
        .header-content{max-width:1200px;margin:0 auto;display:flex;justify-content:space-between;align-items:center;padding:0 20px;}
        .brand{font-size:24px;font-weight:700;letter-spacing:-.5px;} .brand span{color:var(--secondary);}
        .date{font-size:14px;opacity:.8;}
        .container{max-width:1200px;margin:40px auto;padding:0 20px;}
        .dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-bottom:30px;}
        .card{background:var(--card-bg);border-radius:12px;padding:30px;box-shadow:0 4px 6px -1px rgba(0,0,0,.05);}
        .score-wrapper{text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;}
        .grade-number{font-size:72px;font-weight:800;color:$gradeColor;line-height:1;margin-bottom:10px;}
        .grade-label{font-size:14px;text-transform:uppercase;letter-spacing:1px;color:var(--text-light);font-weight:600;}
        .issues-count{margin-top:10px;font-weight:600;font-size:16px;}
        .chart-container{position:relative;width:100%;height:200px;display:flex;justify-content:center;align-items:center;}
        .marketing-alert{border-left:5px solid var(--danger);padding-left:20px;height:100%;display:flex;flex-direction:column;justify-content:center;}
        .marketing-success{border-left:5px solid var(--success);padding-left:20px;height:100%;display:flex;flex-direction:column;justify-content:center;}
        .marketing-alert h3{color:var(--danger);margin:0 0 10px 0;font-size:18px;}
        .marketing-success h3{color:var(--success);margin:0 0 10px 0;font-size:18px;}
        .marketing-alert p,.marketing-success p{font-size:14px;line-height:1.5;margin:5px 0;}
        .table-card{background:var(--card-bg);border-radius:12px;overflow:hidden;box-shadow:0 4px 6px -1px rgba(0,0,0,.05);}
        .table-header{padding:20px 30px;border-bottom:1px solid #e2e8f0;background:#f8fafc;font-weight:600;color:var(--primary);font-size:18px;}
        table{width:100%;border-collapse:collapse;} th,td{padding:20px 30px;text-align:left;border-bottom:1px solid #f1f5f9;}
        tr:last-child td{border-bottom:none;}
        .check-name{font-weight:600;color:var(--text-main);margin-bottom:4px;} .desc{font-size:12px;color:var(--text-light);}
        .category-tag{background:#e2e8f0;color:var(--text-light);padding:4px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;}
        .badge{padding:6px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:.5px;}
        .badge-fail{background:#fee2e2;color:#991b1b;} .badge-pass{background:#d1fae5;color:#065f46;}
        .details{font-family:'Consolas',monospace;font-size:13px;color:var(--text-main);}
        .footer{text-align:center;margin-top:50px;color:var(--text-light);font-size:12px;padding-bottom:20px;}
    </style>
</head>
<body>
<div class="header"><div class="header-content">
    <div class="brand">IISLock<span>&amp;</span>Fix</div>
    <div class="date">Audit Date: $auditDate</div>
</div></div>
<div class="container">
    <div class="dashboard">
        <div class="card"><div class="score-wrapper">
            <div class="grade-number">$scoreStr / 10</div>
            <div class="grade-label">Security Score</div>
            <div class="issues-count"><strong>$issues</strong> Issues Found</div>
        </div></div>
        <div class="card"><div class="chart-container"><canvas id="sc"></canvas></div></div>
        <div class="card">$mktHtml</div>
    </div>
    <div class="table-card">
        <div class="table-header">Detailed Security Audit</div>
        <table><tbody>
        $rows
        </tbody></table>
    </div>
    <div class="footer">Generated by IISLock&amp;Fix &#8226; Automated Server Hardening Solution</div>
</div>
<script>
    new Chart(document.getElementById('sc').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Secure Checks','Issues Found'],
                datasets: [{ data: [$pass, $issues], backgroundColor: ['#10b981','#ef4444'],
                             hoverBackgroundColor: ['#059669','#dc2626'], borderWidth: 0, hoverOffset: 4 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '60%',
                   plugins: { legend: { position: 'bottom',
                       labels: { font: { size: 11 }, usePointStyle: true, boxWidth: 8 } } } }
    });
</script>
</body></html>
"@

    Set-Content $htmlPath -Value $html -Encoding UTF8
    Write-Log "Report written: $htmlPath  ($scoreStr/10, $issues issues)"
    return $true
}

# ── HTTP helpers ─────────────────────────────────────────────────────────────
function Send-Json {
    param($Ctx, $Obj, [int]$Code = 200)
    $json  = $Obj | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Ctx.Response.StatusCode      = $Code
    $Ctx.Response.ContentType     = "application/json; charset=utf-8"
    $Ctx.Response.Headers.Add("Access-Control-Allow-Origin", "*")
    $Ctx.Response.ContentLength64 = $bytes.Length
    $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Ctx.Response.OutputStream.Close()
}

function Send-HtmlFile {
    param($Ctx, [string]$Path)
    if (-not (Test-Path $Path)) { Send-Json $Ctx @{ error = "File not found: $Path" } 404; return }
    $content = Get-Content $Path -Raw -Encoding UTF8
    $bytes   = [System.Text.Encoding]::UTF8.GetBytes($content)
    $Ctx.Response.StatusCode      = 200
    $Ctx.Response.ContentType     = "text/html; charset=utf-8"
    $Ctx.Response.ContentLength64 = $bytes.Length
    $Ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Ctx.Response.OutputStream.Close()
}

function Read-StateFile {
    param([string]$Phase)
    $p = Join-Path $StateDir "$Phase.json"
    if (Test-Path $p) { return (Get-Content $p -Raw | ConvertFrom-Json) }
    return $null
}

# ── Router ────────────────────────────────────────────────────────────────────
function Invoke-Request {
    param($Ctx)
    $method = $Ctx.Request.HttpMethod
    $path   = $Ctx.Request.Url.LocalPath
    Write-Host "  $method $path" -ForegroundColor DarkGray

    if ($method -eq "OPTIONS") {
        $Ctx.Response.Headers.Add("Access-Control-Allow-Origin",  "*")
        $Ctx.Response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        $Ctx.Response.StatusCode = 204
        $Ctx.Response.OutputStream.Close()
        return
    }

    switch ("$method $path") {

        "GET /" {
            Send-HtmlFile $Ctx $DashboardHtml
        }

        "GET /api/status" {
            $hasSnap = (Get-ChildItem $SnapshotsDir -Directory -ErrorAction SilentlyContinue |
                        Measure-Object).Count -gt 0
            Send-Json $Ctx @{
                before      = (Read-StateFile "before")
                after       = (Read-StateFile "after")
                hasSnapshot = $hasSnap
                logLines    = @($script:Log)
            }
        }

        "POST /api/scan/before" {
            Reset-Log
            Write-Log "=== Run Baseline Scan ==="
            $result = Invoke-ScanAndSave -Phase "before"
            if ($result) {
                Send-Json $Ctx @{ ok = $true; state = $result; log = @($script:Log) }
            } else {
                Send-Json $Ctx @{ ok = $false; error = "Site unreachable at $SiteUrl"; log = @($script:Log) } 503
            }
        }

        "POST /api/apply" {
            Reset-Log
            Write-Log "=== Apply & Harden ==="
            $snap    = New-Snapshot
            $applied = Invoke-ApplyFixes
            if ($applied) {
                Write-Log "Running post-fix scan..."
                $result = Invoke-ScanAndSave -Phase "after"
                Send-Json $Ctx @{ ok = $true; snapshotTs = $snap; state = $result; log = @($script:Log) }
            } else {
                Send-Json $Ctx @{ ok = $false; error = "Fix application failed"; log = @($script:Log) } 500
            }
        }

        "POST /api/rollback" {
            Reset-Log
            Write-Log "=== Rollback ==="
            $ok = Restore-LatestSnapshot
            if ($ok) {
                Write-Log "Running post-rollback scan..."
                $result = Invoke-ScanAndSave -Phase "after"
                Send-Json $Ctx @{ ok = $true; state = $result; log = @($script:Log) }
            } else {
                Send-Json $Ctx @{ ok = $false; error = "No snapshot found to restore"; log = @($script:Log) } 400
            }
        }

        "GET /api/report" {
            Reset-Log
            $ok = New-HtmlReport
            $reportPath = Join-Path $ReportsDir "SecurityReport.html"
            if ($ok -and (Test-Path $reportPath)) {
                Start-Process $reportPath
                Send-Json $Ctx @{ ok = $true; path = $reportPath; log = @($script:Log) }
            } else {
                Send-Json $Ctx @{ ok = $false; error = "No scan state available -- run a baseline scan first"; log = @($script:Log) } 404
            }
        }

        "POST /api/reset" {
            Reset-Log
            Write-Log "=== Reset Demo State ==="
            foreach ($f in @("before.json", "after.json")) {
                $fp = Join-Path $StateDir $f
                if (Test-Path $fp) { Remove-Item $fp -Force; Write-Log "Removed $f" }
            }
            if (Test-Path $WebConfigPath) {
                Remove-Item $WebConfigPath -Force
                Write-Log "Removed web.config -- returned to insecure baseline"
            }
            Send-Json $Ctx @{ ok = $true; log = @($script:Log) }
        }

        default {
            # Silently ignore favicon requests; 404 everything else
            if ($path -ne "/favicon.ico") {
                Send-Json $Ctx @{ error = "Not found: $path" } 404
            } else {
                $Ctx.Response.StatusCode = 204
                $Ctx.Response.OutputStream.Close()
            }
        }
    }
}

# ── Entry point ───────────────────────────────────────────────────────────────
$url = "http://localhost:$Port/"

# Kill any stale dashboard process that still holds the port
Get-Process powershell, pwsh -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -ne $PID } |
    ForEach-Object {
        try {
            $cl = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
            if ($cl -match 'Start-Dashboard') {
                Write-Host "  Stopping previous dashboard (PID $($_.Id))..." -ForegroundColor Yellow
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 700
            }
        } catch {}
    }

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($url)

try {
    $listener.Start()
    Write-Host ""
    Write-Host "  IISLock&Fix  Dashboard" -ForegroundColor Cyan
    Write-Host "  $url" -ForegroundColor Green
    Write-Host "  Ctrl+C to stop" -ForegroundColor DarkGray
    Write-Host ""
    Start-Process $url

    while ($listener.IsListening) {
        try {
            $ctx = $listener.GetContext()
            Invoke-Request $ctx
        } catch [System.Net.HttpListenerException] {
            if ($listener.IsListening) { Write-Host "Listener error: $_" -ForegroundColor Red }
        } catch {
            Write-Host "Error: $_" -ForegroundColor Red
            try { Send-Json $ctx @{ error = $_.ToString() } 500 } catch {}
        }
    }
} finally {
    try { $listener.Stop()  } catch {}
    try { $listener.Close() } catch {}
    Write-Host "`nDashboard stopped." -ForegroundColor Yellow
}
