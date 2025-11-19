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
        [string]$Phase  # "before" (baseline)
    )

    Write-Host "[*] Running HTTP scan ($Phase) on $Url"

    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
    } catch {
        $msg = "Error: could not reach $Url : $($_.Exception.Message)"
        Write-Host $msg
        $msg | Set-Content $OutputPath
        return
    }

    $headers = $resp.Headers

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

    # HSTS
    if ($headers["Strict-Transport-Security"]) {
        Add-Content $OutputPath "[OK] HSTS present: $($headers["Strict-Transport-Security"])"
    } else {
        Add-Content $OutputPath "[X] Missing HSTS (Strict-Transport-Security)"
    }

    # Clickjacking: X-Frame-Options or CSP frame-ancestors
    $hasXfo = $false
    $hasFrameAncestors = $false

    if ($headers["X-Frame-Options"]) {
        $hasXfo = $true
    }

    if ($headers["Content-Security-Policy"]) {
        if ($headers["Content-Security-Policy"] -match "frame-ancestors") {
            $hasFrameAncestors = $true
        }
    }

    if ($hasXfo -or $hasFrameAncestors) {
        Add-Content $OutputPath "[OK] Clickjacking protection present (X-Frame-Options and/or CSP frame-ancestors)"
    } else {
        Add-Content $OutputPath "[X] No Clickjacking protection (no X-Frame-Options and no CSP frame-ancestors)"
    }

    # X-Content-Type-Options
    if ($headers["X-Content-Type-Options"] -and $headers["X-Content-Type-Options"] -match "nosniff") {
        Add-Content $OutputPath "[OK] X-Content-Type-Options: nosniff present"
    } else {
        Add-Content $OutputPath "[X] Missing X-Content-Type-Options: nosniff"
    }

    # Referrer-Policy
    if ($headers["Referrer-Policy"]) {
        Add-Content $OutputPath "[OK] Referrer-Policy present: $($headers["Referrer-Policy"])"
    } else {
        Add-Content $OutputPath "[X] Missing Referrer-Policy header"
    }

    # Fingerprinting: Server / X-Powered-By
    $server = $headers["Server"]
    $xPoweredBy = $headers["X-Powered-By"]

    if ($server) {
        Add-Content $OutputPath "[!] Server header present: $server"
        Add-Content $OutputPath "    Recommendation: hide or generalize this value."
    } else {
        Add-Content $OutputPath "[OK] No Server header"
    }

    if ($xPoweredBy) {
        Add-Content $OutputPath "[!] X-Powered-By header present: $xPoweredBy"
        Add-Content $OutputPath "    Recommendation: remove it to reduce fingerprinting."
    } else {
        Add-Content $OutputPath "[OK] No X-Powered-By header"
    }

    Add-Content $OutputPath ""
    Add-Content $OutputPath "=== End of report ($Phase) ==="
}

# ------------ TLS scan (baseline only) ------------
function Run-TlsScan {
    param(
        [string]$Host,
        [int]$Port,
        [string]$OutputPathPrefix,
        [string]$Phase
    )

    Write-Host "[*] Running TLS scan ($Phase) on $Host`:$Port"

    $nmapOut   = "${OutputPathPrefix}_nmap_${Phase}.txt"
    $sslyzeOut = "${OutputPathPrefix}_sslyze_${Phase}.txt"

    # Nmap
    try {
        $cmd = "nmap -p $Port --script ssl-enum-ciphers $Host"
        Write-Host "   Nmap: $cmd"
        cmd /c $cmd > $nmapOut 2>&1
    } catch {
        "Nmap scan failed: $($_.Exception.Message)" | Set-Content $nmapOut
    }

    # SSLyze
    try {
        $cmd2 = "sslyze --regular $Host`:$Port"
        Write-Host "   SSLyze: $cmd2"
        cmd /c $cmd2 > $sslyzeOut 2>&1
    } catch {
        "SSLyze scan failed or not installed: $($_.Exception.Message)" | Set-Content $sslyzeOut
    }
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
if ($policy.TlsScan.Enabled -eq $true) {
    $tlsPrefix = Join-Path $ReportsFolder "tls"
    Run-TlsScan -Host $policy.TlsScan.Host -Port $policy.TlsScan.Port -OutputPathPrefix $tlsPrefix -Phase "before"
}

Write-Host ""
Write-Host "=== IIS Lock & Fix - baseline completed ==="
Write-Host "HTTP baseline report: $baselineHttpReport"
Write-Host "If TLS scan is enabled: tls_nmap_before.txt / tls_sslyze_before.txt under $ReportsFolder"
