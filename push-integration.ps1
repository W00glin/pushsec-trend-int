
<#
Push Security -> Trend Vision One (Third‑Party Log Collection)
Polls Push REST v1 /detections and forwards as CEF via Syslog TCP
PowerShell 5.1 compatible
#>

[CmdletBinding()]
param(
    [int]$BackfillHours = 0  # 0 = use saved state; >0 = override lookback just for this run
)

$ErrorActionPreference = 'Stop'

# -------------------- USER CONFIGURATION --------------------
$PushApiBaseUrl     = 'https://api.pushsecurity.com/v1'       # REST v1
$PushApiKey         = 'ADD_API_KEY_HERE'                      # or set $env:PUSH_API_TOKEN
$ServiceGatewayHost = '127.0.0.1'                             # Service Gateway IP/FQDN
$ServiceGatewayPort = 6531                                    # CEF/TCP
$StateFilePath      = 'C:\ProgramData\PushToTrend\state.json' # Persists last poll time (UTC)
$LogFilePath        = 'C:\ProgramData\PushToTrend\run.log'    # Operational log
$LookbackMinutes    = 10                                      # used when no state yet
$PageLimit          = 200                                     # Push page size
$MaxPages           = 20                                      # safety cap
$TimeoutSeconds     = 30
# ------------------------------------------------------------

# Ensure folders exist (state + log)
$null = New-Item -ItemType Directory -Path (Split-Path $StateFilePath) -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path (Split-Path $LogFilePath)  -Force -ErrorAction SilentlyContinue

# ---- Logging ----
function Write-Log {
    param([string]$Msg, [string]$Level='INFO')
    try {
        $ts = (Get-Date).ToString('s')
        Add-Content -Path $LogFilePath -Value "[$ts][$Level] $Msg" -Encoding UTF8
    } catch {}
}

# ---- State ----
function Get-LastTimestampUtc {
    if (Test-Path $StateFilePath) {
        try {
            $raw = Get-Content $StateFilePath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $j = $raw | ConvertFrom-Json
                if ($j.lastPollUtc) { return [DateTime]::Parse($j.lastPollUtc).ToUniversalTime() }
            }
        } catch { Write-Log "Failed to parse state file: $_" 'WARN' }
    }
    return (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes)
}
function Set-LastTimestampUtc([DateTime]$dt) {
    @{ lastPollUtc = $dt.ToString('o') } |
        ConvertTo-Json |
        Set-Content -Path $StateFilePath -Encoding UTF8
}

# ---- Helpers ----
function UnixSeconds([DateTime]$dt) {
    return [int][Math]::Floor( ($dt.ToUniversalTime() - [DateTime]'1970-01-01T00:00:00Z').TotalSeconds )
}
# Helps prevent pipes and other characters breaking parsing
function CefEscape([string]$v) {
    if ($null -eq $v) { return '' }
    $v = $v -replace '\\', '\\\\'
    $v = $v -replace '\|', '\|'
    $v = $v -replace '=', '\='
    return $v
}
function SeverityToCef([string]$s) {
    # PowerShell 5.1-safe null/default handling
    if ([string]::IsNullOrWhiteSpace($s)) { $s = 'MEDIUM' }
    switch ($s.ToUpperInvariant()) {
        'LOW'      { 3 }
        'MEDIUM'   { 5 }
        'HIGH'     { 8 }
        'CRITICAL' { 10 }
        default    { 5 }
    }
}

# ---- Syslog (CEF/TCP) ----
function Send-SyslogTcp([string]$msg) {
    $pri = '<134>' # Facility 16 (local use) × 8 = 128 | Severity 6 (informational) = 6 | Total = 134 - considering changing to be more than `informational`
    $hdr = "{0} {1}" -f (Get-Date -Format 'MMM dd HH:mm:ss'), $env:COMPUTERNAME
    $payload = "$pri$hdr $msg`n"
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.SendTimeout    = 5000
        $client.ReceiveTimeout = 5000
        $client.Connect($ServiceGatewayHost, $ServiceGatewayPort)
        $bytes  = [Text.Encoding]::UTF8.GetBytes($payload)
        $stream = $client.GetStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally {
        if ($client) { $client.Close() }
    }
}

# ---- CEF builder for Push detections ----
function Build-Cef($detection) {
    $sev = SeverityToCef $detection.severity
    $rt  = $null
    if ($detection.creationTimestamp -is [int]) {
        $rt = ([DateTime]'1970-01-01Z').AddSeconds($detection.creationTimestamp).ToUniversalTime().ToString('o')
    }

    # detectionType becomes the event "name", considering changing from `SaaS Indentity Security` to `Push Security`
    $hdr = "CEF:0|Push Security|SaaS Identity Security|1.0|PUSH_DETECTION|{0}|{1}|" -f (CefEscape $detection.detectionType), $sev

    $ext = @()
    if ($detection.id) { $ext += "externalId=$(CefEscape $detection.id)" }
    if ($rt)           { $ext += "rt=$(CefEscape $rt)" }
    if ($detection.response) {
        $ext += "cs5Label=Response cs5=$(CefEscape $detection.response)"
    }
    if ($null -ne $detection.archived) {
        $ext += "cs6Label=Archived cs6=$(CefEscape ([string]$detection.archived))"
    }
    if ($detection.employee -and $detection.employee.email) {
        $ext += "cs1Label=User cs1=$(CefEscape $detection.employee.email)"
    }

    return $hdr + ($ext -join ' ')
}

# Track last API pull success for state advancement
$script:LastPullSucceeded = $false

# ---- Pull detections with paging ----
function Get-PushDetections([DateTime]$sinceUtc) {
    $script:LastPullSucceeded = $false

    $key = if (-not [string]::IsNullOrWhiteSpace($env:PUSH_API_TOKEN)) { $env:PUSH_API_TOKEN } else { $PushApiKey }
    if ([string]::IsNullOrWhiteSpace($key)) {
        Write-Log "Missing API key (env:PUSH_API_TOKEN or `$PushApiKey)" 'ERROR'
        return ,@()
    }

    $headers = @{
        'x-api-key' = $key
        'Accept'    = 'application/json'
    }

    $sinceUnix = UnixSeconds $sinceUtc
    $nextToken = $null
    $all       = @()
    $page      = 0

    do {
        $page++
        if ($page -gt $MaxPages) {
            Write-Log "Pagination stop: reached $MaxPages pages." 'WARN'
            break
        }

        # Build query
        # Add optional server-side filters here, e.g.:
        #   $qs += "&severity=HIGH"
        #   $qs += "&archived=false"
        #   $qs += "&detectionType=PHISHING"
        $qs = "creationTimestampAfter=$sinceUnix&limit=$PageLimit"
        if ($nextToken) { $qs += "&nextToken=$([uri]::EscapeDataString($nextToken))" }

        $url = "$PushApiBaseUrl/detections?$qs"
        # Write-Log ("GET {0}" -f $url)  # uncomment to troubleshoot

        try {
            $resp = Invoke-RestMethod -Method GET -Uri $url -Headers $headers -TimeoutSec $TimeoutSeconds
        } catch {
            # Add status + body to logs to ease debugging
            $statusCode = $null
            $body       = $null
            if ($_.Exception.Response) {
                try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
                try {
                    $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $body = $sr.ReadToEnd()
                    $sr.Close()
                } catch {}
            }
            Write-Log ("Push API error: Status={0} Body={1} Error={2}" -f $statusCode, $body, $_.Exception.Message) 'ERROR'
            return ,$all
        }

        if ($resp.result) { $all += $resp.result }

        if ($resp.paging -and $resp.paging.moreResults -eq $true -and $resp.paging.nextToken) {
            $nextToken = [string]$resp.paging.nextToken
        } else {
            $nextToken = $null
        }

    } while ($nextToken)

    $script:LastPullSucceeded = $true
    return ,$all
}

# --------------------------- MAIN ---------------------------
Write-Log "Run started."

# Determines the effective start time
if ($BackfillHours -gt 0) {
    $effectiveUtc = (Get-Date).ToUniversalTime().AddHours(-$BackfillHours)
    Write-Log ("Backfill mode: last {0}h starting {1}" -f $BackfillHours, $effectiveUtc.ToString('o'))
} else {
    $effectiveUtc = Get-LastTimestampUtc
    Write-Log ("Polling from UTC {0}" -f $effectiveUtc.ToString('o'))
}

# Skew guard: never query "into the future"
$nowUtc = (Get-Date).ToUniversalTime()
if ($effectiveUtc -gt $nowUtc) {
    $effectiveUtc = $nowUtc.AddMinutes(-$LookbackMinutes)
    Write-Log "Adjusted effectiveUtc to now - lookback (skew guard)."
}

# Pull detections and forward
$detections = Get-PushDetections $effectiveUtc
Write-Log ("Fetched {0} detections." -f $detections.Count)

$sent = 0
foreach ($d in $detections) {
    try {
        $cef = Build-Cef $d
        Send-SyslogTcp $cef
        $sent++
    } catch {
        Write-Log ("Failed to process detection {0}: {1}" -f $d.id, $_.Exception.Message) 'WARN'
    }
}

# Advance state only if not backfilling and the last API pull succeeded
if ($BackfillHours -eq 0 -and $script:LastPullSucceeded) {
    Set-LastTimestampUtc $nowUtc
    Write-Log "State advanced."
} else {
    if ($BackfillHours -gt 0) { Write-Log "Backfill run: state not advanced." }
}

Write-Log ("Run completed. Forwarded {0} detections." -f $sent)
