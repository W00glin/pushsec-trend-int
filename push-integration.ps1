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
$PushApiKey         = 'REDACTED'
$ServiceGatewayHost = '127.0.0.1'
$ServiceGatewayPort = 6531
$StateFilePath      = 'C:\ProgramData\PushToTrend\state.json'
$LogFilePath        = 'C:\ProgramData\PushToTrend\run.log'
$LookbackMinutes    = 10
$PageLimit          = 500
$MaxPages           = 20
$TimeoutSeconds     = 30
# ------------------------------------------------------------

$null = New-Item -ItemType Directory -Path (Split-Path $StateFilePath) -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path (Split-Path $LogFilePath)  -Force -ErrorAction SilentlyContinue

function Write-Log {
    param([string]$Msg, [string]$Level='INFO')
    try {
        $ts = (Get-Date).ToString('s')
        Add-Content -Path $LogFilePath -Value "[$ts][$Level] $Msg" -Encoding UTF8
    } catch {}
}

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

function UnixSeconds([DateTime]$dt) {
    return [int][Math]::Floor( ($dt.ToUniversalTime() - [DateTime]'1970-01-01T00:00:00Z').TotalSeconds )
}

function CefEscape([string]$v) {
    if ($null -eq $v) { return '' }
    $v = $v -replace '\\', '\\\\'
    $v = $v -replace '\|', '\|'
    $v = $v -replace '=', '\='
    return $v
}

function SeverityToCef([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { $s = 'MEDIUM' }
    switch ($s.ToUpperInvariant()) {
        'LOW'      { 3 }
        'MEDIUM'   { 5 }
        'HIGH'     { 8 }
        'CRITICAL' { 10 }
        default    { 5 }
    }
}

function Send-SyslogTcp([string]$msg) {
    $pri = '<134>'
    $hdr = "{0} {1}" -f (Get-Date -Format 'MMM dd HH:mm:ss'), $env:COMPUTERNAME
    $payload = "$pri$hdr $msg`n"
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($ServiceGatewayHost, $ServiceGatewayPort)
        $bytes  = [Text.Encoding]::UTF8.GetBytes($payload)
        $stream = $client.GetStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally {
        if ($client) { $client.Close() }
    }
}

function Get-PushDetectionDetail($id, $headers) {
    try {
        $url = "$PushApiBaseUrl/detections/$id"
        return Invoke-RestMethod -Method GET -Uri $url -Headers $headers -TimeoutSec $TimeoutSeconds
    } catch {
        Write-Log ("Failed to get details for {0}: {1}" -f $id, $_.Exception.Message) 'WARN'
        return $null
    }
}

function Build-Cef($detection) {
    $sev = SeverityToCef $detection.severity

    $rt = $null
    if ($detection.creationTimestamp -is [int]) {
        $rt = ([DateTime]'1970-01-01Z').AddSeconds($detection.creationTimestamp).ToUniversalTime().ToString('o')
    }

    $hdr = "CEF:0|Push Security|SaaS Identity Security|1.0|PUSH_DETECTION|{0}|{1}|" -f (CefEscape $detection.detectionType), $sev

    $ext = @()

    if ($detection.id) { $ext += "externalId=$(CefEscape $detection.id)" }
    if ($rt)           { $ext += "rt=$(CefEscape $rt)" }
    if ($detection.browserId) { $ext += "deviceExternalId=$(CefEscape $detection.browserId)" }

    if ($detection.employee) {
        if ($detection.employee.email)     { $ext += "cs1Label=User cs1=$(CefEscape $detection.employee.email)" }
        if ($detection.employee.firstName) { $ext += "cs2Label=FirstName cs2=$(CefEscape $detection.employee.firstName)" }
        if ($detection.employee.lastName)  { $ext += "cs3Label=LastName cs3=$(CefEscape $detection.employee.lastName)" }
        if ($detection.employee.department){ $ext += "cs4Label=Department cs4=$(CefEscape $detection.employee.department)" }
        if ($detection.employee.location)  { $ext += "cs7Label=Location cs7=$(CefEscape $detection.employee.location)" }
    }

    if ($detection.response) {
        $ext += "cs5Label=Response cs5=$(CefEscape $detection.response)"
    }

    if ($null -ne $detection.archived) {
        $ext += "cs6Label=Archived cs6=$(CefEscape ([string]$detection.archived))"
    }

    # ✅ FIX: Always include msg field
    $summary = "{0} - {1}" -f $detection.detectionType, $detection.response
    $ext += "msg=$(CefEscape $summary)"

    # ✅ FIX: Use ONLY the first event (avoid duplicate keys)
    $ev = $detection.events | Select-Object -First 1
    if ($ev) {
        if ($ev.url)              { $ext += "request=$(CefEscape $ev.url)" }
        if ($ev.sourceIpAddress)  { $ext += "src=$(CefEscape $ev.sourceIpAddress)" }
        if ($ev.extensionName)    { $ext += "cs8Label=Extension cs8=$(CefEscape $ev.extensionName)" }
        if ($ev.phishingToolIndicator) { $ext += "cs9Label=PhishingTool cs9=$(CefEscape $ev.phishingToolIndicator)" }
        if ($ev.referrerUrl)      { $ext += "cs10Label=Referrer cs10=$(CefEscape $ev.referrerUrl)" }
    }

    # ✅ FIX: Preserve all URLs safely in ONE field
    $allUrls = ($detection.events | Where-Object { $_.url } | Select-Object -ExpandProperty url) -join ","
    if ($allUrls) {
        $ext += "cs11Label=AllUrls cs11=$(CefEscape $allUrls)"
    }

    return $hdr + ($ext -join ' ')
}

$script:LastPullSucceeded = $false

function Get-PushDetections([DateTime]$sinceUtc, $headers) {
    $script:LastPullSucceeded = $false

    $sinceUnix = UnixSeconds $sinceUtc
    $nextToken = $null
    $all       = @()
    $page      = 0

    do {
        $page++
        if ($page -gt $MaxPages) { break }

        $qs = "creationTimestampAfter=$sinceUnix&limit=$PageLimit"
        if ($nextToken) { $qs += "&nextToken=$([uri]::EscapeDataString($nextToken))" }

        $url = "$PushApiBaseUrl/detections?$qs"

        try {
            $resp = Invoke-RestMethod -Method GET -Uri $url -Headers $headers -TimeoutSec $TimeoutSeconds
        } catch {
            Write-Log "Push API error: $_" 'ERROR'
            return ,$all
        }

        if ($resp.result) { $all += $resp.result }

        if ($resp.paging -and $resp.paging.moreResults -and $resp.paging.nextToken) {
            $nextToken = $resp.paging.nextToken
        } else {
            $nextToken = $null
        }

    } while ($nextToken)

    $script:LastPullSucceeded = $true
    return ,$all
}

Write-Log "Run started."

$key = if (-not [string]::IsNullOrWhiteSpace($env:PUSH_API_TOKEN)) { $env:PUSH_API_TOKEN } else { $PushApiKey }
$headers = @{ 'x-api-key' = $key; 'Accept'='application/json' }

if ($BackfillHours -gt 0) {
    $effectiveUtc = (Get-Date).ToUniversalTime().AddHours(-$BackfillHours)
} else {
    $effectiveUtc = Get-LastTimestampUtc
}

$nowUtc = (Get-Date).ToUniversalTime()

$detections = Get-PushDetections $effectiveUtc $headers

$sent = 0
foreach ($d in $detections) {
    try {
        $full = Get-PushDetectionDetail $d.id $headers
        if ($full) { $d = $full }

        $cef = Build-Cef $d
        Send-SyslogTcp $cef
        $sent++
    } catch {
        Write-Log ("Failed detection {0}" -f $d.id) 'WARN'
    }
}

if ($BackfillHours -eq 0 -and $script:LastPullSucceeded) {
    Set-LastTimestampUtc $nowUtc
}

Write-Log ("Run completed. Forwarded {0} detections." -f $sent)