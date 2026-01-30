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
$PushApiKey         = ''                                      # Optional fallback (lab only). Prefer CredMan or $env:PUSH_API_TOKEN
$ServiceGatewayHost = '127.0.0.1'                             # Service Gateway IP/FQDN
$ServiceGatewayPort = 6531                                    # CEF/TCP (use 6514 for TLS when ready)
$StateFilePath      = 'C:\ProgramData\PushToTrend\state.json' # Persists last poll time (UTC)
$LogFilePath        = 'C:\ProgramData\PushToTrend\run.log'    # Operational log
$LookbackMinutes    = 10                                      # Used when no state yet
$PageLimit          = 200                                     # Push page size
$MaxPages           = 20                                      # Safety cap (avoid very long runs)
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

# ===================== Windows Credential Manager Helpers =====================
# C# P/Invoke for CredRead/CredFree (no 'using' placement issues)
Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NATIVE_CREDENTIAL
{
    public UInt32 Flags;
    public UInt32 Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob;
    public UInt32 Persist;
    public UInt32 AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

public static class NativeCredMan
{
    [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CredRead(string target, UInt32 type, UInt32 reservedFlag, out IntPtr credentialPtr);

    [DllImport("Advapi32.dll", SetLastError=true)]
    public static extern bool CredFree(IntPtr cred);
}
"@

function Get-CredentialManagerSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TargetName  # e.g. 'PushSecurity.ApiKey'
    )
    $CRED_TYPE_GENERIC = [uint32]1
    $ptr = [IntPtr]::Zero
    try {
        $ok = [NativeCredMan]::CredRead($TargetName, $CRED_TYPE_GENERIC, 0, [ref]$ptr)
        if (-not $ok -or $ptr -eq [IntPtr]::Zero) { return $null }

        # PS 5.1-friendly PtrToStructure overload
        $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [NATIVE_CREDENTIAL])

        if ($cred.CredentialBlobSize -le 0 -or $cred.CredentialBlob -eq [IntPtr]::Zero) { return $null }

        $bytes = New-Object byte[] ($cred.CredentialBlobSize)
        [System.Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $cred.CredentialBlobSize)

        # Generic credential blobs are UTF-16 (Unicode)
        $secret = [System.Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)
        return $secret
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [NativeCredMan]::CredFree($ptr) | Out-Null
        }
    }
}

function Get-PushApiKey {
    <#
      Resolution order:
        1) Windows Credential Manager (Generic) => Target: 'PushSecurity.ApiKey'
        2) Environment variable $env:PUSH_API_TOKEN
        3) Script variable $PushApiKey (hardcoded fallback)
      Logs the chosen source; never logs the secret itself.
    #>
    [CmdletBinding()]
    param(
        [string]$CredTargetName = 'PushSecurity.ApiKey'
    )

    # 1) Credential Manager (per-user vault of the Scheduled Task identity)
    try {
        $fromCred = Get-CredentialManagerSecret -TargetName $CredTargetName
        if (-not [string]::IsNullOrWhiteSpace($fromCred)) {
            Write-Log "API key source: CredentialManager ($CredTargetName)"
            return $fromCred
        } else {
            Write-Log "CredentialManager target '$CredTargetName' not found for current user." 'WARN'
        }
    } catch {
        Write-Log ("CredentialManager read error: {0}" -f $_.Exception.Message) 'WARN'
    }

    # 2) Environment variable
    if (-not [string]::IsNullOrWhiteSpace($env:PUSH_API_TOKEN)) {
        Write-Log "API key source: Environment (PUSH_API_TOKEN)"
        return $env:PUSH_API_TOKEN
    } else {
        Write-Log "Environment variable PUSH_API_TOKEN not set." 'WARN'
    }

    # 3) Script variable fallback (lab/testing)
    if (-not [string]::IsNullOrWhiteSpace($script:PushApiKey)) {
        Write-Log "API key source: Script variable (`$PushApiKey). Consider migrating to CredMan or env for security."
        return $script:PushApiKey
    }

    Write-Log "No API key found via Credential Manager, environment, or script variable. Aborting." 'ERROR'
    return $null
}
# =================== End Credential Manager + Resolver ========================

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
function Convert-ToCefEscaped {
    [CmdletBinding()]
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $v = $Value -replace '\\', '\\\\'
    $v = $v -replace '\|', '\|'
    $v = $v -replace '=', '\='
    return $v
}
function Convert-SeverityToCef([string]$s) {
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
function Send-SyslogTcp([string]$Message) {
    # Facility 16 (local0) -> 16*8=128; Severity 6 (informational) -> 6; PRI=<134>
    $pri = '<134>'
    $hdr = "{0} {1}" -f (Get-Date -Format 'MMM dd HH:mm:ss'), $env:COMPUTERNAME
    $payload = "$pri$hdr $Message`n"
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
function New-CefMessage {
    [CmdletBinding()]
    param($Detection)

    $sev = Convert-SeverityToCef $Detection.severity

    $rt = $null
    if ($Detection.creationTimestamp -is [int]) {
        $rt = ([DateTime]'1970-01-01Z').AddSeconds($Detection.creationTimestamp).ToUniversalTime().ToString('o')
    }

    # detectionType becomes the event "name"
    $hdr = "CEF:0|Push Security|SaaS Identity Security|1.0|PUSH_DETECTION|{0}|{1}|" -f (Convert-ToCefEscaped $Detection.detectionType), $sev

    $ext = @()
    if ($Detection.id) { $ext += "externalId=$(Convert-ToCefEscaped $Detection.id)" }
    if ($rt)           { $ext += "rt=$(Convert-ToCefEscaped $rt)" }
    if ($Detection.response) {
        $ext += "cs5Label=Response cs5=$(Convert-ToCefEscaped $Detection.response)"
    }
    if ($null -ne $Detection.archived) {
        $ext += "cs6Label=Archived cs6=$(Convert-ToCefEscaped ([string]$Detection.archived))"
    }
    if ($Detection.employee -and $Detection.employee.email) {
        $ext += "cs1Label=User cs1=$(Convert-ToCefEscaped $Detection.employee.email)"
    }

    return $hdr + ($ext -join ' ')
}

# Track last API pull success for state advancement
$script:LastPullSucceeded = $false

# ---- Pull detections with paging ----
function Get-PushDetections([DateTime]$sinceUtc) {
    $script:LastPullSucceeded = $false

    # Resolve API key via CredMan -> env -> script variable
    $key = Get-PushApiKey
    if ([string]::IsNullOrWhiteSpace($key)) {
        return ,@()  # error already logged in resolver
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

# Determine the effective start time
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
        $cef = New-CefMessage -Detection $d
        Send-SyslogTcp -Message $cef
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