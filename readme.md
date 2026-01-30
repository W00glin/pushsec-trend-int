
# Push Security → Trend Vision One (CEF via Syslog)  
**PowerShell integration to ingest Push Security detections into Trend Micro Vision One Third‑Party Log Collection**

---

## Overview

This tool polls the **[Push Security REST API](https://pushsecurity.com/help/audience/engineering/rest-v1)** for **detections** and forwards each detection to **Trend Micro Vision One** using **CEF over Syslog (TCP)** via a **Service Gateway** (Third‑Party Log Collection). It supports:

- PowerShell **5.1** (Windows)
- **x-api-key** authentication
- **/v1/detections** endpoint
- **creationTimestampAfter** (UNIX seconds) time filter
- Pagination (**limit** + **nextToken**)
- **Backfill** mode to bootstrap historical data
- CEF output with useful fields (User, Response, Archived, Severity, Event Time)
- On‑prem deployment (no cloud compute or SOAR required)

## To Do -
- [X] Re-work API key so it is not hardcoded, use Windows Credential Manager
- [ ] Expand ingest scope (Findings, Apps, etc)
- [ ] *Nix option for non-Windows environments
- [ ] Documentation for adding it as a scheduled task to run
- [ ] Retry for network latency/hiccups
---

## Architecture (at a glance)
```
Push Security (REST API /v1/detections)
        |
        |  HTTPS (x-api-key)
        v
Windows server (PowerShell script)
        |
        |  CEF over Syslog (TCP 6531 or TLS 6514)
        v
Trend Vision One Service Gateway
        |
        v
Trend Vision One (Third‑Party Log Collection / Log Search)
```
---
## Prerequisites
 ### Push Security

- Push Security account with REST API access
- Read‑only API key enabled for detections

 ### Trend Vision One

- Service Gateway deployed and online
- Third‑Party Log Collection configured:
    - Format: `CEF`
    - Protocol: `TCP` (or `TLS`)
    - Port: `6531` (or `6514` for `TLS`) or whichever port you would like
    - Timezone: `UTC+00:00 (Etc/GMT)`

### Windows Host

- Windows PowerShell 5.1
- Network connectivity to:
    - `api.pushsecurity.com:443`  
    - Service Gateway on the chosen syslog port
---
## Configuration
Edit the User Configuration section at the top of the script:

- PushApiBaseUrl = `https://api.pushsecurity.com/v1`
- PushApiKey = `YOUR_PUSH_API_KEY`
- ServiceGatewayHost = `10.10.10.50`
- ServiceGatewayPort = `6531`
- StateFilePath = `C:\ProgramData\PushToTrend\state.json`
- LogFilePath = `C:\ProgramData\PushToTrend\run.log`
- LookbackMinutes = `10`

### API Key Handling (Testing only)
Instead of hard‑coding the API key, set it as an environment variable for the account running the script:

Set the environment variable `PUSH_API_TOKEN` to your key.
The script prefers `PUSH_API_TOKEN if` present.
Examples -
```
$env:PUSH_API_TOKEN = '<YOUR_PUSH_API_KEY>'
```
To test and confirm that is working, you should then run:
```powershell
echo $env
```
And the output should match the PSK you just entered.

#### Windows Credential Manager (Recommended option)
To avoid having hardcoded credentials in the script, or to having the API live in the `$env` consider leveraging the Windows Credential Manage with a dedciated service account and limiting its permissions. To add the API key as a `Generic Credential` under the Windows Credential Manager do the following:
- Log on as DOMAIN\svc_PushTrend (temporarily), or open a process as that account.
- Save a Generic Credential into that user’s Windows Credential Manager:
```
Target (name): PushSecurity.ApiKey
User name field: can be a static label like api_key ( this is not going to be used)
Password/secret: your Push API key (read‑only is fine)
```
- Close the session; the secret is now DPAPI‑protected under that profile.

---
## First Run (Backfill)
For the initial run, perform a backfill to pull historical detections and validate the entire pipeline.

Run the script with `-BackfillHours` set, for example 24 hours. For example -
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\Script\push-integration.ps1" -BackfillHours 24
```

This pulls detections from the previous 24 hours and does not advance the saved state.

Check the log file at:
`C:\ProgramData\PushToTrend\run.log`
Expected entries include:
```
Run started
Backfill mode enabled
Fetched N detections
Forwarded N detections
```

## Normal Operation (Incremental Mode)
After a successful backfill, run the script without `BackfillHours`.
In this mode:

The script reads the last successful poll time from `state.json`
Only new detections are retrieved
The state file is advanced on success

---

## Scheduling
Run the script every 5–10 minutes using Windows Task Scheduler.
Ensure the scheduled task runs under an account that:

- Can access the script directory
- Has network access to the Service Gateway
- Has the `PUSH_API_TOKEN` environment variable set (if used)

---

## Log and State Files
Operational log:
`C:\ProgramData\PushToTrend\run.log`

Poll cursor state:
`C:\ProgramData\PushToTrend\state.json`

If you need to re‑bootstrap, delete or edit `state.json` or run a backfill again.

CEF Field Mapping
Each Push detection is sent as a CEF event.
CEF Header fields:
```
Vendor: Push Security
Product: SaaS Identity Security
Version: 1.0
Signature: PUSH_DETECTION
Name: detectionType (PHISHING, BLOCKED_URL, etc.)
Severity mapped to CEF 0–10
```

---

## CEF Extensions:
```
externalId = Push detection ID
rt = detection creation time (UTC, ISO‑8601)
cs1Label = User
cs1 = employee.email
cs5Label = Response
cs5 = BLOCKED / NOT_BLOCKED / etc.
cs6Label = Archived
cs6 = True / False
```
Severity mapping:
```
LOW → 3
MEDIUM → 5
HIGH → 8
CRITICAL → 10
```

---

## Backfill vs Stateful Operation
### Backfill Mode

- Overrides the saved cursor
- Pulls historical data for validation or recovery
- Does not advance the state file


### Stateful Mode (Default)

- Uses timestamp stored in state.json
- Prevents duplicate ingestion
- Intended for scheduled operation

### Recommended usage:

Run once in backfill mode. Switch to normal scheduled runs.

## Troubleshooting
### No detections returned:
- Run a backfill (`-BackfillHours 24`)
- Verify API directly using a single detection request, like so -
```PowerShell
Invoke-RestMethod -Uri https://api.pushsecurity.com/v1/detections?limit=1 `
  -Headers @{ 'x-api-key'='<key>'; 'Accept'='application/json' }
```

### Syslog connection failures:

- Verify Service Gateway IP and port
- Ensure collector is listening on the configured port, like so -
```PowerShell
test-netconnection -Computername 127.0.0.1 -Port 6531  
```

### Authentication errors:

- Verify `x‑api‑key` header
- Confirm the key is REST‑enabled
- Re‑copy the key to avoid hidden whitespace

### Incorrect timestamps:

- Confirm collector timezone is `UTC+00:00`
- Push timestamps are converted to UTC before being sent

---
Made by humans with some AI help.