# Windows Demo Config (Sysmon + Signal Engine)

This profile is for **demo / test lab** usage.
It enables broad Sysmon visibility and forwards telemetry to the signal engine.

## 1) Sysmon config file

Use this file from repo:

- `reports/sysmon-full-network.xml`

Content summary:
- `ProcessCreate` enabled
- `NetworkConnect` enabled
- `DnsQuery` enabled
- `DestinationPort != 0` filter

## 2) Apply Sysmon config on Windows

Run as Administrator:

```powershell
cd C:\Users\safa\Downloads\Sysmon
.\Sysmon64.exe -c C:\Demo\sysmon-full-network.xml
Restart-Service sysmon64
```

Verify config update event:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=16; StartTime=(Get-Date).AddMinutes(-5)} | Select-Object -First 5 TimeCreated, Id, Message
```

Verify network events (ID=3):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=(Get-Date).AddMinutes(-2)} | Select-Object -First 20 TimeCreated, RecordId, Message
```

## 3) Telemetry forwarder (agent)

Use this file from repo:

- `reports/sysmon-agent.ps1`

Recommended runtime command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Demo\sysmon-agent.ps1"
```

Default target:

- `http://192.168.1.251/api/sysmon/events`

## 4) Platform-side verification

On demo host:

```bash
cd /opt/demo-runbook
docker compose logs -f --tail=100 signal-engine
```

Expected logs:

- `job ... completed { inserted: X, skipped: Y }`

## 5) Analytics verification

UI path:

- `Analytics`

Expected:
- Connected Data Sources: `1`
- Source: `Sysmon (Windows)`
- Last 10 Raw Events populated

## Notes

- This profile is intentionally noisy for demonstration.
- For production, add filtering, deduplication, and stricter source controls.
