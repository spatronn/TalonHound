param(
  [string]$EngineUrl = "http://192.168.1.251/api/sysmon/events",
  [string]$EngineHost = "192.168.1.251",
  [int]$IntervalSeconds = 30,
  [int]$BatchSize = 200
)

$ErrorActionPreference = "Stop"

$stateFile = "C:\ProgramData\SysmonAgent\state.json"
$stateDir = Split-Path $stateFile -Parent

if (-not (Test-Path $stateDir)) {
  New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
}

function Get-LatestRecordId {
  try {
    $latest = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3 } -MaxEvents 1 -ErrorAction Stop
    if ($latest) { return [long]$latest.RecordId }
    return 0
  } catch {
    return 0
  }
}

if (-not (Test-Path $stateFile)) {
  @{ lastRecordId = (Get-LatestRecordId) } | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8
}

function Get-State {
  try {
    $s = Get-Content $stateFile -Raw | ConvertFrom-Json
    if ($null -eq $s.lastRecordId) { return [pscustomobject]@{ lastRecordId = 0 } }
    return $s
  } catch {
    return [pscustomobject]@{ lastRecordId = 0 }
  }
}

function Save-State([long]$recordId) {
  @{ lastRecordId = $recordId } | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8
}

function Is-SelfNoise($processName, $destinationIp, $destinationPort, $engineHost) {
  $p = [string]$processName
  $dip = [string]$destinationIp
  $dpt = [string]$destinationPort

  if ([string]::IsNullOrWhiteSpace($dip)) { return $false }

  $isAgentProcess = ($p -ieq 'powershell.exe' -or $p -ieq 'pwsh.exe')
  $isEngineDest = ($dip -eq $engineHost)
  $isHttpPort = ($dpt -eq '80' -or $dpt -eq '443')

  return ($isAgentProcess -and $isEngineDest -and $isHttpPort)
}

Write-Host "Sysmon mini agent started. Sending every $IntervalSeconds sec -> $EngineUrl"

while ($true) {
  try {
    $state = Get-State
    $lastRecordId = [long]$state.lastRecordId

    $events = Get-WinEvent -FilterHashtable @{
      LogName = 'Microsoft-Windows-Sysmon/Operational'
      Id = 3
    } -MaxEvents 500 -ErrorAction SilentlyContinue |
      Where-Object { [long]$_.RecordId -gt $lastRecordId } |
      Sort-Object RecordId |
      Select-Object -First $BatchSize

    if ($events -and $events.Count -gt 0) {
      $mapped = foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
          $data[$d.Name] = $d.'#text'
        }

        $procName = [System.IO.Path]::GetFileName($data.Image)
        $dstIp = $data.DestinationIp
        $dstPort = $data.DestinationPort

        if (Is-SelfNoise -processName $procName -destinationIp $dstIp -destinationPort $dstPort -engineHost $EngineHost) {
          continue
        }

        [PSCustomObject]@{
          event_time       = $e.TimeCreated.ToString('o')
          host_name        = $env:COMPUTERNAME
          username         = $data.User
          process_name     = $procName
          process_id       = $data.ProcessId
          destination_ip   = $dstIp
          destination_port = $dstPort
          protocol         = $data.Protocol
          record_id        = [long]$e.RecordId
        }
      }

      $eventList = @($mapped)

      if ($eventList.Count -gt 0) {
        $body = @{ events = $eventList } | ConvertTo-Json -Depth 6
        $resp = Invoke-RestMethod -Uri $EngineUrl -Method Post -ContentType 'application/json' -Body $body
        Write-Host ("[{0}] found={1} sent={2} queued={3} jobId={4}" -f (Get-Date), $events.Count, $eventList.Count, $resp.queued, $resp.jobId)
      } else {
        Write-Host ("[{0}] found={1} sent=0 (all filtered as self-noise)" -f (Get-Date), $events.Count)
      }

      $maxRecordId = ($events | Measure-Object -Property RecordId -Maximum).Maximum
      Save-State ([long]$maxRecordId)
    } else {
      Write-Host ("[{0}] no new ID=3 events" -f (Get-Date))
    }
  } catch {
    Write-Warning ("[{0}] agent error: {1}" -f (Get-Date), $_.Exception.Message)
  }

  Start-Sleep -Seconds $IntervalSeconds
}
