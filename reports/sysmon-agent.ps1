param(
  [string]$EngineUrl = "http://192.168.1.251/api/sysmon/events",
  [string]$IngestApiKey = $env:INGEST_API_KEY,
  [int]$IntervalSeconds = 30,
  [int]$BatchSize = 500,
  [int]$LookbackSeconds = 60
)

$ErrorActionPreference = "Stop"

Write-Host "Sysmon mini agent started. Every $IntervalSeconds sec -> $EngineUrl (lookback=$LookbackSeconds sec, duplicates allowed)"

while ($true) {
  try {
    $startTime = (Get-Date).AddSeconds(-1 * $LookbackSeconds)

    $events = Get-WinEvent -FilterHashtable @{
      LogName   = 'Microsoft-Windows-Sysmon/Operational'
      Id        = 3
      StartTime = $startTime
    } -ErrorAction SilentlyContinue |
      Sort-Object TimeCreated |
      Select-Object -First $BatchSize

    if ($events -and $events.Count -gt 0) {
      $mapped = foreach ($e in $events) {
        $xml = [xml]$e.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) {
          $data[$d.Name] = $d.'#text'
        }

        [PSCustomObject]@{
          event_time       = $e.TimeCreated.ToString('o')
          host_name        = $env:COMPUTERNAME
          username         = $data.User
          process_name     = [System.IO.Path]::GetFileName($data.Image)
          process_id       = $data.ProcessId
          destination_ip   = $data.DestinationIp
          destination_port = $data.DestinationPort
          protocol         = $data.Protocol
          record_id        = [long]$e.RecordId
          source_log       = 'Microsoft-Windows-Sysmon/Operational'
          source_event_id  = 3
        }
      }

      $eventList = @($mapped)
      $body = @{ events = $eventList } | ConvertTo-Json -Depth 6
      $headers = @{ 'Content-Type' = 'application/json' }
      if ($IngestApiKey) { $headers['X-Ingest-Key'] = $IngestApiKey }
      $resp = Invoke-RestMethod -Uri $EngineUrl -Method Post -Headers $headers -Body $body

      Write-Host ("[{0}] found={1} sent={2} queued={3} jobId={4}" -f (Get-Date), $events.Count, $eventList.Count, $resp.queued, $resp.jobId)
    } else {
      Write-Host ("[{0}] no ID=3 event in last {1}s" -f (Get-Date), $LookbackSeconds)
    }
  } catch {
    Write-Warning ("[{0}] agent error: {1}" -f (Get-Date), $_.Exception.Message)
  }

  Start-Sleep -Seconds $IntervalSeconds
}
