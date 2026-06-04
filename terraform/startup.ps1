Start-Sleep -Seconds 60

# retry until metadata server responds
$instanceName = $null
while (-not $instanceName) {
    try {
        $instanceName = Invoke-RestMethod `
            -Headers @{"Metadata-Flavor"="Google"} `
            -Uri "http://metadata.google.internal/computeMetadata/v1/instance/name" `
            -TimeoutSec 5
    } catch {
        Start-Sleep -Seconds 5
    }
}

$domain = "zayahdevelopment.com"
$publicip = "$instanceName.$domain"

$taskName = "Run Server"

Write-Output "Instance name: $instanceName"
Write-Output "Public domain: $publicip"

$task = Get-ScheduledTask -TaskName $taskName

$triggers  = $task.Triggers
$settings  = $task.Settings
$principal = $task.Principal

$oldAction = $task.Actions[0]
$exe = $oldAction.Execute

$newAction = New-ScheduledTaskAction `
    -Execute $exe `
    -Argument "--publicip $publicip"

$principal = New-ScheduledTaskPrincipal `
  -UserId "SYSTEM" `
  -LogonType ServiceAccount `
  -RunLevel Highest
  
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $newAction `
    -Trigger $triggers `
    -Principal $principal `
    -Settings $settings `
    -Force

# restart the task so new arguments apply
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Start-ScheduledTask -TaskName $taskName
