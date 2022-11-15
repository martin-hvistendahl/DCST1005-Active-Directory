New-Item -Path "\\prosjekt.sec\files\it-admins" -name "Check_W3SVC.ps1" -ItemType "file" -Value '
$Services="W3SVC"
# loop through each service, if its not running, start it
foreach($ServiceName in $Services){
write-host $ServiceName (Get-Service -name $ServiceName).Status
while ((Get-Service -name $ServiceName).Status -ne "Running")
{
Start-Service $ServiceName
write-host "    Starting service " $ServiceName
Start-Sleep -seconds 10
(Get-Service -name $ServiceName).Refresh()
if ((Get-Service -name $ServiceName).Status -eq "Running")
{
Write-Host "    Service is now Running" $ServiceName
}
}
}'


#lager powershell file som sjekker W3SVC services på srv1

New-Item -Path "\\prosjekt.sec\files\it-admins" -name "Check_Services_dc1.ps1" -ItemType "file" -Value '
$Services="DNS","DFS Replication","Intersite Messaging","Kerberos Key Distribution Center","NetLogon","Active Directory Domain Services","DFS Namespace","wuauserv", "Windows Time", "Remote Procedure Call (RPC)"
# loop through each service, if its not running, start it
foreach($ServiceName in $Services){
write-host $ServiceName (Get-Service -name $ServiceName).Status
while ((Get-Service -name $ServiceName).Status -ne "Running")
{
Start-Service $ServiceName
write-host "    Starting service " $ServiceName
Start-Sleep -seconds 10
(Get-Service -name $ServiceName).Refresh()
if ((Get-Service -name $ServiceName).Status -eq "Running")
{
Write-Host "    Service is now Running" $ServiceName
}
}
}'
New-Item -Path "\\prosjekt.sec\files\it-admins" -name "Check_Counters_srv1.ps1" -ItemType "file" -Value '
$date = Get-Date -Format "MM_dd_yyyy_HH.mm"
$counters = "\Memory\% Committed Bytes In Use",
    "\Processor(_Total)\% processor time",
    "\PhysicalDisk(_Total)\% Disk Read Time",
    "\Network Interface(*)\Bytes Total/sec"


      Get-Counter -Counter $counters -MaxSamples 1 |
      ForEach-Object {
          $_.CounterSamples | ForEach-Object {
              [PSCustomObject]@{
                  TimeStamp = $_.Timestamp
                  Path = $_.Path
                  Value = $_.CookedValue
              }
          }
      } | Export-CSV -Path "\\prosjekt.sec\files\it-admins\logs\srv1_log_$date.csv" -NoTypeInformation'

#lager powershell file som sjekker counters på srv1, her er kode hentet fra Tor ivar

#de fire linjene under skal kjøres på dc1
    Set-ExecutionPolicy Bypass
    $action = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument \\prosjekt.sec\files\it-admins\Check_Services_dc1.ps1
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days (365 * 20) )
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "CheckServiceDC1" -Description "Checking services on dc1 and starting them if they are down"
        Set-ScheduledTask -Trigger $trigger -TaskName "CheckServiceDC1"


#disse skal kjøres på srv1
    Import-Module PSScheduledJob
    Set-ExecutionPolicy Bypass

        Register-ScheduledJob -Name 'Check_IIS' -FilePath '\\prosjekt.sec\files\it-admins\Check_W3SVC.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue))
        Register-ScheduledJob -Name 'Check_SRV1_Counters' -FilePath '\\prosjekt.sec\files\it-admins\Check_Counters_srv1.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue))

        #dette må være i en powershell 5 fil

        