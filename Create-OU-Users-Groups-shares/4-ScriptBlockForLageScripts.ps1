New-Item -Path "\\prosjekt.sec\files\it-admins" -name "Check_W3SVC.ps1" -ItemType "file" -Value '
$Services="W3SVC"
# Looper gjennom Services og sjekker om den kjører, hvis den ikke gjør det så vil den bli startet. 
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
# Looper gjennom Services og sjekker om den kjører, hvis den ikke gjør det så vil den bli startet. 
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

#Lager powershell script som sjekker services på dc1 

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
      } | Export-CSV -Path "\\prosjekt.sec\files\it-admins\logs\srv1_log_$date.csv" -NoTypeInformation
      #vil bli laget en ny csv med datoen og tidspunkt for når logs blir tatt
      '

#lager powershell file som sjekker counters på srv1, kode er tungt inspirert fra https://gitlab.com/undervisning/dcst1005-demo/-/blob/master/v22/220228%20-%20Uke9-PS%20brukt%20i%20undervisningstime%20monitoring.ps1
Install-WindowsFeature -name Web-Server -IncludeManagementTools #installerer IIS

$cred = Get-Credential prosjekt\Administrator
$srv1Ps5 = New-PSSession -computerName srv1 -credential $cred
$CheckCountersW3SVC = {
    Import-Module PSScheduledJob
    Set-ExecutionPolicy Bypass
        
        Register-ScheduledJob -Name 'Check_IIS' -FilePath '\\prosjekt.sec\files\it-admins\Check_W3SVC.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue))
        Register-ScheduledJob -Name 'Check_SRV1_Counters' -FilePath '\\prosjekt.sec\files\it-admins\Check_Counters_srv1.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue))
    #kode er inspirert fra https://docs.microsoft.com/en-us/powershell/module/psscheduledjob/register-scheduledjob?view=powershell-5.1
    #https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.2
}
Invoke-Command -Session $srv1Ps5 -Scriptblock $CheckCountersW3SVC
Remove-PSSession $srv1Ps5

$dc1 = New-PSSession -computerName dc1 -credential $cred
$scriptCheckServiceDC1 = {
    Enter-PSSession dc1
    Set-ExecutionPolicy Bypass
    $action = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument \\prosjekt.sec\files\it-admins\Check_Services_dc1.ps1
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days (365 * 20) )
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "CheckServiceDC1" -Description "Checking services on dc1 and starting them if they are down"
        Set-ScheduledTask -Trigger $trigger -TaskName "CheckServiceDC1"
    #mye kode er hentet fra:
    #https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2022-ps
    #https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2022-ps
    #https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2022-ps

}
Invoke-Command -Session $dc1 -Scriptblock $scriptCheckServiceDC1
Remove-PSSession $dc1