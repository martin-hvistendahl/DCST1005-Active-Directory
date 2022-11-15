Import-Module PSScheduledJob
    Set-ExecutionPolicy Bypass

        Register-ScheduledJob -Name 'Check_IIS' -FilePath '\\prosjekt.sec\files\it-admins\Check_W3SVC.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue))
        Register-ScheduledJob -Name 'Check_SRV1_Counters' -FilePath '\\prosjekt.sec\files\it-admins\Check_Counters_srv1.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue))
