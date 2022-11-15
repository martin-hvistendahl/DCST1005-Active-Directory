$backup_block = {
    
    # Dette scriptet er inspirert av leksjonen om backup 

    # Kode for å lage partisjon og diskbokstav etter at volum er opprettet i openstack
    Initialize-Disk -Number 1 -PartitionStyle MBR
    New-Partition -DiskNumber 1 -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel backup
    Get-Partition -DiskNumber 1 | Set-Partition -NewDriveLetter G

    # Lagrer selve backupscriptet i en ny fil som skal bli hentet ut i task scheduler
    New-Item -Path "\\prosjekt.sec\files\it-admins" -Name "backup.ps1" -ItemType "file" -Value '

    #Setter disken online 
    Set-Disk -Number 1 -IsOffline $False

    # Oppretter variabler
    $source = "\\prosjekt.sec\files"
    $destination = "G:\"

    $date = Get-Date -UFormat "_%Y_%m_%d"
    $week = Get-Date -UFormat %V
    $checkday = Get-Date -UFormat "%A" 

    # Definerer ulike varabler for god navngivning
    $fullbackuplog = "_full_date"
    $incbackuplog = "_incremental_week_"
    $fullbackupstart = "full_backup"
    $incbackupstart = "incremental_backup_week_"

    $logdir = "G:\logs\"
    $logfull = "G:\logs\backuplogfile$fullbackuplog$date.txt"
    $loginc = "G:\logs\backuplogfile$incbackuplog$week$date.txt"
    $logcopy = "\\prosjekt.sec\files\it-admins"

    # Variabler som skal sjekke om mappen for backup eksisterer 
    $checkfull = -join($destination,$fullbackupstart,$date) 
    $checkinc = -join($destination,$incbackupstart,$week,$date)


    # Lager logfolder hvis det ikke eksisterer
    if (-not(Test-Path -Path $logdir -PathType Container)) {
        New-Item -Path $logdir  -ItemType Directory
    }

    # Sjekker det om det finnes en mappe for full backup, hvis den ikke finnes og det er søndag, lages en mappe og det tas det full backup
    if (-not(Test-Path -Path $checkfull -PathType Container) -and ($checkday -eq "Sunday")) {
        New-Item -Path $checkfull -ItemType Directory

        # Kopierer fra source til destination. /e er å ta med undermapper, /r er antall retries, /w er tid mellom retries, /z er at den kom gjennopptas hvis den blir stoppet 
        Robocopy $source $checkfull /e /r:3 /w:10 /z /copy:DAT /LOG:$logfull

        # Kopierer log filen til itadmins
        Copy-Item $logfull -Destination $logcopy
    } else {
        # Hvis det ikke ble gjort full backup sjekkes det om det finnes en mappe for inkrementell backup, hvis ikke lages det en mappe
        if (-not(Test-Path -Path $checkinc -PathType Container)) {
            New-Item -Path $checkinc -ItemType Directory
        }

        # Tar inkrementell backup. /im tar backup av filer andrede filer
        Robocopy $source $checkinc /e /im /r:3 /w:10 /z /copy:DAT /LOG:$loginc

        Copy-Item $loginc -Destination $logcopy
    }

    # Setter disken offline for ekstra sikkerhet
    Set-Disk -Number 1 -IsOffline $True' 

    # Lager en task å setter den til å kjøre daglig. Hentet fra https://www.windowscentral.com/how-create-scheduled-tasks-powershell-windows-10
    # Man bør gå inn å endre til 'run whether user is logged on or not' i task scheduler
    $action = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument \\prosjekt.sec\files\it-admins\backup.ps1
    $trigger = New-ScheduledTaskTrigger -Daily -At 1am
    $principal = New-ScheduledTaskPrincipal -UserId "prosjekt\Administrator" -RunLevel Highest 
    $settings = New-ScheduledTaskSettingsSet 
    Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -TaskName "Backup" -Description "Daily backup"
    Set-ScheduledTask -Trigger $trigger -TaskName "Backup"

    # For å få tilgang til der scriptet blir lagret
    Set-ExecutionPolicy Bypass
}

$cred = Get-Credential prosjekt\Administrator
$s = New-PSSession -computerName mgr -credential $cred
Invoke-Command -Session $s -Scriptblock $backup_block
Remove-PSSession $s