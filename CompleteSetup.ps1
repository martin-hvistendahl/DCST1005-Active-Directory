$cred = Get-Credential prosjekt\Administrator
$OUPS = New-PSSession -computerName dc1 -credential $cred
$UserPS = New-PSSession -computerName dc1 -credential $cred
$MonitorDc1PS = New-PSSession -computerName dc1 -credential $cred
$MonitorSrv1PS = New-PSSession -computerName srv1 -credential $cred
$BackPS = New-PSSession -computerName mgr -credential $cred


$OU_Struktur = {
    # Opprettelse av AD OU #
    New-ADOrganizationalUnit "Prosjekt_X" -Description "Prosjekt_gruppe10"

    Get-ADObject -Identity "OU=Prosjekt_X,DC=prosjekt,DC=sec" | Set-ADObject -ProtectedFromAccidentalDeletion:$false

    # Creates OU's
    New-ADOrganizationalUnit "Employees" -Path "OU=Prosjekt_X,DC=prosjekt,DC=sec" -Description "Employees OU"
    New-ADOrganizationalUnit "Workstations" -Path "OU=Prosjekt_X,DC=prosjekt,DC=sec" -Description "Workstations OU"
    New-ADOrganizationalUnit "Groups" -Path "OU=Prosjekt_X,DC=prosjekt,DC=sec" -Description "Groups OU"

    Get-ADObject -Identity "OU=Employees,OU=Prosjekt_X,DC=prosjekt,DC=sec" | Set-ADObject -ProtectedFromAccidentalDeletion:$false
    Get-ADObject -Identity "OU=Workstations,OU=Prosjekt_X,DC=prosjekt,DC=sec" | Set-ADObject -ProtectedFromAccidentalDeletion:$false
    Get-ADObject -Identity "OU=Groups,OU=Prosjekt_X,DC=prosjekt,DC=sec" | Set-ADObject -ProtectedFromAccidentalDeletion:$false

    $ADOU = "IT-drift", "Developer", "Regnskap", "Sale", "HR";
    $paths = "OU=Employees,OU=Prosjekt_X,DC=prosjekt,DC=sec", "OU=Workstations,OU=Prosjekt_X,DC=prosjekt,DC=sec"
    $gr="OU=Groups,"
    

    foreach ($path in $paths) {
        foreach ($ou in $ADou) {
            New-ADOrganizationalUnit -Name $ou -path $path
        }
    }

    #creates local and global groups, and puts the global groups in the local ones

    $Groups=$ADOU+"AllEmployees"
    @("Local","Global") | ForEach-Object{
        New-ADOrganizationalUnit "$_" -Path "$($gr)OU=Prosjekt_X,DC=prosjekt,DC=sec"
    }
    foreach($Group in $Groups){
        New-ADGroup -GroupCategory Security `
        -GroupScope DomainLocal  `
        -Name "l_$Group" `
        -Path "OU=Local,$($gr)OU=Prosjekt_X,DC=prosjekt,DC=sec" `
        -SamAccountName "l_$Group"
    }
    foreach($Group in $Groups){
        New-ADGroup -GroupCategory Security `
            -GroupScope Global `
            -Name "g_$Group" `
            -Path "OU=Global,$($gr)OU=Prosjekt_X,DC=prosjekt,DC=sec" `
            -SamAccountName "g_$Group"
        $localGroup=Get-ADGroup -filter * | Where-Object SamAccountName -eq "l_$Group"
        $globalGroup=Get-ADGroup -filter * | Where-Object SamAccountName -eq "g_$Group"
        $localgroup | Add-ADGroupMember -Members $globalgroup.samaccountname

    }
    
    
    
}  
Invoke-Command -Session $OUPS -Scriptblock $OU_Struktur
Remove-PSSession $OUPS

Install-WindowsFeature -Name FS-DFS-Namespace,FS-DFS-Replication,RSAT-DFS-Mgmt-Con -IncludeManagementTools

Import-module dfsn

#Creates fileshares

$folders = ('C:\dfsroots\files', "C:\shares\it-admins", 'C:\shares\IT-drift','C:\shares\Developer','C:\shares\Regnskap','C:\shares\HR','C:\shares\Sale')
$sharesFolders = @()
$folders[2..$folders.Length] | ForEach-Object {$sharesFolders += $_.Substring(10)}
Write-Host $sharesFolders
mkdir -path $folders
$folders | ForEach-Object {
    $sharename = (Get-Item $_).name
    New-SMBShare -Name $shareName -Path $_ -FullAccess Everyone
}

New-DfsnRoot -TargetPath \\srv1\files -Path \\prosjekt.sec\files -Type DomainV2

$folders | Where-Object {$_ -like "*shares*"} | ForEach-Object {
    $name = (Get-Item $_).name
    $DfsPath = ('\\prosjekt.sec\files\' + $name)
    $targetPath = ('\\srv1\' + $name)
    New-DfsnFolderTarget -Path $DfsPath -TargetPath $targetPath
}

#Only allows the the departmentmebers to acces their folder

$sharesFolders | ForEach-Object {
    $acl = Get-Acl \\prosjekt\files\$_
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("prosjekt\l_$_","FullControl",'ContainerInherit, ObjectInherit','None',"Allow")
    $acl.SetAccessRule($AccessRule)
    $acl | Set-Acl -Path "\\prosjekt\files\$_"
    $acl = Get-Acl -Path "\\prosjekt\files\$_"
    $acl.SetAccessRuleProtection($true,$true)
    $acl | Set-Acl -Path "\\prosjekt\files\$_"
    $acl = Get-Acl "\\prosjekt\files\$_"
    $acl.Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users"} | ForEach-Object { $acl.RemoveAccessRuleSpecific($_) }
    Set-Acl "\\prosjekt\files\$_" $acl
} 

mkdir -path "\\prosjekt\files\it-admins\logs"
$acl = Get-Acl \\prosjekt\files\it-admins
$acl | Set-Acl -Path "\\prosjekt\files\it-admins"
$acl = Get-Acl -Path "\\prosjekt\files\it-admins"
$acl.SetAccessRuleProtection($true,$true)
$acl | Set-Acl -Path "\\prosjekt\files\it-admins"
$acl = Get-Acl "\\prosjekt\files\it-admins"
$acl.Access | Where-Object {$_.IdentityReference -eq "BUILTIN\Users"} | ForEach-Object { $acl.RemoveAccessRuleSpecific($_) }
Set-Acl "\\prosjekt\files\it-admins" $acl

#Fids the path the repo is dowloaded to

$mypath = $MyInvocation.MyCommand.Path -split '\\'
$numb=$mypath.Length-1
1..$numb | ForEach-Object {
    $first, $mypath=$mypath
    $newpath+=$first+"\"
}
$filelocation=$newpath+"CSV-files"
$newpath+="CSV-files\users.csv"

#Krever at det er en fileshere med navn it-admins
#Krever at det er en OU med navn Employees
#Krever at departments i csv filen matcher med OU strukturen

#Coppies the CSV file to the a fileshere

Copy-Item -Path $newpath `
        -Destination \\prosjekt.sec\files\it-admins -recurse -Force
Remove-Item -Path $newpath

New-Item -Path $filelocation -name "users.csv" -ItemType "file" -Value "GivenName,SurName,Department`n"

$addAllUsers = {
    $NewUsers= import-csv "\\prosjekt.sec\files\it-admins\users.csv" -Delimiter ","

    #Creates the file to export to
    New-Item -Path "\\prosjekt.sec\files\it-admins" -name "userinfo.csv" -ItemType "file" -Value "GivenName,SurName,UserName,Password,Department`n"

    $tekstToFile=""

    function New-CompanyADUser {
        param (
            [String[]]$info
            )
            Process {
            
            $givenName=$info[0]
            $surName=$info[1]
            $department=$info[2]
            
            while ($givenName.Length -lt 5) {
                $givenName+=$givenName[$givenName.Length-1]
            }
            while ($surName.Length -lt 5) {
                $surName+=$surName[$surName.Length-1]
            }

            #Identify if wanted UserPrincipalName 
            $identicPersonCounter= if (@(Get-ADUser -filter * | Where-Object {($_.SurName -eq $info[1]) -and ($_.GivenName -eq $info[0])}).Length -eq 0) {
                ""
            }else {
                @(Get-ADUser -filter * | Where-Object {($_.SurName -eq $info[1]) -and ($_.GivenName -eq $info[0])}).Length
            }

            #Creates a unic username in a consistent way
            $usernameCounter=0
            do {
                $username=$givenName.Substring(0,5).ToLower()+$surName.Substring(0,5).ToLower()+$usernameCounter.tostring('000')
                $usernameCounter+=1
            } until ($null -eq (Get-ADUser -filter * | Where-Object SamAccountName -eq $username))

            $AUserPrincipalName="$($info[0].ToLower()).$($info[1].ToLower())$identicPersonCounter@prosjekt.sec"
            
            #Creates a password
            #https://dev.to/onlyann/user-password-generation-in-powershell-core-1g91
            $symbols="!@#$%&*_-+=/(){}[]:;<>.?".ToCharArray()
            $ValidPassordLetters= "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*_-+=/(){}[]:;<>.?"
            do{
                $password=""
                0..12|ForEach-Object{
                    $rand = Get-Random -Maximum $ValidPassordLetters.Length
                    $password+=$ValidPassordLetters[$rand]
                }
                [int]$lower=$password -cmatch '[a-z]'
                [int]$upper=$password -cmatch '[A-Z]'
                [int]$dig=$password -cmatch '[0-9]'
                [int]$symbol = $password.IndexOfAny($symbols) -ne -1
                
            }
            until (($lower+$upper+$dig+$symbol) -eq 4)
            
            #Creates the path with department name
            $Path = "OU=$department,OU=Employees,OU=Prosjekt_X,DC=prosjekt,DC=sec"

            #Adds a new user
            New-ADUser `
                -SamAccountName $username `
                -DisplayName $username `
                -UserPrincipalName $AUserPrincipalName `
                -Name $username `
                -GivenName $info[0] `
                -SurName $info[1] `
                -Enabled $true `
                -ChangePasswordAtLogon $true `
                -Department $department `
                -Path $Path `
                -AccountPassword (convertto-securestring $password -AsPlainText -Force)
        
            #Saves Username and Password in a variable to file
            $teksts+="$givenName,$surName,$username,$password,$department`n"
            return $teksts
        }
    } 
    $NewUsers | ForEach-Object {
       $tekstToFile += New-CompanyADUser -info @($_.GivenName, $_.SurName, $_.Department) 
    }

    #saved the info to a file
    Add-Content \\prosjekt.sec\files\it-admins\userinfo.csv "$tekstToFile"
    Remove-Item -Path "\\prosjekt.sec\files\it-admins\users.csv"

    $departments = "IT-drift", "Developer", "Regnskap", "Sale", "HR";

    #added members to groups

    foreach($dep in $departments){
        $usersToBeAdded = Get-ADUser -filter * -Properties department | Where-Object{$_.department -eq $dep}
        Add-ADGroupMember -Identity "g_$dep" -Members $usersToBeAdded.SamAccountName
        Add-ADGroupMember -Identity "g_AllEmployees" -Members $usersToBeAdded.SamAccountName
    } 
}

#Runs the commands in a PS-sesion 
Invoke-Command -Session $UserPS -Scriptblock $addAllUsers
Remove-PSSession $UserPS



    New-Item -Path "\\prosjekt.sec\files\it-admins" -name "Check_W3SVC.ps1" -ItemType "file" -Value '
    $Services="W3SVC"
    # Looper gjennom Services og sjekker om den kjører, hvis den ikke gjør det så vil den bli startet. 
    foreach($ServiceName in $Services){
        write-host $ServiceName (Get-Service -name $ServiceName).Status
        while ((Get-Service -name $ServiceName).Status -ne "Running"){
            Start-Service $ServiceName
            write-host "    Starting service " $ServiceName
            Start-Sleep -seconds 10
            (Get-Service -name $ServiceName).Refresh()
                if ((Get-Service -name $ServiceName).Status -eq "Running"){
                    Write-Host "    Service is now Running" $ServiceName
                }
        }
    }'


    #lager powershell file som sjekker W3SVC services på srv1 og legger det på delte filområder

    New-Item -Path "\\prosjekt.sec\files\it-admins" -name "Check_Services_dc1.ps1" -ItemType "file" -Value '
    $Services="DNS","DFS Replication","Intersite Messaging","Kerberos Key Distribution Center","NetLogon","Active Directory Domain Services","DFS Namespace","wuauserv", "Windows Time", "Remote Procedure Call (RPC)"
    # Looper gjennom Services og sjekker om den kjører, hvis den ikke gjør det så vil den bli startet. 
    foreach($ServiceName in $Services){
        write-host $ServiceName (Get-Service -name $ServiceName).Status
        while ((Get-Service -name $ServiceName).Status -ne "Running"){
            Start-Service $ServiceName
            write-host "    Starting service " $ServiceName
            Start-Sleep -seconds 10
            (Get-Service -name $ServiceName).Refresh()
            if ((Get-Service -name $ServiceName).Status -eq "Running"){
                Write-Host "    Service is now Running" $ServiceName
            }
        }
    }'

    #Lager powershell script som sjekker services på dc1 og legger det på delte filområder

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

#lager powershell file som sjekker counters på srv1 og legger det på delte filområder, kode er tungt inspirert fra https://gitlab.com/undervisning/dcst1005-demo/-/blob/master/v22/220228%20-%20Uke9-PS%20brukt%20i%20undervisningstime%20monitoring.ps1
Install-WindowsFeature -name Web-Server -IncludeManagementTools #installerer IIS

$CheckCountersW3SVC = {
    Import-Module PSScheduledJob
    Set-ExecutionPolicy Bypass
    #Set-ExecutionPolicy Bypass er ikke en bra policy men klarte ikke på noen andre måte å kjøre scriptet. Prøvde Unblock-File, prøvde å sette ExecutionPolicy til Allsigned
    #og så signere dokumentene. Dette fungerte heller ikke så da ble det en denne løsningen som fungerer. 
        Register-ScheduledJob -Name 'Check_IIS' -FilePath '\\prosjekt.sec\files\it-admins\Check_W3SVC.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue))
        Register-ScheduledJob -Name 'Check_SRV1_Counters' -FilePath '\\prosjekt.sec\files\it-admins\Check_Counters_srv1.ps1' -Trigger (New-JobTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue))
    #kode er inspirert fra https://docs.microsoft.com/en-us/powershell/module/psscheduledjob/register-scheduledjob?view=powershell-5.1
    #https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.2
    #dette må kjøres gjennom en Session fordi PSScheduledJob ikke finnes i powershell 7. Gjennom en session kjøres det i powershell 5
}
Invoke-Command -Session $MonitorSrv1PS -Scriptblock $CheckCountersW3SVC
Remove-PSSession $MonitorSrv1PS

$CheckServiceDC1 = {
    Set-ExecutionPolicy Bypass
    #Set-ExecutionPolicy Bypass er ikke en bra policy men klarte ikke på noen andre måte å kjøre scriptet. Prøvde Unblock-File, prøvde å sette ExecutionPolicy til Allsigned
    #og så signere dokumentene. Dette fungerte heller ikke så da ble det en denne løsningen som fungerer. 
    $action = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument \\prosjekt.sec\files\it-admins\Check_Services_dc1.ps1
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days (365 * 20) )
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "CheckServiceDC1" -Description "Checking services on dc1 and starting them if they are down"
        Set-ScheduledTask -Trigger $trigger -TaskName "CheckServiceDC1"
        #mye kode er hentet fra:
        #https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?view=windowsserver2022-ps
        #https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2022-ps
        #https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask?view=windowsserver2022-ps
        
    }
    
Invoke-Command -Session $MonitorDc1PS -Scriptblock $CheckServiceDC1
Remove-PSSession $MonitorDc1PS
    
    
    # Dette scriptet er inspirert av leksjonen om backup     

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
    $checkinc = -join($destination,$incbackupstart,$week)


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

        # Tar inkrementell backup. /im tar backup av endrede filer
        Robocopy $source $checkinc /e /im /r:3 /w:10 /z /copy:DAT /LOG:$loginc

        Copy-Item $loginc -Destination $logcopy
    }

    # Setter disken offline for ekstra sikkerhet
    Set-Disk -Number 1 -IsOffline $True' 

$backup_block = {
    # For å få tilgang til der scriptet blir lagret
    Set-ExecutionPolicy Bypass
    # Set-ExecutionPolicy Bypass er ikke en bra policy men klarte ikke på noen andre måte å kjøre scriptet. Prøvde Unblock-File, prøvde å sette ExecutionPolicy til Allsigned
    # og så signere dokumentene. Dette fungerte heller ikke så da ble det en denne løsningen som fungerer. 
    # Dette scriptet er inspirert av leksjonen om backup 

    # Kode for å lage partisjon og diskbokstav etter at volum er opprettet i openstack
    Initialize-Disk -Number 1 -PartitionStyle MBR
    New-Partition -DiskNumber 1 -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel backup
    Get-Partition -DiskNumber 1 | Set-Partition -NewDriveLetter G


    # Lager en task å setter den til å kjøre daglig. Hentet fra https://www.windowscentral.com/how-create-scheduled-tasks-powershell-windows-10
    # Man bør gå inn å endre til 'run whether user is logged on or not' i task scheduler
    $action = New-ScheduledTaskAction -Execute 'C:\Program Files\PowerShell\7\pwsh.exe' -Argument \\prosjekt.sec\files\it-admins\backup.ps1
    $trigger = New-ScheduledTaskTrigger -Daily -At 1am
    $principal = New-ScheduledTaskPrincipal -UserId "prosjekt\Administrator" -RunLevel Highest 
    $settings = New-ScheduledTaskSettingsSet 
    Register-ScheduledTask -Action $action -Principal $principal -Trigger $trigger -Settings $settings -TaskName "Backup" -Description "Daily backup"
    Set-ScheduledTask -Trigger $trigger -TaskName "Backup"

}

Invoke-Command -Session $BackPS -Scriptblock $backup_block
Remove-PSSession $BackPS