$cred = Get-Credential prosjekt\Administrator

#Fids the path the repo is dowloaded to

$mypath = $MyInvocation.MyCommand.Path -split '\\'
$numb=$mypath.Length-2
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

$s = New-PSSession -computerName dc1 -credential $cred
$scriptb = {
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
Invoke-Command -Session $s -Scriptblock $scriptb
Remove-PSSession $s