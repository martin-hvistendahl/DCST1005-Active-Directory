$cred = Get-Credential prosjekt\Administrator
$s = New-PSSession -computerName dc1 -credential $cred
$scriptb = {
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
Invoke-Command -Session $s -Scriptblock $scriptb
Remove-PSSession $s