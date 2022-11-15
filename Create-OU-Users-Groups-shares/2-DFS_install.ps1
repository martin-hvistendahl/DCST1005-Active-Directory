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
