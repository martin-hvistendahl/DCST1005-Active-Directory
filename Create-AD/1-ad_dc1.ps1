Get-WinUserLanguageList
$languagelist = Get-WinUserLanguageList
$LanguageList.Add("nb")
Set-WinUserLanguageList $languagelist

Set-TimeZone -id 'Central Europe Standard Time'
Set-ExecutionPolicy -ExecutionPolicy unrestricted -Scope LocalMachine
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco upgrade chocolatey
# Installere programvare med Choco
choco install -y powershell-core
choco install -y git.install
choco install -y vscode
 #kode er hentet fra https://gitlab.com/undervisning/dcst1005-demo/-/blob/master/v22/220117%20-%20Uke3-PS%20brukt%20i%20undervisningstimen.ps1



$newcompname = "dc1"
Rename-Computer -Newname $newcompname -Restart -Force

Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
$Password = Read-Host -Prompt 'Enter Password' -AsSecureString
Set-LocalUser -Password $Password Administrator
$Params = @{
    DomainMode = 'WinThreshold'
    DomainName = 'prosjekt.sec'
    DomainNetbiosName = 'prosjekt'
    ForestMode = 'WinThreshold'
    InstallDns = $true
    NoRebootOnCompletion = $true
    SafeModeAdministratorPassword = $Password
    Force = $true
}
# Hvis maskinen ikke tillater autentisering for oppkoblingen, kjør følgende i powershell:
winrm set winrm/config/service/auth '@{Kerberos="true"}'
# Hvis maskina ikke har aktivert PSRemote:
Enable-PSRemoting -Force

Install-ADDSForest @Params
Restart-Computer
