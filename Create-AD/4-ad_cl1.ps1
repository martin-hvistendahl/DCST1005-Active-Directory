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

Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses 192.168.111.170
#Pass på ¨å endre IP adresse etter hva Domene kontrolleren sin ip er!

# Legger til maskin i domenet
# For Windows 10 må en gjøre følgende i Windows PowerShell 5.1
#

$cred = Get-Credential -UserName 'prosjekt\Administrator' -Message 'Cred'
Add-Computer -Credential $cred -DomainName prosjekt.sec -PassThru -Verbose
# Hvis maskinen ikke tillater autentisering for oppkoblingen, kjør følgende i powershell:
winrm set winrm/config/service/auth '@{Kerberos="true"}'
# Hvis maskina ikke har aktivert PSRemote:
Enable-PSRemoting -Force
Restart-Computer


#kode er hentet fra https://gitlab.com/undervisning/dcst1005-demo/-/blob/master/v22/220124%20-%20Uke4-PS%20brukt%20i%20undervisningstimen-AD.ps1
