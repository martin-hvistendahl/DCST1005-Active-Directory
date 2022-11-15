## Navn
Oppsett av AD

## Innledning
Scriptet setter opp AD med OU, brukere, backup og monitorering. 

## Installering
Scriptene kjøres med pwsh kommandoen i Powershell. Filene i Create-AD må kjøres lokalt på PC'ene, **IP-addressen i disse filene må byttes med IP-addressen til faktisk domenekontroller**. Videre har man to muligheter, enten kan man kjøre CompleteSetup.ps1 som må kjøres på srv1, men hvis man ikke ønsker å belaste serveren og heller ønsker å bruke en manager PC, må filene i mappa Create-OU-Users-Groups-shares kjøres i rekkefølgen filnanvnene er nummerert. 2-DFS_install må kjørest på srv1. I starten når filene kjøres må administratorpassordet skrives inn.

## Output
Forventet output er grønn tekst med filnavn. Det skal ikke være noe rød tekst. 

## Filstruktur
Mapppenavn | Filnavn | Bruksområde
--- | --- |---
Create-AD | | 
--\|\|--| [1-ad_dc1.ps1](.\Create-AD\1-ad_dc1.ps1) | Setter opp AD på domenekontroller
--\|\|--| [2-ad_mgr.ps1](.\Create-AD\2-ad_mgr.ps1) | Melder mgr inn i AD 
--\|\|--| [3-ad_srv1.ps1](.\Create-AD\3-ad_srv1.ps1) | Melder srv1 inn i AD 
--\|\|--| [4-ad_cl1.ps1](.\Create-AD\4-ad_cl1.ps1) | Melder cl1 inn i AD 
Create-OU-Users-Groups-shares | |
--\|\|--| [1-OU_strukturOgGrupper.ps1](.\Create-OU-Users-Groups-shares\1-OU_strukturOgGrupper.ps1) | Setter opp OU'er samt lokale og globale grupper
--\|\|--| [2-DFS_install.ps1](.\Create-OU-Users-Groups-shares\2-DFS_install.ps1) | Setter opp file shares og setter tilganger på de
--\|\|--| [3-Create-users-in-bulk.ps1](.\Create-OU-Users-Groups-shares\3-Create-users-in-bulk.ps1) | Legger til bruker ut ifra en CSV-fil
--\|\|--| [4-ScriptBlockForLageScripts.ps1](.\Create-OU-Users-Groups-shares\4-ScriptBlockForLageScripts.ps1) | Setter opp overvåkning av kritiske tjenester og counters
--\|\|--| [5-Backup.ps1](.\Create-OU-Users-Groups-shares\5-Backup.ps1) | Setter opp automatisk backup
CSV-files | | 
--\|\|--|Users.csv | Her skrives inn brukerne som skal opprettes
IIS-Services-Counters
--\|\|--|[Chech_Counters_srv1.ps1](.\IIS-Services-Counters\Chech_Counters_srv1.ps1) | Sjekke Counters på srv1 
--\|\|--|[Check_dc1_Services.ps1](.\IIS-Services-Counters\Check_dc1_Services.ps1) | Sjekke om visse Services er Running på dc1
--\|\|--|[Check_IIS_Service.ps1](.\IIS-Services-Counters\Check_IIS_Service.ps1) | Sjekke om visse W3SVC er Running på srv1
--\|\|--|[Create_ps1_and_jobs.ps1](.\IIS-Services-Counters\Create_ps1_and_jobs.ps1) | Lager scripts på delte filområder og lager tasks og jobs for å kjøre disse scriptene
--\|\|--|[Install_IIS.ps1](.\IIS-Services-Counters\Install_IIS.ps1) | Installasjon av IIS
--\|\|--|[PSScheduledJob.ps1](.\IIS-Services-Counters\PSScheduledJob.ps1) | Lager jobs på srv1
Source | | 
--\|\|--|[CompleteSetup.ps1](.\CompleteSetup.ps1) | Kombinasjon av scriptene i mappen Create-OU-Users-Groups-shares 
--\|\|--|[README.md](.\README.md) | Denne filen

## Utviklere
Jo Remvik<br> 
Martin Sannes Hvistendahl<br>
Mathias Bjerkan<br>
Nicolai Forsberg Sommerfelt<be>
