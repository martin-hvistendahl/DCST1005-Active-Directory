$Services='DNS','DFS Replication','Intersite Messaging','Kerberos Key Distribution Center','NetLogon','Active Directory Domain Services','DFS Namespace','wuauserv', 'Windows Time', 'Remote Procedure Call (RPC)'
                    # loop through each service, if its not running, start it
            foreach($ServiceName in $Services){
                write-host $ServiceName (Get-Service -name $ServiceName).Status
                while ((Get-Service -name $ServiceName).Status -ne 'Running')
                {
                    Start-Service $ServiceName
                    write-host '    Starting service ' $ServiceName
                    Start-Sleep -seconds 10
                    (Get-Service -name $ServiceName).Refresh()
                    if ((Get-Service -name $ServiceName).Status -eq 'Running')
                    {
                    Write-Host '    Service is now Running' $ServiceName
                    }
                }
            }