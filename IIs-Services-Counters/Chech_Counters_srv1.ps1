$counters = '\Memory\% Committed Bytes In Use',
    '\Processor(_Total)\% processor time',
    '\PhysicalDisk(_Total)\% Disk Read Time',
    '\Network Interface(*)\Bytes Total/sec'


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
     
