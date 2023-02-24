Import-Module PSSQLite



##################  DEFINITIONS ###################################
$regex = [regex] "\d+\.\d+\.\d+\.\d+"
$logfile = "D:\Firewall\blocked.log"
(Get-Date).ToString() + ' Start Script'  >> $logfile
$Database = "D:\Firewall\IPTable.SQLite"
$URLInfluxDB ="http://185.40.100.150:8086"
$MaxFailedLogon = 3 # NB d'echec d'authentification MAX
$Unban = 24 # NB d'heure avant débannissement 

$query_insert = "INSERT INTO IP (IP, Timestamp) VALUES (@IP, @TS)"
$query_MaxFailed = "SELECT IP,Timestamp, COUNT(*) FROM IP GROUP BY IP HAVING COUNT(*) > @MAXFAILED"
$query_purge = "DELETE FROM IP where TimeStamp < @TS"





##################  DETECTION DE L'EVENT 140 ###################################
$DT = [DateTime]::Now.AddSeconds(-120)
(Get-Date).ToString() + ' requete Event ' + ($DT).ToString()   >> $logfile
$af = Get-WinEvent   -FilterHashTable @{ LogName = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"; ID = 140 ; StartTime = $DT } -MaxEvents 1 | select-string -inputobject { $_.message } -Pattern $regex | % { $_.Matches } | Select-Object @{n = 'ClientIP'; e = { $_.Value } }  
$getip = $af | group-object -property ClientIP | Select-Object -property Name

# Purge des IP bannies 
(Get-Date).ToString() + ' Purge des IP'  >> $logfile
Invoke-SqliteQuery -DataSource $Database -Query $query_purge -SqlParameters @{
    TS = ((get-date).AddHours((-$Unban)))
}
    
# Suppression des lignes ayant une IP nulle
Invoke-SqliteQuery -DataSource $Database -Query "DELETE FROM IP WHERE ip is null"


$fw = New-Object -ComObject hnetcfg.fwpolicy2

$BlackListRule = $fw.rules | Where-Object { $_.name -eq 'MY BLACKLIST' }
$IPValue = $getip | Where-Object { $_.Name.Length -gt 1 }

#Ajout des IPs dans Sqlite
if (($IPValue.name).Length -gt 1) {
    (Get-Date).ToString() + ' Ajout IP Base ' + $IPValue.name  >> $logfile
    Invoke-SqliteQuery -DataSource $Database -Query $query_insert -SqlParameters @{
        IP = $IPValue.name
        TS = (get-date)
    }  
#### Ajout dans INFLUXDB
    $IPAddress= $IPValue.name
    # on compte combien il y a d�ja cette ip dans la base
    $countquery =  "SELECT  IP,COUNT(*) FROM IP WHERE IP = @IP"
    $countqueryresult =  Invoke-SqliteQuery -DataSource $Database -Query $countquery -SqlParameters  @{IP = $IPValue.name}


        
    $request = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress"
            $hash = $null
            $hash = @{ }
            $hash.add("host", $env:computername)
            $hash.add("IPHost", $IPAddress)
            $hash.add("lon", $request.lon)
            $hash.add("lat",$request.lat)
            $hash.add("ISP",$request.isp)
            $hash.add("as",$request.as)
            $hash.add("zip",$request.zip)
            $hash.add("regionName",$request.regionName)
            $hash.add("count", $countqueryresult.'COUNT(*)')
    $tag= $null
    $tag = @{ }
    $tag.add("IPAddress", $IPAddress)
    $tag.add("City", $request.city)
    Write-Influx  -Measure Attack  -Database bruteforce -Metrics $hash -Timestamp (Get-Date) -Tags $tag   -Server $URLInfluxDB      
}


##################  OPERATIONS dans FIREWALL ###################################


#Construction de la nouvelle liste d'ip blacklistées 'Liste ip séparateur virgules)

$ListeIP = "" 

(Get-Date).ToString() + ' Construction de la Blacklist IP'  >> $logfile
$collectionIP = Invoke-SqliteQuery -DataSource $Database -Query $query_MaxFailed -SqlParameters @{MAXFAILED = $MaxFailedLogon }

foreach ($IP in $collectionIP) {
    if ($ListeIP.Length -gt 0) { $ListeIP = $ListeIP += ',' + $IP.IP }
    else { $ListeIP = $IP.IP }               
}


if ($ListeIP.length -gt 1) {
    # Anti lockout
    $ListeIP = $ListeIP += ',8.8.8.8'
    $BlackListRule.RemoteAddresses = $ListeIP
    $ListeIP | ForEach-Object { (Get-Date).ToString() + ' Ajout de IP Firewall ' + $IPValue.name >> $logfile }
}

Exit

