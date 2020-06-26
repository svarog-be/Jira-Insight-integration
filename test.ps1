
$iis_lastChange_site = @()
$script = {
    $hashtable_iis_lastChange_site = @{}
    $all_site_path = get-childitem 'D:\www'
    foreach ($i in $all_site_path) {
        $a = get-childitem $i.FullName -Recurse 
        $last = $a.lastwritetime | Sort-Object |  Select-Object -last 1
        $hashtable_iis_lastChange_site[$i.fullname]= $last
    }
}
$iis_lastChange_site += Invoke-Command -ComputerName $list_iis -ScriptBlock $script

###################
$Server  = "sql-grind"
$Database = "1ckom_10"
[Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
$SmoServer = New-Object Microsoft.SqlServer.Management.Smo.Server $Server
$db =$SmoServer.Databases[$Database]
$db.Users
$db.Roles['db_owner'].EnumMembers()


[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") 

[void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Management.RegisteredServers")


