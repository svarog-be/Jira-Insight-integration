<#

Интеграция JIRA/Insight c vCloud RTCloud, Zabbix, MSSQL

Скрипт используется для автоматического добавления в JIRA/Insight ралзичных данных:
добавляет запись о виртуальной машине из vCloud RTCloud,а
Изменяет у хостов атрибуты: стоимость ВМ в РТКлауде, в каком ЦОД находится ВМ в РТклауде, версия ОС, объём RAM, количество ядер.
добалвяет список баз данных с MSSQL инстансов с атрибутами: модель восстановления, объём, доступный объём
статус ZABBIX агента на хосте
ip адрес из DNS 
доступность хоста по сети

#>

function jira_auth {
    param (
        $user,
        $pass
    )
    

    $pair = "$($user):$($pass)"

    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))

    $basicAuthValue = "Basic $encodedCreds"

    $Headers = @{
    Authorization = $basicAuthValue
    }

    $Headers.Add("Content-Type", "application/json")

    return $Headers
}

function rtcloud_auth {
    param (
        $user,
        $pass,
        $domain
    )
    
    #$user = 'p.morozov@otlnal'
    #$pass = "10Rhensitr"

    $pair = "$($user + $domain):$($pass)"

    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))

    $basicAuthValue = "Basic $encodedCreds"

    $Headers = @{
    Authorization = $basicAuthValue
    }

    #$Headers.Add("Accept", "application/vnd.vmware.vcloud.session+xml;version=30.0")
    $Headers.Add("Accept", "application/*+xml;version=30.0")
    #$headers.remove("Accept")
    #$headers_rtcloud.add("Accept", "application/vnd.vmware.vcloud.query+xml;version=30.0")

    $rtcloud_Response = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/sessions' -Method POST -Headers $Headers
    $rtcloud_token = $rtcloud_Response.headers["x-vcloud-authorization"]
    $Headers.Add("x-vcloud-authorization", $rtcloud_token[0])
    $headers.remove("Authorization")

    return $Headers
}

function jira_changeAtr {
    param (
        $value_atr,
        $id_object,
        $id_atr
    )
    $json = '{"attributes":[{"objectTypeAttributeId":' + $id_atr +',"objectAttributeValues":[{"value": "' + $value_atr +'"}]}]}'
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/' + $id_object + ''
    Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function jira_changeAtr4 {
    param (
        $value_atr1,
        $value_atr2,
        $value_atr3,
        $value_atr4,
        $id_object,
        $id_atr1,
        $id_atr2,
        $id_atr3,
        $id_atr4,
        $Headers_jira
    )
    $json = '{"attributes":[  
    {"objectTypeAttributeId":' + $id_atr1 +',"objectAttributeValues":[{"value": "' + $value_atr1 +'"}]} , 
    {"objectTypeAttributeId":' + $id_atr2 +',"objectAttributeValues":[{"value": "' + $value_atr2 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr3 +',"objectAttributeValues":[{"value": "' + $value_atr3 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr4 +',"objectAttributeValues":[{"value": "' + $value_atr4 +'"}]} 
    ]}'
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/' + $id_object + ''
    Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function jira_CreateObject {
    param (
        $name_object,
        $objectTypeId,
        $id_atr_name,
        $Headers_jira
    )
    $json = '{"objectTypeId": ' + $objectTypeId + ' ,
    "attributes":[{"objectTypeAttributeId":'+ $id_atr_name + ',
    "objectAttributeValues":[{"value": "' + $name_object +'"}]}]}'
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/create'
    Invoke-WebRequest -Uri $uri  -Method POST -Headers $Headers_jira -Body $json
    
}

Function Connect-Zabbix_PSCredential {
    Param (
        [Parameter(Mandatory=$True)]
        [PSCredential]$PSCredential
        ,
        [Parameter(Mandatory=$True)]
        [string]$IPAdress
        ,
        [Switch]$UseSSL
    )
    $Body = @{
	    jsonrpc = "2.0"
	    method = "user.login"
	    params = @{
		    user = $PSCredential.UserName
		    password = $PSCredential.GetNetworkCredential().Password
	    }
	    id = 1
	    auth = $null
    }

    $BodyJSON = ConvertTo-Json $Body

    Switch ($UseSSL.IsPresent) {
        $False {$Protocol = "http"}
        $True {$Protocol = "https"}
    }
    $URL = $Protocol+"://$IPAdress/zabbix"
    $Res = Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post

    if (($Res | Get-Member | Select-Object -ExpandProperty Name) -contains "result") {
        #Connection successful
        $Global:ZabbixSession = $Res | Select-Object jsonrpc,@{Name="Session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
        Write-Host ("Successfuly connected to " + $URL)
    }
    else {
        #Connection error
        $Res.error
    }
}

Function Connect-Zabbix {
    Param (
        $user,
        $pass,
        [Parameter(Mandatory=$True)]
        [string]$IPAdress,
        [Switch]$UseSSL
    )
    $Body = @{
	    jsonrpc = "2.0"
	    method = "user.login"
	    params = @{
		    user = $user
		    password = $pass
	    }
	    id = 1
	    auth = $null
    }

    $BodyJSON = ConvertTo-Json $Body

    Switch ($UseSSL.IsPresent) {
        $False {$Protocol = "http"}
        $True {$Protocol = "https"}
    }
    $BodyJSON
    $URL = $Protocol+"://$IPAdress/zabbix"
    $Res = Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post

    if (($Res | Get-Member | Select-Object -ExpandProperty Name) -contains "result") {
        #Connection successful
        $Global:ZabbixSession = $Res | Select-Object jsonrpc,@{Name="Session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
        Write-Host ("Successfuly connected to " + $URL)
    }
    else {
        #Connection error
        $Res.error
    }
}

Function Get-ZabbixHost {
    Param (
        $HostName
        ,
        $HostID
    )
    $Body = @{
	    jsonrpc = $ZabbixSession.jsonrpc
	    method = "host.get"
	    params = @{
		    output = "extend"
            selectGroups = @(
                "groupid",
                "name"
            )
            selectParentTemplates = @(
                "templateid",
                "name"
            )
		    filter = @{
			    host = $HostName
		    }
            hostids = $HostID
	    }
	    id = $ZabbixSession.id
	    auth = $ZabbixSession.Session
    }

    $BodyJSON = ConvertTo-Json $Body
    $Res =  Invoke-RestMethod ($ZabbixSession.URL + "/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post

    if (($Res | Get-Member | Select-Object -ExpandProperty Name) -contains "result") {
        #Command successful
        $Res.result
    }
    else {
        #Command error
        $Res.error
    }
}

function MBtoGB {
    param (
        $in
    )
    if ($in -lt 1000){
        $out = [string] ([int]$in) + " MB"
    }else{
        $out = [string]( [math]::Floor($in / 1024) )  + " GB"
    }
    return $out
}

function rtcloud_disk_decoder {
    param (
        $type_disk
    )
    if ($type_disk -eq "S_STANDARD_ON1"){
        $out = 2.4
    }

    if ($type_disk -eq "H_FAST2"){
        $out = 7
    }

    if ($type_disk -eq "DC_FAST_ON"){
        $out = 7
    }

    if ($type_disk -eq "S_ULTRA7"){
        $out = 20
    }
    return $out
}

function get_list_object_jira {
    param (
        $object_Type_Id,
        $Headers_jira
    )

    $response = Invoke-WebRequest -Uri ("https://jira.otlnal.ru/rest/insight/1.0/iql/objects?objectSchemaId=1&iql=objectTypeId=" + $object_Type_Id + "&resultPerPage=1000") -Method GET -Headers $Headers_jira 
    $jira_object = $response.content | convertfrom-json
    #$jira_host.objectEntries.label

    return $jira_object
}

$user = "p.morozov"
$pass = "10Rhensitr"
$domain = '@otlnal'


$Headers_jira = jira_auth -user $user -pass $pass

# get list Host ( JIRA )
$jira_host = get_list_object_jira -Headers_jira $Headers_jira -object_Type_Id "2"

# get list Database ( JIRA )
$jira_db = get_list_object_jira -Headers_jira $Headers_jira -object_Type_Id "13"

# get list hypervisor ( JIRA )
$jira_hypervisor = get_list_object_jira -Headers_jira $Headers_jira -object_Type_Id "34"
$filter_jira_hypervisor_rtcloud = $jira_hypervisor.objectEntries | where-object {$_.name -like "otlnal-*"}

# get list Zabbix host ( ZABBIX )
Connect-Zabbix -IPAdress zabbix -user $user -pass $pass
$zabbix_host = Get-ZabbixHost | where-object error -eq ""
$filter_zabbix_host = $zabbix_host | 
where-object { ($_.status -eq 0) -and ($_.name -notlike "sw-*") -and ($_.name -notlike "gw-*") -and ($_.name -notlike "10.*") } 

# get list VM ( RTCloud ) 
# Важные поля: ft name, momoryMB, numberofcpus, status, storageProfileName, guestOs
$Headers_rtcloud = rtcloud_auth -user $user -pass $pass -domain $domain
$rtcloud_Response = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/vms/query?pageSize=128' -Method GET -Headers $Headers_rtcloud
[xml]$vm_rtcloud = $rtcloud_Response.content
$filter_vm_rtcloud = $vm_rtcloud.QueryResultRecords.VMRecord | where-object {$_.container -notlike "https://dc.rtcloud.ru/api/vAppTemplate*"}

# get list database ( MSSQL ) 
# Доступные поля: Containment Type, Collation, Owner, Compat. Level, Recovery model, space avalible, Size, Status, Name
$list_mssql_instance = @("SQL-GRIND", "1c_sql", "NSK-BSV-QA2", "adwh", "nsk-sqleps-01", "SQL-1C2", "srv-luxbasedb-1", "SQLCLU2-1" )
$mssql_database = @()
$hashtable_db_server = @{}
foreach ($i in $list_mssql_instance){
    $mssql_database_tmp = Get-SqlInstance -ServerInstance $i | Get-SqlDatabase # подключение к инстансу субд и получение списка баз
    $mssql_database += $mssql_database_tmp 
    foreach ($ii in $mssql_database_tmp){
        $hashtable_db_server[$ii.name] = $i
    }
}


$rtcloud_vdc = $filter_vm_rtcloud.vdc | Sort-Object | Get-Unique
# create hashtable RTCloud VDC (href VDC : name VDC )
$hashtable_rtcloud_vdc = @{}
foreach($i in $rtcloud_vdc){
    $rtcloud_Response = Invoke-WebRequest -Uri $i -Method GET -Headers $Headers_rtcloud
    [xml]$rtcloud_Response_xml = $rtcloud_Response.content
    $hashtable_rtcloud_vdc[$rtcloud_Response_xml.vdc.href]=$rtcloud_Response_xml.vdc.name
}

# create hashtable jira hypervosir (name hypervisor : id )
$hashtable_jira_vdc = @{}
foreach($i in $jira_hypervisor.objectEntries){
    $hashtable_jira_vdc[$i.name]=$i.id
}

# create hashtable jira VM (name vm : id )
$hashtable_jira_host = @{}
foreach($i in $jira_host.objectEntries){
    $hashtable_jira_host[$i.name]=$i.id
}

# create $hashtable_rtcloud_jira_vdc (href vdc rtcloud : hypervisor id )
@($hashtable_rtcloud_vdc.Keys) | ForEach-Object { $hashtable_rtcloud_jira_vdc[$_] = $hashtable_jira_vdc[$hashtable_rtcloud_vdc[$_]] }

# create hashtable jira database (name database : id )
$hashtable_jira_db = @{}
foreach($i in $jira_db.objectEntries){
    $hashtable_jira_db[$i.name]=$i.id
}

# add object: database ( MSSQL -> Jira ) 
foreach($i in $mssql_database){
    if ($jira_db.objectEntries.name -notcontains $i.name){
        jira_CreateObject -objectTypeId "13" -id_atr_name "50" -name_object $i.name -Headers_jira $headers_jira
    }
}

# change attr: type, size, available size -> database ( MSSQL -> Jira ) 
foreach ($i in $mssql_database){
    jira_changeAtr4 -Headers_jira $Headers_jira -id_object $hashtable_jira_db[$i.name] -id_atr1 460 -id_atr2 461 -id_atr3 459 -value_atr1  (MBtoGB -in ($i.Size)) -value_atr2 (MBtoGB -in ($i.SpaceAvailable / 1024 ) ) -value_atr3 $i.RecoveryModel -id_atr4 161 -value_atr4 $hashtable_jira_host[$hashtable_db_server[$i.name]]
}

# change attr: online -> host ( Powershell test-connection -> Jira ) 
foreach ($i in $jira_host.objectentries ){
    if ((test-connection -Count 1 $i.name -quiet) -eq $True) {
        jira_changeAtr -value_atr "1" -id_object $i.id -id_atr "436"
    } else {
        jira_changeAtr -value_atr "7" -id_object $i.id -id_atr "436"
    }
}

# change attr: ip -> host ( Powershell Resolve-DnsName -> Jira ) 
foreach ($i in $jira_host.objectentries ){
    $ip = Resolve-DnsName $i.name
    jira_changeAtr -value_atr $ip.IPAddress -id_object $i.id -id_atr "387"
}

<#
# change attr: OS, RAM -> host ( Powershell Get-ComputerInfo -> Jira ) 
foreach ($i in $jira_host.objectentries ){
    $pc_info = Invoke-Command -ComputerName $i.name -ScriptBlock {Get-ComputerInfo -Property *}    
    if ($null -eq $pc_info){
        Continue
    }
    jira_changeAtr -value_atr ($pc_info.WindowsProductName) -id_object ($i.id) -id_atr "431" 
    Start-Sleep -Milliseconds 1000 # если выставить меньше, джира обезумивает и пытается менять не те атрибуты, которые передаешь в json
    jira_changeAtr -value_atr ($pc_info.WindowsVersion) -id_object ($i.id) -id_atr "432" 
    Start-Sleep -Milliseconds 1000 # если выставить меньше, джира обезумивает и пытается менять не те атрибуты, которые передаешь в json
    jira_changeAtr -value_atr ([math]::Floor($pc_info.OsTotalVisibleMemorySize / 1000000)) -id_object ($i.id) -id_atr "430" 
}
#>

# change attr: status zabbix -> host ( Zabbix -> Jira ) 
foreach ($i in $jira_host.objectEntries) { # 
	if ( $filter_zabbix_host.name -contains  $i.label ) {
        jira_changeAtr -value_atr "1" -id_object $i.id -id_atr "435"
	}else { 
        jira_changeAtr -value_atr "7" -id_object $i.id -id_atr "435"
    }
}


# add object: VM (host)  ( RTCloud -> Jira )
# change attr: hypervisor -> Host
foreach ($i in $filter_vm_rtcloud) { 
	if ( $jira_host.objectEntries.label -notcontains  $i.name ) {
        $res = jira_CreateObject -objectTypeId "2" -id_atr_name "6" -name_object $i.name -Headers_jira $headers_jira
        $res = $res.content | convertfrom-json
        jira_changeAtr -id_atr 383 -id_object $res.id -value_atr $hashtable_rtcloud_jira_vdc[$i.vdc] 
	}
}

# change attr: CPU -> Host ( RTCloud -> Jira )
foreach ($i in $filter_vm_rtcloud){
    jira_changeAtr -id_object $hashtable_jira_host[$i.name] -id_atr "437" -value_atr $i.numberOfCpus
    #$hashtable_jira_host[$i.name] # id
}

# change attr: RAM -> Host ( RTCloud -> Jira )
foreach ($i in $filter_vm_rtcloud){
    jira_changeAtr -id_object $hashtable_jira_host[$i.name] -id_atr "513" -value_atr ([math]::Round($i.memoryMB / 1024, 1))  -replace ("," , ".")
    #$hashtable_jira_host[$i.name] # id
}

# change attr: OS -> Host ( RTCloud -> Jira )
foreach ($i in $filter_vm_rtcloud){
    if ($i.guestOs -notlike "Microsoft*"){
        jira_changeAtr -id_object $hashtable_jira_host[$i.name] -id_atr "513" -value_atr $i.guestOs
    }    
}

# create hashtable RTCloud VM (name VM : GHz core )
$hashtable_jira_GHz = @{}
foreach ($i in $filter_vm_rtcloud){
    if ($i.vdc -eq "https://dc.rtcloud.ru/api/vdc/319bde7e-d2e2-4098-b8e7-f8f30884d283"){
        # otlnal 2.5
        $hashtable_jira_GHz[$i.name]=2.5
        #jira_changeAtr -id_object $hashtable_jira_host[$i.name] -id_atr "383" -value_atr "136"
    }
    if ($i.vdc -eq "https://dc.rtcloud.ru/api/vdc/31ed76b7-229a-4949-ac7d-ebe0ae7c990f"){
        # otlnal 1.0
        $hashtable_jira_GHz[$i.name]=1.0
        #jira_changeAtr -id_object $hashtable_jira_host[$i.name] -id_atr "383" -value_atr "134"
    }
    if ($i.vdc -eq "https://dc.rtcloud.ru/api/vdc/0f871e7f-4a1a-4bb8-9779-c5fe422c1753"){
        # otlnal 3.0
        $hashtable_jira_GHz[$i.name]=3.0
        #jira_changeAtr -id_object $hashtable_jira_host[$i.name] -id_atr "383" -value_atr "137"
    }
}


# change attr: cost -> host ( RTCloud -> Jira )
#! вынести стоимость каждого ресурса в конфиг
foreach ($i in $filter_vm_rtcloud.href){
    $rtcloud_Response3 = Invoke-WebRequest -Uri $i -Method GET -Headers $Headers_rtcloud
    [xml]$disk_rtcloud = $rtcloud_Response3.content
    #$disk_rtcloud.vm.VmSpecSection.DiskSection.DiskSettings
    #$disk_rtcloud.vm.VmSpecSection.DiskSection.DiskSettings.StorageProfile
    # стоимость дисков
    $rub_all_disk = 0
    foreach ($ii in $disk_rtcloud.vm.VmSpecSection.DiskSection.DiskSettings ){
        $rub_Gb_disk = rtcloud_disk_decoder($ii.StorageProfile.name) 
        #$rub_Gb_disk
        $rub_disk = $ii.SizeMb / 1024 * $rub_Gb_disk * 1.2
        #$rub_disk 
        $rub_all_disk += $rub_disk 
    }
    $rub_cpu = [int]$disk_rtcloud.vm.VmSpecSection.NumCpus * 175 * 1.2 * [int]$hashtable_jira_GHz[$disk_rtcloud.vm.name]
    $rub_ram = $disk_rtcloud.vm.VmSpecSection.MemoryResourceMb.Configured / 1024 * 250 * 1.2
    $rub_all = $rub_all_disk + $rub_cpu + $rub_ram
    jira_changeAtr -value_atr ([int]$rub_all) -id_object $hashtable_jira_host[$disk_rtcloud.vm.name] -id_atr "512"
}

# change attr: Hypervisor -> host ( RTCloud -> Jira )
foreach ($i in $filter_vm_rtcloud){
    jira_changeAtr -id_atr 383 -id_object $hashtable_jira_host[$i.name] -value_atr $hashtable_rtcloud_jira_vdc[$i.vdc] 
}



