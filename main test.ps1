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

function jira_DeleteObject {
    param (
        $id_object,
        $Headers_jira
    )
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/767'
    Invoke-WebRequest -Uri ('https://jira.otlnal.ru/rest/insight/1.0/object/' + $id_object)  -Method DELETE -Headers $Headers_jira
    
}

function jira_changeAtr {
    param (
        $value_atr,
        $id_object,
        $id_atr,
        $Headers_jira
    )
    $json = '{"attributes":[{"objectTypeAttributeId":' + $id_atr +',"objectAttributeValues":[{"value": "' + $value_atr +'"}]}]}'
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/' + $id_object + ''
    $out = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json # -ErrorVariable a -ErrorAction SilentlyContinue | Out-Null
    
}

function jira_changeAtr3 {
    param (
        $value_atr1,
        $value_atr2,
        $value_atr3,
        $id_object,
        $id_atr1,
        $id_atr2,
        $id_atr3,
        $Headers_jira
    )
    $json = '{"attributes":[  
    {"objectTypeAttributeId":' + $id_atr1 +',"objectAttributeValues":[{"value": "' + $value_atr1 +'"}]} , 
    {"objectTypeAttributeId":' + $id_atr2 +',"objectAttributeValues":[{"value": "' + $value_atr2 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr3 +',"objectAttributeValues":[{"value": "' + $value_atr3 +'"}]} 
    ]}'
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
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
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function jira_changeAtr5 {
    param (
        $value_atr1,
        $value_atr2,
        $value_atr3,
        $value_atr4,
        $value_atr5,
        $id_object,
        $id_atr1,
        $id_atr2,
        $id_atr3,
        $id_atr4,
        $id_atr5,
        $Headers_jira
    )
    $json = '{"attributes":[  
    {"objectTypeAttributeId":' + $id_atr1 +',"objectAttributeValues":[{"value": "' + $value_atr1 +'"}]} , 
    {"objectTypeAttributeId":' + $id_atr2 +',"objectAttributeValues":[{"value": "' + $value_atr2 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr3 +',"objectAttributeValues":[{"value": "' + $value_atr3 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr4 +',"objectAttributeValues":[{"value": "' + $value_atr4 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr5 +',"objectAttributeValues":[{"value": "' + $value_atr5 +'"}]} 
    ]}'
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
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
    $URL = $Protocol+"://$IPAdress/zabbix"
    $Res = Invoke-RestMethod ("$URL/api_jsonrpc.php") -ContentType "application/json" -Body $BodyJSON -Method Post

    if (($Res | Get-Member | Select-Object -ExpandProperty Name) -contains "result") {
        #Connection successful
        $Global:ZabbixSession = $Res | Select-Object jsonrpc,@{Name="Session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
        #Write-Host ("Successfuly connected to " + $URL)
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

function get-jira_Find_Object_Type_Attributes {
    param (
        $object_schema_id
    )
    $uri = 'https://jira.otlnal.ru/rest/insight/1.0/objectschema/' + $object_schema_id + '/attributes'
    $response = Invoke-WebRequest -Uri $uri  -Method GET -Headers $Headers_jira
    $Object_Type_Attributes = $response.content | convertfrom-json
    return $Object_Type_Attributes
}

# read config
$config = Get-Content (join-path -path $PSScriptRoot -childpath '/config.json') | Out-String | ConvertFrom-Json


########################
<#
# ( Powershell Resolve-DnsName -> Jira ) 
foreach ($i in $jira_host.objectentries ){
    if ( (Resolve-DnsName $i.name -ErrorAction SilentlyContinue) -eq 'Null'){
        ($i.name).ToString() + ' : Нет имени в DNS'
    }
}
#>
######################

##########################
### RTCloud 

# auth RTCloud
$Headers_rtcloud = rtcloud_auth -user $config.cred.user -pass $config.cred.pass -domain $config.cred.domain

# get list VM ( RTCloud ) 
# Важные поля: ft name, momoryMB, numberofcpus, status, storageProfileName, guestOs
$rtcloud_Response = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/vms/query?pageSize=500' -Method GET -Headers $Headers_rtcloud
[xml]$vm_rtcloud = $rtcloud_Response.content
$filter_vm_rtcloud = $vm_rtcloud.QueryResultRecords.VMRecord | where-object {$_.container -notlike "https://dc.rtcloud.ru/api/vAppTemplate*"}

# create hashtable RTCloud VDC (href VDC : name VDC )
# get list VDC ( RTCloud ) 
$rtcloud_vdc_href = $filter_vm_rtcloud.vdc | Sort-Object | Get-Unique
$hashtable_rtcloud_vdc = @{}
<#
$vdc_rtcloud.name
$vdc_rtcloud.VCpuInMhz2 # MHz core
$vdc_rtcloud.ResourceEntities.ResourceEntity # list vApp
$vdc_rtcloud.ComputeCapacity.cpu # 
$vdc_rtcloud.ComputeCapacity.memory #
#>
$rtcloud_vdc = @()
foreach ($i in $rtcloud_vdc_href) {
    $rtcloud_Response = Invoke-WebRequest -Uri $i -Method GET -Headers $Headers_rtcloud
    [xml]$vdc_rtcloud_xml = $rtcloud_Response.content
    $rtcloud_vdc += $vdc_rtcloud_xml.vdc
    $hashtable_rtcloud_vdc[$vdc_rtcloud_xml.vdc.href]=$vdc_rtcloud_xml.vdc.name
}

##########################


# change attr: cost allocated, cost used -> hypervisor ( RTCloud -> Jira ) 
# get list VdcStorageProfile $rtcloud_disk ( RTCloud )
$rtcloud_disk = @()
# $rtcloud_disk.VdcStorageProfile
# properties: $rtcloud_disk.VdcStorageProfile. name, limit, StorageUsedMB
foreach ($i in $rtcloud_vdc) { # стоимость дисков в одном ЦОДе
    $rub_limit_disk = 0
    $rub_used_disk = 0
    foreach($ii in $i.VdcStorageProfiles.VdcStorageProfile){ # стоимость диска в одном storageProfile 
        $rtcloud_Response = Invoke-WebRequest -Uri $ii.href -Method GET -Headers $Headers_rtcloud
        [xml]$rtcloud_disk_xml = $rtcloud_Response.content
        $rtcloud_disk += $rtcloud_disk_xml
    
        $rub_Gb_disk = $config.rtcloud.cost.disk.($rtcloud_disk_xml.VdcStorageProfile.name) 
        $rub_limit_disk += $rtcloud_disk_xml.VdcStorageProfile.Limit / 1024 * $rub_Gb_disk
        $rub_used_disk += $rtcloud_disk_xml.VdcStorageProfile.StorageUsedMB / 1024 * $rub_Gb_disk
    }

    $rub_all_cpu = $i.ComputeCapacity.cpu.Allocated / 1000 * $config.rtcloud.cost.cpu
    $rub_used_cpu = $i.ComputeCapacity.cpu.used / 1000 * $config.rtcloud.cost.cpu

    $rub_all_mem = $i.ComputeCapacity.memory.Allocated / 1024 * $config.rtcloud.cost.ram
    $rub_used_mem = $i.ComputeCapacity.memory.used / 1024 * $config.rtcloud.cost.ram

    $rub_all = ( $rub_limit_disk + $rub_all_cpu + $rub_all_mem ) * $config.rtcloud.cost.nds
    $rub_used = ( $rub_used_disk + $rub_used_cpu + $rub_used_mem ) * $config.rtcloud.cost.nds

    $a = [int]$rub_all
    $b = [int]$rub_used
    jira_changeAtr2 -id_atr1 536 -value_atr1 $a -id_atr2 537 -value_atr2 $b -id_object $hashtable_jira_vdc[$i.name] -Headers_jira $Headers_jira
    
}