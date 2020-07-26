function get-JiraAuthHeader {
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

function Remove-JiraObject {
    param (
        $id_object,
        $Headers_jira
    )
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/767'
    Invoke-WebRequest -Uri ('https://jira.' + $config.domain + '/rest/insight/1.0/object/767' + $id_object)  -Method DELETE -Headers $Headers_jira
    
}

function Set-JiraAttribute {
    param (
        $value_atr,
        $id_object,
        $id_atr,
        $Headers_jira
    )
    $json = '{"attributes":[{"objectTypeAttributeId":' + $id_atr +',"objectAttributeValues":[{"value": "' + $value_atr +'"}]}]}'
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/' + $id_object + ''
    $out = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json # -ErrorVariable a -ErrorAction SilentlyContinue | Out-Null
    
}

function Set-JiraAttribute2 {
    param (
        $value_atr1,
        $value_atr2,
        $id_object,
        $id_atr1,
        $id_atr2,
        $Headers_jira
    )
    $json = '{"attributes":[  
    {"objectTypeAttributeId":' + $id_atr1 +',"objectAttributeValues":[{"value": "' + $value_atr1 +'"}]} , 
    {"objectTypeAttributeId":' + $id_atr2 +',"objectAttributeValues":[{"value": "' + $value_atr2 +'"}]} 
    ]}'
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function Set-JiraAttribute3 {
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
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function Set-JiraAttribute4 {
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
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function Set-JiraAttribute5 {
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
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function Set-JiraAttribute6 {
    param (
        $value_atr1,
        $value_atr2,
        $value_atr3,
        $value_atr4,
        $value_atr5,
        $value_atr6,
        $id_object,
        $id_atr1,
        $id_atr2,
        $id_atr3,
        $id_atr4,
        $id_atr5,
        $id_atr6,
        $Headers_jira
    )
    $json = '{"attributes":[  
    {"objectTypeAttributeId":' + $id_atr1 +',"objectAttributeValues":[{"value": "' + $value_atr1 +'"}]} , 
    {"objectTypeAttributeId":' + $id_atr2 +',"objectAttributeValues":[{"value": "' + $value_atr2 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr3 +',"objectAttributeValues":[{"value": "' + $value_atr3 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr4 +',"objectAttributeValues":[{"value": "' + $value_atr4 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr5 +',"objectAttributeValues":[{"value": "' + $value_atr5 +'"}]} ,
    {"objectTypeAttributeId":' + $id_atr6 +',"objectAttributeValues":[{"value": "' + $value_atr6 +'"}]} 
    ]}'
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/' + $id_object + ''
    $a = Invoke-WebRequest -Uri $uri  -Method PUT -Headers $Headers_jira -Body $json
    
}

function Add-JiraObject {
    param (
        $name_object,
        $objectTypeId,
        $id_atr_name,
        $Headers_jira
    )
    $json = '{"objectTypeId": ' + $objectTypeId + ' ,
    "attributes":[{"objectTypeAttributeId":'+ $id_atr_name + ',
    "objectAttributeValues":[{"value": "' + $name_object +'"}]}]}'
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/object/create'
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
        #Write-Host ("Successfuly connected to " + $URL)
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
        return $Res | Select-Object jsonrpc,@{Name="Session";Expression={$_.Result}},id,@{Name="URL";Expression={$URL}}
        #Write-Host ("Successfuly connected to " + $URL)
    }
    else {
        #Connection error
        $Res.error
    }
}

Function Get-ZabbixHost {
    Param (
        $HostName,
        $HostID,
        $ZabbixSession
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

function Format-MBtoGB {
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

<#
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
#>
function Get-JiraObject {
    param (
        $object_Type_Id,
        $Headers_jira
    )

    $response = Invoke-WebRequest -Uri ('https://jira.' + $config.domain + '/rest/insight/1.0/iql/objects?objectSchemaId=1&iql=objectTypeId=' + $object_Type_Id + '&resultPerPage=1000') -Method GET -Headers $Headers_jira 
    $jira_object = $response.content | convertfrom-json
    #$jira_host.objectEntries.label

    return $jira_object
    <#
    .SYNOPSIS
    Получает список объектов из Jira
    #>
    
}


function Get-JiraFindObjectTypeAttributes {
    param (
        $object_schema_id
    )
    $uri = 'https://jira.' + $config.domain + '/rest/insight/1.0/objectschema/' + $object_schema_id + '/attributes'
    $response = Invoke-WebRequest -Uri $uri  -Method GET -Headers $Headers_jira
    $Object_Type_Attributes = $response.content | convertfrom-json
    return $Object_Type_Attributes
}

function get-RTCloudAuthHeader {
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