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
function Get-JiraObject {
    param (
        $object_Type_Id,
        $Headers_jira
    )

    $response = Invoke-WebRequest -Uri ('https://jira.' + $config.domain + '/rest/insight/1.0/iql/objects?objectSchemaId=1&iql=objectTypeId=' + $object_Type_Id + '&resultPerPage=1000') -Method GET -Headers $Headers_jira 
    $jira_object = $response.content | convertfrom-json
    #$jira_host.objectEntries.label

    return $jira_object
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

# read config
$config = Get-Content (join-path -path $PSScriptRoot -childpath '/config.json') | Out-String | ConvertFrom-Json

###########################
### JIRA 

# auth JIRA
$Headers_jira = get-JiraAuthHeader -user $config.cred.user -pass $config.cred.pass





scp -r p.morozov@srv-ansible-01:/home/p.morozov/mikrotik_facts C:\Users\p.morozov.OTLNAL\Downloads\1

$list_file = Get-ChildItem 'C:\Users\p.morozov.OTLNAL\Downloads\1\mikrotik_facts'
$list_mikro = @()
foreach ($i in $list_file ) {
    $list_mikro += $i | Get-Content | ConvertFrom-Json 
}

#$list_mikro.ansible_facts.ansible_net_hostname # 542
#$list_mikro.ansible_facts.ansible_net_all_ipv4_addresses # 543
#$list_mikro.ansible_facts.ansible_net_version # 544
#$list_mikro.ansible_facts.ansible_net_model # 545

foreach ($i in $list_mikro){
    $res = Add-JiraObject -objectTypeId 51 -name_object $i.ansible_facts.ansible_net_hostname -id_atr_name 539 -Headers_jira $Headers_jira
    $res = $res.content | convertfrom-json
    Set-JiraAttribute4 -Headers_jira $headers_jira -id_object $res.id -id_atr1 542 -id_atr2 543 -id_atr3 544 -value_atr1 $i.ansible_facts.ansible_net_hostname -value_atr2 $i.ansible_facts.ansible_net_all_ipv4_addresses -value_atr3 $i.ansible_facts.ansible_net_version -id_atr4 545 -value_atr4 $i.ansible_facts.ansible_net_model

}

# env ANSIBLE_LOAD_CALLBACK_PLUGINS=yes ANSIBLE_STDOUT_CALLBACK=log_plays ansible-playbook -f 20 /home/ansible/playbooks/mikrotik-facts.yml
