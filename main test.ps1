Import-Module -Name C:\Users\p.morozov.OTLNAL\Desktop\gitproject\Jira-Insight-integration\jira-integration
# Get-Command -Module jira-integration

# read config
$config = Get-Content (join-path -path $PSScriptRoot -childpath '/config.json') | Out-String | ConvertFrom-Json

### RTCloud 

# auth RTCloud
$Headers_rtcloud = get-RTCloudAuthHeader -user $config.cred.user -pass $config.cred.pass -domain $config.cred.domain

# get list VM ( RTCloud ) 
# Важные поля: ft name, momoryMB, numberofcpus, status, storageProfileName, guestOs
# $rtcloud_Response = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/vms/query?pageSize=500' -Method GET -Headers $Headers_rtcloud
# [xml]$vm_rtcloud = $rtcloud_Response.content
$rtcloud_Response = Invoke-RestMethod -Method 'GET' -Uri 'https://dc.rtcloud.ru/api/vms/query?pageSize=500' -Headers $Headers_rtcloud
$filter_vm_rtcloud = $rtcloud_Response.QueryResultRecords.VMRecord | where-object {$_.container -notlike "https://dc.rtcloud.ru/api/vAppTemplate*"}

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


##################################################################################
# https://kb.selectel.ru/docs/cloud-services/vmware/faq/

#для московских ресурсов: vcd-msk.selectel.ru;
#для ресурсов в Санкт-Петербурге: vcd.selectel.ru.

#У нас используется vCloud Director 9.7, который поддерживает версии API 20.0-32.0.