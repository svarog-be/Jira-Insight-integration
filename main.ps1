[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")

Import-Module .\jira-integration
If ( ((get-WindowsFeature -Name Hyper-V-PowerShell).InstallState) -ne "Installed" ){
    Install-WindowsFeature -Name Hyper-V-PowerShell
}
import-module Hyper-V -Prefix hyperv
If ( (Get-PackageProvider -Name NuGet).Version -lt '2.8.5.201' ){
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}
If ( (Get-Module -Name sqlserver).name -ne 'SqlServer' ){
    install-module sqlserver -Force
}

# read config
try { 
    $config = Get-Content (join-path -path $PSScriptRoot -childpath '/config.json') | Out-String | ConvertFrom-Json
    Set-Log "read config OK"
} 
catch { 
    "config not available"
    break 
}
 

###########################
### JIRA 

# auth JIRA
$Headers_jira = get-JiraAuthHeader -user $config.cred.jira.user -pass $config.cred.jira.pass

# get list Object_Type_Attributes ( JIRA )
$jira_Object_Type_Attributes = Get-JiraFindObjectTypeAttributes -object_schema_id $config.jira.object_schema_id
set-log "jira_Object_Type_Attributes ", $jira_Object_Type_Attributes.count

# get Host ( JIRA )
$jira_host = Get-JiraObject -Headers_jira $Headers_jira -object_Type_Id "2"
set-log "jira_host ", $jira_host.objectEntries.count

# create hashtable jira VM (name vm : id )
$hashtable_jira_host = @{}
foreach($i in $jira_host.objectEntries){
    $hashtable_jira_host[$i.name]=$i.id
}

# get list Database ( JIRA )
$jira_db = Get-JiraObject -Headers_jira $Headers_jira -object_Type_Id "13"
set-log "jira_db "

# create hashtable jira database (name database : id )
$hashtable_jira_db = @{}
foreach($i in $jira_db.objectEntries){
    $hashtable_jira_db[$i.name]=$i.id
}

# get list hypervisor ( JIRA )
$jira_hypervisor = Get-JiraObject -Headers_jira $Headers_jira -object_Type_Id "34"
$filter_jira_hypervisor_rtcloud = $jira_hypervisor.objectEntries | where-object {$_.name -like "otlnal-*"}
set-log "jira_hypervisor"

# create hashtable jira hypervosir (name hypervisor : id )
$hashtable_jira_vdc = @{}
foreach($i in $jira_hypervisor.objectEntries){
    $hashtable_jira_vdc[$i.name.ToUpper()]=$i.id
}

# get list site ( JIRA )
# $jira_site.objectEntries.id/name
$jira_site = Get-JiraObject -Headers_jira $Headers_jira -object_Type_Id "50"
set-log "jira_site"

# create hashtable jira site (name site : id )
$hashtable_jira_site = @{}
foreach($i in $jira_site.objectEntries){
    $hashtable_jira_site[$i.name]=$i.id
}

########################
### ZABBIX 

# auth ZABBIX
$Headers_Zabbix = Connect-Zabbix -IPAdress zabbix -user $config.cred.zabbix.user -pass $config.cred.zabbix.pass

# get list Zabbix host ( ZABBIX )
$zabbix_host = Get-ZabbixHost -ZabbixSession $Headers_Zabbix | where-object error -eq ""
$filter_zabbix_host = $zabbix_host | 
where-object { ($_.status -eq 0) -and ($_.name -notlike "sw-*") -and ($_.name -notlike "gw-*") -and ($_.name -notlike "10.*") } 
set-log "zabbix_host"
##########################
### RTCloud 

# auth RTCloud
$Headers_rtcloud = get-RTCloudAuthHeader -user $config.cred.rtcloud.user -pass $config.cred.rtcloud.pass -domain $config.cred.domain

# get list VM ( RTCloud ) 
# Важные поля: ft name, momoryMB, numberofcpus, status, storageProfileName, guestOs
# $rtcloud_Response = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/vms/query?pageSize=500' -Method GET -Headers $Headers_rtcloud
# [xml]$vm_rtcloud = $rtcloud_Response.content
$rtcloud_Response = Invoke-RestMethod -Method 'GET' -Uri 'https://dc.rtcloud.ru/api/vms/query?pageSize=500' -Headers $Headers_rtcloud
$filter_vm_rtcloud = $rtcloud_Response.QueryResultRecords.VMRecord | where-object {$_.container -notlike "https://dc.rtcloud.ru/api/vAppTemplate*"}
set-log "filter_vm_rtcloud"
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
set-log "rtcloud_vdc"
##########################
### MSSQL 

# get list database ( MSSQL ) 
# create hashtable_db_server ( MSSQL )
# Доступные поля: Containment Type, Collation, Owner, Compat. Level, Recovery model, space avalible, Size, Status, Name
$mssql_database = @()
$hashtable_db_server = @{}
foreach ($i in $config.MSSQL){
    try{ 
        $mssql_database_tmp = Get-SqlInstance -ServerInstance $i -ErrorAction 'Stop' | Get-SqlDatabase # подключение к инстансу субд и получение списка баз
    }
    catch{
        set-log "ERROR: not available " + $i # sql инстанс недоступен
        Continue
    }
    
    $mssql_database += $mssql_database_tmp 
    foreach ($ii in $mssql_database_tmp){
        $hashtable_db_server[$ii.name] = $i
    }
}

set-log ("DBMS: " + [string]($hashtable_db_server.values| Sort-Object | Get-Unique).count + " out of " + [string]($config.MSSQL).count)
set-log( "get database: " + [string]$mssql_database.count )
##############################
### IIS 

# get list iis site ( IIS )
$iis_site = @()
$iis_site += Invoke-Command -ComputerName $config.iis -ScriptBlock {get-iissite }

# изменяет iis_site.state для проставления статуса сайт в JIRA 
foreach ($i in $iis_site){
    if ($i.state -eq "Started"){
        $i.state = "1"
    }else {$i.state = "7"}
}
set-log "iis_site"

$iis_site = $iis_site | Where-Object {$_.name -ne 'Default Web Site'} # Default Web Site есть на каждом инстансе и не имеет смысла добавлять его в JIRA

# get iis path sites ( IIS ) 
$list_iis_path_sites = @()
$list_iis_path_sites += Invoke-Command -ComputerName $config.iis -ScriptBlock { (Get-IISServerManager).sites | foreach { [pscustomobject]@{Name=$_.Name; path=$_.Applications.VirtualDirectories.PhysicalPath}} }
$list_iis_path_sites = $list_iis_path_sites | Where-Object {$_.name -ne 'Default Web Site'} # Default Web Site есть на каждом инстансе и не имеет смысла добавлять его в JIRA
set-log "list_iis_path_sites"


##########################
### С зависимостями 

# create $hashtable_rtcloud_jira_vdc (href vdc rtcloud : hypervisor id )
$hashtable_rtcloud_jira_vdc = @{}
@($hashtable_rtcloud_vdc.Keys) | ForEach-Object { $hashtable_rtcloud_jira_vdc[$_] = $hashtable_jira_vdc[$hashtable_rtcloud_vdc[$_]] }

# add object: database ( MSSQL -> Jira ) 
foreach($i in $mssql_database){
    if ($jira_db.objectEntries.name -notcontains $i.name){
        Add-JiraObject -objectTypeId "13" -id_atr_name "50" -name_object $i.name -Headers_jira $headers_jira
    }
}
set-log "add object: database ( MSSQL -> Jira )"

# change attr: type, size, available size, LastBackupDate -> database ( MSSQL -> Jira ) 
foreach ($i in $mssql_database){
    Set-JiraAttribute5 -Headers_jira $Headers_jira -id_object $hashtable_jira_db[$i.name] `
    -id_atr1 460 -value_atr1  (Format-MBtoGB -in ($i.Size)) `
    -id_atr2 461 -value_atr2 (Format-MBtoGB -in ($i.SpaceAvailable / 1024 ) ) `
    -id_atr3 459 -value_atr3 $i.RecoveryModel `
    -id_atr4 161 -value_atr4 $hashtable_jira_host[$hashtable_db_server[$i.name]] `
    -id_atr5 549 -value_atr5 $i.LastBackupDate.GetDateTimeFormats('g')[0]
    
}
set-log "change attr: type, size, available size, LastBackupDate -> database ( MSSQL -> Jira )"

<#
# change attr: online -> host ( Powershell test-connection -> Jira )
foreach ($i in $jira_host.objectentries ){
    if ((test-connection -Count 1 $i.name -quiet -ErrorAction SilentlyContinue ) -eq $True) {
        Set-JiraAttribute -value_atr "1" -id_object $i.id -id_atr "436" -Headers_jira $headers_jira
    } else {
        Set-JiraAttribute -value_atr "7" -id_object $i.id -id_atr "436" -Headers_jira $headers_jira
    }
}
#>

<#
# change attr: ip -> host ( Powershell Resolve-DnsName -> Jira ) 
$change_ok = @()
$change_error = @()
foreach ($i in $jira_host.objectentries ){
    if ( ($ip = Resolve-DnsName $i.name -ErrorAction SilentlyContinue) -ne 'Null'){
        Set-JiraAttribute -value_atr $ip.IPAddress -id_object $i.id -id_atr "387" -Headers_jira $headers_jira
        $change_ok += $i
    }else {
        $change_error += $i
    }
}
($change_ok.count).ToString() + ' : change attr: ip -> host ( Powershell Resolve-DnsName -> Jira )'
($change_error.count).ToString() + ' : ERROR change attr: ip -> host ( Powershell Resolve-DnsName -> Jira )'
#>

# ( Powershell Resolve-DnsName -> Jira ) 
foreach ($i in $jira_host.objectentries ){
    if ( (Resolve-DnsName $i.name -ErrorAction SilentlyContinue) -eq 'Null'){
        ($i.name).ToString() + ' : Нет имени в DNS'
    }
}
set-log "( Powershell Resolve-DnsName -> Jira ) "

<#
# change attr: OS, RAM -> host ( Powershell Get-ComputerInfo -> Jira ) 
foreach ($i in $jira_host.objectentries ){
    $pc_info = Invoke-Command -ComputerName $i.name -ScriptBlock {Get-ComputerInfo -Property *}    
    if ($null -eq $pc_info){
        Continue
    }
    Set-JiraAttribute -value_atr ($pc_info.WindowsProductName) -id_object ($i.id) -id_atr "431" 
    Start-Sleep -Milliseconds 1000 # если выставить меньше, джира обезумивает и пытается менять не те атрибуты, которые передаешь в json
    Set-JiraAttribute -value_atr ($pc_info.WindowsVersion) -id_object ($i.id) -id_atr "432" 
    Start-Sleep -Milliseconds 1000 # если выставить меньше, джира обезумивает и пытается менять не те атрибуты, которые передаешь в json
    Set-JiraAttribute -value_atr ([math]::Floor($pc_info.OsTotalVisibleMemorySize / 1000000)) -id_object ($i.id) -id_atr "430" 
}
#>

# change attr: status zabbix -> host ( Zabbix -> Jira ) 
foreach ($i in $jira_host.objectEntries) { # 
	if ( $filter_zabbix_host.name -contains  $i.label ) {
        Set-JiraAttribute -value_atr "1" -id_object $i.id -id_atr "435" -Headers_jira $headers_jira
	}else { 
        Set-JiraAttribute -value_atr "7" -id_object $i.id -id_atr "435" -Headers_jira $headers_jira
    }
}
set-log "change attr: status zabbix -> host ( Zabbix -> Jira ) "

# add object: VM (host)  ( RTCloud -> Jira )
# change attr: hypervisor -> Host
foreach ($i in $filter_vm_rtcloud) { 
	if ( $jira_host.objectEntries.label -notcontains  $i.name ) {
        $res = Add-JiraObject -objectTypeId "2" -id_atr_name "6" -name_object $i.name -Headers_jira $headers_jira
        $res = $res.content | convertfrom-json
        Set-JiraAttribute -id_atr 383 -id_object $res.id -value_atr $hashtable_rtcloud_jira_vdc[$i.vdc] -Headers_jira $headers_jira
	}
}
set-log "add object: VM (host)  ( RTCloud -> Jira )"

# change attr: Hypervisor, OS, CPU, RAM -> Host ( RTCloud -> Jira )
foreach ($i in $filter_vm_rtcloud){
    [string]$tmp = ""
    $tmp = if($i.status -eq "POWERED_ON") {"1"}else {"7"}
    Set-JiraAttribute5 -id_object $hashtable_jira_host[$i.name] -Headers_jira $headers_jira `
    -id_atr1 513 -value_atr1 ([math]::Round($i.memoryMB / 1024, 1))  -replace ("," , ".") `
    -id_atr2 437 -value_atr2 $i.numberOfCpus `
    -id_atr3 431 -value_atr3 $i.guestOs `
    -id_atr4 383 -value_atr4 $hashtable_rtcloud_jira_vdc[$i.vdc] `
    -id_atr5 436 -value_atr5 $tmp
    #$hashtable_jira_host[$i.name] # id
}
set-log "change attr: Hypervisor, OS, CPU, RAM -> Host ( RTCloud -> Jira )"

# change attr: GHz ядро (438), Доступно логических процессоров (439), used cores (532), Allocated RAM (533), used RAM (534) 
# -> Hypervisor ( RTCloud -> Jira )
foreach ($i in $rtcloud_vdc){
    Set-JiraAttribute5 -id_object $hashtable_jira_vdc[$i.name] -Headers_jira $headers_jira `
    -id_atr1 438 -value_atr1 ($i.VCpuInMhz2 / 1000 )  `
    -id_atr2 439 -value_atr2 ([Math]::Floor($i.ComputeCapacity.cpu.Allocated / $i.VCpuInMhz2 )) `
    -id_atr3 532 -value_atr3 ($i.ComputeCapacity.cpu.used / $i.VCpuInMhz2 ) `
    -id_atr4 533 -value_atr4 ($i.ComputeCapacity.memory.Allocated / 1024) `
    -id_atr5 534 -value_atr5 ($i.ComputeCapacity.memory.used / 1024) 
}
set-log "change attr: GHz ядро (438), Доступно логических процессоров (439), used cores (532), Allocated RAM (533), used RAM (534) -> Hypervisor ( RTCloud -> Jira )"

# create hashtable RTCloud VM (name VM : GHz core )
$hashtable_jira_GHz = @{}
foreach ($i in $filter_vm_rtcloud){
    foreach($ii in $rtcloud_vdc){
        if ($i.vdc -eq $ii.href){
            $hashtable_jira_GHz[$i.name] = ( $ii.VCpuInMhz2 / 1000 )
            break
        }
    }
}

# change attr: cost -> host ( RTCloud -> Jira )
foreach ($i in $filter_vm_rtcloud.href){
    $rtcloud_Response3 = Invoke-WebRequest -Uri $i -Method GET -Headers $Headers_rtcloud
    [xml]$disk_rtcloud = $rtcloud_Response3.content
    #$disk_rtcloud.vm.VmSpecSection.DiskSection.DiskSettings
    #$disk_rtcloud.vm.VmSpecSection.DiskSection.DiskSettings.StorageProfile
    # стоимость дисков
    $rub_all_disk = 0
    foreach ($ii in $disk_rtcloud.vm.VmSpecSection.DiskSection.DiskSettings ){
        #$rub_Gb_disk = rtcloud_disk_decoder($ii.StorageProfile.name) 
        $rub_Gb_disk = $config.rtcloud.cost.disk.($ii.StorageProfile.name)
        #$rub_Gb_disk
        $rub_disk = $ii.SizeMb / 1024 * $rub_Gb_disk
        #$rub_disk 
        $rub_all_disk += $rub_disk 
    }
    $rub_cpu = [int]$disk_rtcloud.vm.VmSpecSection.NumCpus * $config.rtcloud.cost.cpu * [int]$hashtable_jira_GHz[$disk_rtcloud.vm.name]
    $rub_ram = $disk_rtcloud.vm.VmSpecSection.MemoryResourceMb.Configured / 1024 * $config.rtcloud.cost.ram
    $rub_all = ( $rub_all_disk + $rub_cpu + $rub_ram ) * $config.rtcloud.cost.nds
    Set-JiraAttribute -value_atr ([int]$rub_all) -id_object $hashtable_jira_host[$disk_rtcloud.vm.name] -id_atr "512" -Headers_jira $headers_jira
}
set-log "change attr: cost -> host ( RTCloud -> Jira )"

# add object: site ( IIS -> Jira )
foreach ($i in $iis_site){
    if ($jira_site.objectEntries.name -notcontains $i.name ){
        Add-JiraObject -objectTypeId "50" -id_atr_name "522" -name_object $i.name -Headers_jira $headers_jira
    }
}
set-log "add object: site ( IIS -> Jira )"

# change attr: PhysicalPath ( IIS -> Jira ) 
foreach ($i in $list_iis_path_sites) {
    $shielding = $i.path -replace '\\','\\' 
    Set-JiraAttribute -Headers_jira $Headers_jira -id_atr 531 -id_object $hashtable_jira_site[$i.name] -value_atr $shielding 
}
set-log "change attr: PhysicalPath ( IIS -> Jira ) "

# change attr: server, bindings, state -> site ( IIS -> Jira ) 
foreach ($i in $iis_site){
    Set-JiraAttribute3 -Headers_jira $Headers_jira -id_object $hashtable_jira_site[$i.name] `
    -id_atr1 525 -id_atr2 526 -id_atr3 527 -value_atr1 ($hashtable_jira_host[$i.PSComputerName]) -value_atr2 $i.Bindings -value_atr3 $i.state
}
set-log "change attr: server, bindings, state -> site ( IIS -> Jira )  "

# delete object: site ( IIS -> Jira ) 
if ($iis_site -ne "Null" ){
    foreach ($i in  $jira_site.objectEntries){
        if ($iis_site.name -notcontains $i.name){
            Remove-JiraObject -Headers_jira $Headers_jira -id_object $hashtable_jira_site[$i.name]
        }
    }
}
set-log "delete object: site ( IIS -> Jira ) "

# delete object: database ( MSSQL -> Jira ) 
if ($mssql_database -ne "Null"){
    foreach ($i in  $jira_db.objectEntries){
        if ($mssql_database.name -notcontains $i.name){
            Remove-JiraObject -Headers_jira $Headers_jira -id_object $hashtable_jira_db[$i.name]
        }
    }
}
set-log "delete object: database ( MSSQL -> Jira ) "

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
    Set-JiraAttribute2 -id_object $hashtable_jira_vdc[$i.name] -Headers_jira $Headers_jira `
    -id_atr1 536 -value_atr1 $a `
    -id_atr2 537 -value_atr2 $b
    
}
set-log "change attr: cost allocated, cost used -> hypervisor ( RTCloud -> Jira ) "

############################################################### 
# HyperV

# Get HyperV VM ( Powershell Get-VM ) 
$HyperVhost = Get-hypervVM -ComputerName ($config.hyperv)
set-log "Get-hypervVM = ", $HyperVhost.count
<#
$HyperVhost.VMName # 6
$HyperVhost.ProcessorCount # 437
$HyperVhost.MemoryAssigned # 513
$HyperVhost.MemoryDemand
$HyperVhost.State # 436
$HyperVhost.Version
$HyperVhost.SizeOfSystemFiles
$HyperVhost.ComputerName # 383
#>

# add object: VM (host)  ( Hyper-V -> Jira )
foreach ($i in $HyperVhost) { 
	if ( $jira_host.objectEntries.label -notcontains  $i.name ) {
        $res = Add-JiraObject -objectTypeId "2" -id_atr_name "6" -name_object $i.name -Headers_jira $headers_jira
	}
}
set-log "add object: VM (host)  ( Hyper-V -> Jira )"

# change attr Host: core (host), RAM (host), online (host), hypervisor (host) -> hypervisor ( Powershell Get-VM -> Jira ) 
foreach ($i in $HyperVhost) {
    [string]$tmp = ""
    $tmp = if($i.state -eq "Running") {"1"}else {"7"}
    Set-JiraAttribute4 -Headers_jira $Headers_jira -id_object $hashtable_jira_host[$i.VMName] `
    -id_atr1 437 -value_atr1 $i.ProcessorCount `
    -id_atr2 513 -value_atr2 ([math]::Round(($i.MemoryAssigned / 1073741824),1))  `
    -id_atr3 436 -value_atr3 $tmp `
    -id_atr4 383 -value_atr4 $hashtable_jira_vdc[$i.ComputerName]
}
set-log "change attr: core (host), RAM (host), online (host), hypervisor (host) -> hypervisor ( Powershell Get-VM -> Jira ) "


# Get HyperV: Used CPU, Used RAM, CpuGHz, Allocated cores, Allocated RAM -> hypervisor ( Powershell Get-ComputerInfo -> Jira ) 
$HyperVhostInfo = Invoke-Command -ComputerName $config.HyperV -ThrottleLimit 50 -ScriptBlock { 
    $env:COMPUTERNAME
    $tmp_ComputerInfo = Get-ComputerInfo
    [hashtable]$hash

    $cpu_proc_used = [int]((Get-Counter -Counter "\Processor(_Total)\% Processor Time").CounterSamples).CookedValue  
    $cpu = [int]$env:NUMBER_OF_PROCESSORS
    $cpu_used = $cpu * $cpu_proc_used / 100

    return $hash = @{ $tmp_ComputerInfo.CsName = @{ 
        memUsed = [int]( ($tmp_ComputerInfo.OsTotalVisibleMemorySize - $tmp_ComputerInfo.OsFreePhysicalMemory ) / 1048576 ) ; 
        cpuGHz = [math]::Round(($tmp_ComputerInfo.CsProcessors.MaxClockSpeed[0] / 1000), 1) ;  
        cpuUsed = [int]$cpu_used ;
        memAllocated = [int]($tmp_ComputerInfo.OsTotalVisibleMemorySize / 1048576 ) ;
        CoreAlloceted = $tmp_ComputerInfo.CsNumberOfLogicalProcessors
        }
    }
}

# change attr HyperV: Used CPU, Used RAM, CpuGHz, Allocated cores, Allocated RAM -> hypervisor ( Powershell Get-ComputerInfo -> Jira ) 
$HyperVhostInfo | ForEach-Object {
    if ($_ -eq $Null) {return} # не до всех гиперов иногда можно достучаться
    $tmp = $_.Keys
    Set-JiraAttribute5 -id_object $hashtable_jira_vdc["$tmp"] -Headers_jira $Headers_jira `
    -id_atr1 534 -value_atr1 $_.values.memUsed `
    -id_atr2 532 -value_atr2 $_.values.cpuUsed `
    -id_atr3 438 -value_atr3 $_.values.cpuGHz `
    -id_atr4 439 -value_atr4 $_.values.CoreAlloceted `
    -id_atr5 533 -value_atr5 $_.values.memAllocated 
}

