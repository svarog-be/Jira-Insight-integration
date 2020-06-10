#####################
#####################
#####################
#RTCloud запросы

# RTCloud получение данных по хостам
$rtcloud_Response2 = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/query?type=disk' -Method GET -Headers $Headers_rtcloud
[xml]$disk_rtcloud = $rtcloud_Response2.content

# GET /catalogs/query
$rtcloud_Response3 = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/catalogs/query' -Method GET -Headers $Headers_rtcloud
[xml]$vm_rtcloud = $rtcloud_Response3.content

# GET /disks/query
$rtcloud_Response3 = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/disks/query' -Method GET -Headers $Headers_rtcloud
[xml]$vm_rtcloud = $rtcloud_Response3.content

# 
$headers_rtcloud.add("Accept", "application/vnd.vmware.vcloud.rasdItemsList+xml;version=30.0")
$rtcloud_Response3 = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/vApp/vm-03b546d5-3adb-4435-a90f-34f8721ac6de/virtualHardwareSection/disks' -Method GET -Headers $Headers_rtcloud
[xml]$disk_rtcloud = $rtcloud_Response3.content
$disk_rtcloud.RasdItemsList.item.VirtualQuantity

$rtcloud_Response3 = Invoke-WebRequest -Uri 'https://dc.rtcloud.ru/api/vApp/vm-baef892a-8fe9-409c-8c1e-4218e58a4c9e' -Method GET -Headers $Headers_rtcloud
[xml]$disk_rtcloud = $rtcloud_Response3.content
$disk_rtcloud.vm.VmSpecSection

#####################
#####################
#####################
# rtcloud функции
$Global:Accept = "application/*+xml;version=30.0"

$Global:xvCloudAuthorization = ""

Function New-vCloudLogin($Username,$Password){

    $Pair = "$($Username):$($Password)"

    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Pair)

    $Base64 = [System.Convert]::ToBase64String($Bytes)

    $Global:Authorization = "Basic $base64"

    $headers = @{ Authorization = $Global:Authorization; Accept = $Global:Accept}

    $Res = Invoke-WebRequest -Method Post -Headers $headers -Uri "$($Global:SkyscapeURL)/sessions"

    $Global:xvCloudAuthorization = $res.headers["x-vcloud-authorization"].tostring()

}

Function Get-vCloudRequest($EndPoint){

    $headers = @{"Accept" = $Global:Accept; "x-vcloud-authorization" = $Global:xvCloudAuthorization}

    [xml]$Response = Invoke-WebRequest -Method Get -Headers $headers -Uri "$($Global:SkyscapeURL)/$EndPoint"

    Return $Response

}
#####################
#####################
#####################
