http://host:port/context/rest/insight/api-version/resource-name

https://jira.otlnal.ru/context/rest/insight/1.0/iql/objects?objectSchemaId=1&iql=ObjectType=%22Business%20area%22&resultPerPage=1

/rest/insight/1.0/object/create

# JIRA iql язык запросов
https://documentation.mindville.com/insight/5.4/insight-user-s-guide/iql-insight-query-language

# модуль для ps
Install-Module jiraps
https://atlassianps.org/docs/JiraPS/

# JIRA api
https://developer.atlassian.com/server/jira/platform/basic-authentication/

# JIRA INSIGHT api
https://documentation.mindville.com/insight/5.0/insight-for-developers/insight-rest-api/version-1-0-documentation/objects-rest

# OTRS api
https://doc.otrs.com/doc/api/otrs/stable/REST/

# ZABBIX api
https://www.zabbix.com/documentation/4.0/ru/manual/api

# RTCloud vCenter
https://code.vmware.com/apis/287/vmware-cloud-director/doc/doc/operations/GET-DisksFromQuery.html
https://docs.ukcloud.com/articles/vmware/vmw-how-interact-vcd-api-powershell.html

# json 
https://jsoneditoronline.org

# для ртклауда
Install-Module VMware.VimAutomation.Core -AllowClobber


$params = @{"@type"="login";
 "username"="xxx@gmail.com";
 "password"="yyy";
}

Invoke-WebRequest -Uri http://foobar.com/endpoint -Method POST -Body ($params|ConvertTo-Json) -ContentType "application/json"
#############
$body = @{
    "UserSessionId"="12345678"
    "OptionalEmail"="MyEmail@gmail.com"
   } | ConvertTo-Json
   
   $header = @{
    "Accept"="application/json"
    "connectapitoken"="97fe6ab5b1a640909551e36a071ce9ed"
    "Content-Type"="application/json"
   } 
   
   Invoke-RestMethod -Uri "http://MyServer/WSVistaWebClient/RESTService.svc/member/search" -Method 'Post' -Body $body -Headers $header | ConvertTo-HTML
   ##############



   $user = 'austin.luu91@gmail.com'
   $pass = #API_KEY
   
   $pair = "$($user):$($pass)"
   
   $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
   
   $basicAuthValue = "Basic $encodedCreds"
   
   $Headers = @{
   Authorization = $basicAuthValue
   }
   

Invoke-WebRequest -Uri 'https://15sof1.atlassian.net/rest/api/3/OPS-117' -Method POST -Headers $Headers -SessionVariable session -ContentType 'application / json' 
######################
Invoke-WebRequest -Method Post -Uri "https://15sof1.atlassian.net/rest/api/3/session" -Headers $ headers -SessionVariable session -ContentType 'application / json' 


$ InitiateBackup = Invoke-WebRequest -Method Post -Headers @ {"Accept" = "application / json"} -Uri "https://15sof1.atlassian.net/rest/api/3/backup/export/runbackup" -WebSession $ session -ContentType 'application / json' -Body $ bodyjson -Verbose | ConvertTo-Json -Compress | Из-Null

# запуск exe
& ′C:\Program Files\Hello.exe′