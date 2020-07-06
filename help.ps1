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

# vCenter RTCloud
Install-Module VMware.VimAutomation.Core -AllowClobber

Connect-CIServer -Server dc.rtcloud.ru -User p.morozov -Password "pass" -Org otlnal

Get-CIVM