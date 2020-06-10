$Cred = Get-Credential
$Cred.Password | ConvertFrom-SecureString | Set-Content ./pass.txt
$Cred.UserName | Set-Content ./user.txt


$username = Get-Content ./user.txt
$pass = Get-Content ./pass.txt | ConvertTo-SecureString
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $pass