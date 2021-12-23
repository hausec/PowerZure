## New-AzureToken

### Purpose

This script is to generate an AzureRM (REST API) Access Token without the use of Azure PowerShell Modules. Sometimes there is a conditional access policy that only allows access to Azure from specific devices or IP addresses. If this host is compromised, then New-AzureToken can be run on that host to generate an Access Token which then can be used to login from any device or IP. This requires the user's username and password as well as a TenantId. If the TenantId is not known, you can supply a domain name and the script will find the ID for you.

### Requirements

PowerShell

For simplicity, this script will run with REST API requests and does not require any Azure PowerShell modules.

### Usage

New-AzureToken -Username Bob@domain.com -Password 'Password!' -TenantId 775a4b29-1234-5678-91012-8d0622d4c1e4

New-AzureToken -Username Bob@domain.com -Password 'Password!' -Domain 'testtenant.onmicrosoft.com'

### Example

Say for example, you are not allowed to login because you're on a non-domain joined machine.

![Disallowed](https://i.imgur.com/ajMKgbH.png)

You compromise a domain-joined machine and you can now generate an Access Token using New-AzureToken.

![GenerateAT](https://i.imgur.com/YNvPIsT.png)

This token can then be copy and pasted to your non-domain joined host and login using the Access Token.
![Success](https://i.imgur.com/R2UkjeN.png)

## Author & License

Author: Ryan Hausknecht (@haus3c)

License: BSD-3
