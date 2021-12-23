function New-AzureToken
{
<# 
.SYNOPSIS
    Generates an Azure REST API token without the need for any Azure PowerShell modules.

.PARAMETER 
    -TenantId (TenantId)
    -Username
    -Password
    -Domain (Name of the domain)

.EXAMPLE
    
    New-AzureToken -Username Bob@domain.com -Password 'Password!' -TenantId 775a4b29-1234-5678-91012-8d0622d4c1e4
    New-AzureToken -Username Bob@domain.com -Password 'Password!' -Domain 'testtenant.onmicrosoft.com'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$TenantId = $null,
    [Parameter(Mandatory=$true)][String]$Username = $null,
    [Parameter(Mandatory=$false)][String]$Domain = $null,
    [Parameter(Mandatory=$true)][String]$Password = $null)
    If(!$Domain -and !$TenantId){
    Write-Error "You must supply either a TenantId or Domain. `n Usage: New-AzureToken -Username Bob@domain.com -Password 'Password!' -Domain 'testtenant.onmicrosoft.com `n New-AzureToken -Username Bob@domain.com -Password 'Password!' -TenantId 775a4b29-1234-5678-91012-8d0622d4c1e4"
    Exit
    }
    If($Domain){
        $uri = 'https://login.windows.net/' + $Domain + '/.well-known/openid-configuration'
        $data = Invoke-RestMethod -Method GET -Uri $Uri
        $TenantData = $data.token_endpoint
        $TenantId = $TenantData.Split('/')[3]
    }
    $headers = @{}
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $body = "grant_type=password&username=$Username&password=$Password&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&scope=https://management.azure.com/.default&expiresIn=3599"
    $Uri = 'https://login.microsoftonline.com/' + $TenantId + '/oauth2/v2.0/token'
    $req = Invoke-RestMethod -Uri $Uri -Method 'POST' -Headers $headers -Body $body
    $token = $req.access_token
    If($token){
        $token
    }
}
