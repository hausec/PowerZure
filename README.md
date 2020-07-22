<<<<<<< Updated upstream
![powerzure](https://i.imgur.com/ZALeACF.png)

PowerZure is a PowerShell script written to assist in assessing Azure security. Functions are broken out into their context as well as the role needed to run them. 

## Help
| Function         | Description                                 | Role   |
|------------------|---------------------------------------------|--------|
| **PowerZure -h**| Displays the help menu | Any |

## Mandatory

| Function         | Description                                 | Role   |
|------------------|---------------------------------------------|--------|
| **Set-Subscription**| Sets the default Subscription to operate in | Reader |

## Operational

| Function              | Description                                                                                                    | Role          |
|-----------------------|----------------------------------------------------------------------------------------------------------------|---------------|
| **Create-Backdoor**       | Creates a Runbook that creates an Azure account and generates a Webhook to that Runbook                        | Administrator |
| **Execute-Backdoor**      | Executes the backdoor that is created with "Create-Backdoor". Needs the URI generated from Create-Backdoor     | Administrator |
| **Execute-Command**       | Executes a command on a specified VM                                                                           | Contributor   |
| **Execute-MSBuild**       | Executes MSBuild payload on a specified VM. By default, Azure VMs have .NET 4.0 installed. Will run as SYSTEM. | Contributor   |
| **Execute-Program**       | Executes a supplied program.                                                                                   | Contributor   |
| **Upload-StorageContent** | Uploads a supplied file to a storage share.                                                                    | Contributor   |
| **Stop-VM**               | Stops a VM                                                                                                     | Contributor   |
| **Start-VM**              | Starts a VM                                                                                                    | Contributor   |
| **Restart-VM**            | Restarts a VM                                                                                                  | Contributor   |
| **Start-Runbook**         | Starts a specific Runbook                                                                                      | Contributor   |
| **Set-Role** 				| Sets a role for a specific user on a specific resource or subscription	        							 | Owner		 |
| **Remove-Role**			| Removes a user from a role on a specific resource or subscription												 | Owner         |
| **Set-Group**				| Adds a user to a group																						 | Administrator |


## Information Gathering

| Function                 | Description                                                                         | Role   |
|--------------------------|-------------------------------------------------------------------------------------|--------|
| **Get-Targets**			|	Compares your role to your scope to determine what you have access to and what kind of access it is (Read/write/execute).	| Reader |
| **Get-CurrentUser**          | Returns the current logged in user name, their role + groups, and any owned objects | Reader |
| **Get-AllUsers**           | Lists all users in the subscription                                                 | Reader |
| **Get-User**            | Gathers info on a specific user                                                     | Reader |
| **Get-AllGroups**          | Lists all groups + info within Azure AD                                             | Reader |
| **Get-Resources**            | Lists all resources in the subscription                                             | Reader |
| **Get-Apps**           | Lists all applications in the subscription                                          | Reader |
| **Get-GroupMembers**   | Gets all the members of a specific group. Group does NOT mean role.                 | Reader |
| **Get-AllGroupMembers** | Gathers all the group members of all the groups.                                    | Reader |
| **Get-AllRoleMembers**  | Gets all the members of all roles. Roles does not mean groups.                      | Reader |
| **Get-Roles**                | Lists the roles in the subscription                                                 | Reader |
| **Get-RoleMembers**          | Gets the members of a role                                                          | Reader |
| **Get-Sps**                  | Returns all service principals                                                      | Reader |
| **Get-Sp**                   | Returns all info on a specified service principal                                   | Reader |
| **Get-Apps**                 | Gets all applications and their Ids                                                 | Reader |
| **Get-AppPermissions**       | Returns the permissions of an app                                                   | Reader |
| **Get-WebApps**              | Gets running web apps                                                               | Reader |
| **Get-WebAppDetails**        | Gets running webapps details                                                        | Reader |

## Secret Gathering

| Function                  | Description                                                                  | Role        |
|---------------------------|------------------------------------------------------------------------------|-------------|
| **Get-KeyVaults**             | Lists the Key Vaults                                                         | Reader      |
| **Get-KeyVaultContents**       | Get the secrets from a specific Key Vault                                    | Contributor |
| **Get-AllKeyVaultContents**    | Gets ALL the secrets from all Key Vaults.                                    | Contributor |
| **Get-AppSecrets**            | Returns the application passwords or certificate credentials                 | Contributor |
| **Get-AllAppSecrets**         | Returns all application passwords or certificate credentials (If accessible) | Contributor |
| **Get-AllSecrets**            | Gets ALL the secrets from all Key Vaults and applications.                   | Contributor |
| **Get-AutomationCredentials** | Gets the credentials from any Automation Accounts                            | Contributor |

## Data Exfiltration

| Function               | Description                                                                                     | Role   |
|------------------------|-------------------------------------------------------------------------------------------------|--------|
| **Get-StorageAccounts**    | Gets all storage accounts                                                                       | Reader |
| **Get-StorageAccountKeys** | Gets the account keys for a storage account                                                     | Contributor |
| **Get-StorageContents**    | Gets the contents of a storage container or file share                                          | Reader |
| **Get-Runbooks**           | Lists all the Runbooks                                                                          | Reader |
| **Get-RunbookContent**     | Reads content of a specific Runbook                                                             | Reader |
| **Get-AvailableVMDisks**   | Lists the VM disks available.                                                                   | Reader |
| **Get-VMDisk**             | Generates a link to download a Virtual Machine's disk. The link is only available for an hour. | Contributor |
| **Get-VMs**                | Lists available VMs                                                                             | Reader |
=======
![powerzure](https://i.imgur.com/d5B0U0B.png)

### For a list of functions, their usage, and more, check out https://powerzure.readthedocs.io



## What is PowerZure?

PowerZure is a PowerShell project created to assess and exploit resources within
Microsoft’s cloud platform, Azure. PowerZure was created out of the need for a
framework that can both perform reconnaissance **and** exploitation of Azure, AzureAD, and the associated resources.

## CLI vs. Portal

A common question is why use PowerZure or command line at all when you can just
login to the Azure web portal?

This is a fair question and to be honest, you can accomplish 90% of the
functionality in PowerZure through clicking around in the portal, however by
using the Azure PowerShell modules, you can perform tasks programmatically that
are tedious in the portal. E.g, listing the groups a user belongs to. In
addition, the ability to programmatically upload exploits instead of tinkering
around with the messy web UI. Finally, if you compromise a user who has used the
PowerShell module for Azure before and are able to steal the accesstoken.json
file, you can impersonate that user which effectively bypasses multi-factor
authentication.

## Why PowerShell?

While the offensive security industry has seen a decline in PowerShell usage due
to the advancements of defensive products and solutions, this project does not
contain any malicious code. PowerZure does not exploit bugs within Azure, it
exploits misconfigurations.

C\# was also explored for creating this project but there were two main
problems:

1.  There were at least four different APIs being used for the project. MSOL,
    Azure REST, Azure SDK, Graph.

2.  The documentation for these APIs simply was too poor to continue. Entire
    methods missing, namespaces typo’d, and other problems begged the question
    of what advantage did C\# give over PowerShell (Answer: none)

Realistically, there is zero reason to ever run PowerZure on a victim’s machine.
Authentication is done by using an existing accesstoken.json file or by logging
in via prompt when logging into Azure CLI.

# Requirements

The Azure "Az" [Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0) module is the only module used in PowerZure, as it is the most current module for Azure. The Az module interacts using the Azure REST API.

## Author & License

Author: Ryan Hausknecht (@haus3c)

License: BSD-3
>>>>>>> Stashed changes
