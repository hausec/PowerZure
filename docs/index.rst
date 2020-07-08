---
title: PowerZure Documentation
---

# About

## What is PowerZure?

PowerZure is a PowerShell project created to assess and exploit resources within
Microsoft’s cloud platform, Azure. PowerZure was created out of the need for a
framework that can both perform reconnaissance **and** exploitation of Azure.

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

## Author & License

Author: Ryan Hausknecht (\@haus3c)

License: BSD-3

# Requirements

Azure has many different PowerShell modules, each using a different API. Some
have been deprecated and some do not have nearly as much functionality as the
others, despite all being Microsoft-made. PowerZure uses three Azure modules,
each with a different purpose.

1.  [Azure
    CLI](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest)
    (\`az\`)

    The Azure CLI is the primary module used in PowerZure as throughout my
    testing and building this project, it became clear the Azure CLI module had
    the most functionality and decent support on Github. Azure CLI is the
    successor to the AzureRM module and uses the Azure REST API.

2.  [Azure
    PowerShell](https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0)

    The Azure PS module is used to fill in gaps where Azure CLI functionality
    lacks. Specifically, Azure CLI has no cmdlets for interacting with
    Automation Accounts or Runbooks, hence the need for Azure PS. Azure PS uses
    the Graph API.

3.  [AzureAD](https://docs.microsoft.com/en-us/powershell/module/Azuread/?view=azureadps-2.0)

    The AzureAD module is used for the more mature cmdlets around interacting
    with (you guessed it) Azure Active Directory. While both Azure CLI and Azure
    PS have cmdlets for doing basic things, like listing users and groups, when
    it came to more advanced things such as adding an AAD role to a user, the
    AzureAD module is needed. AzureAD uses the Graph API.

    These three modules are needed to **fully** use PowerZure. If you do not
    need to interact with AAD or Automation Accounts, then Azure CLI is the only
    module needed. With this being said, PowerZure should also be run from an
    elevated PowerShell window.

# Operational Usage

PowerZure comes in .ps1 format which requires it to be imported for each new
PowerShell session. To import, simply use \`Import-Module
C:/Location/to/Powerzure.ps1\`

There is zero reason to ever run PowerZure on a victim’s machine. Authentication
is done by using an existing accesstoken.json file or by logging in via prompt
when logging into Azure CLI, meaning you can safely use PowerZure to interact
with a victim’s cloud instance from your operating machine.

# Functions

## Information Gathering

### **Get-Targets**

#### Synopsis

Compares your role to your scope to determine what you have access to and what
kind of access it is (Read/write/execute).

#### Syntax

\`Get-Targets\`

#### Description

Looks at the current signed-in user’s roles, then looks at the role definitions
and scope of that role. Role definitions are then compared to the scope of the
role to determine which resources under that scope the role definitions are
actionable against.

#### Examples

\`Get-Targets\`

#### Required Modules

Azure CLI

#### Parameters

None

#### Output

List of resources with what type of access the current user has access to.

#### *Get-CurrentUser*

#### Synopsis

Returns the current logged in user name and any owned objects

#### Syntax

\`Get-CurrentUser\`

#### Description

Looks at the current logged in username and compares that to the role assignment
list to determine what objects/resources the user has ownership over.

#### Examples

\` Get-CurrentUser\`

\` Get-CurrentUser -All\`

#### Required Modules

Azure CLI

#### Parameters 

\-All

Grabs all details

#### Output

Current username and owned objects by that user

#### *Get-AllUsers*

#### Synopsis

List all Azure users in the tenant

#### Syntax

\`Get-AllUsers \`

#### Description

Lists all users in the tenant including their email, object type, distinguished
name, Principal name, and usertype.

#### Examples

\` Get-AllUsers \`

\`Get-AllUsers -OutFile users.csv\`

\`Get-AllUsers -OutFile users.txt\`

#### Required Modules

Azure CLI

#### Parameters 

\-Outfile

Specifies the output of the data.

#### Output

List of all users in AAD, optionally in a file.

*Get-AADRoleMembers*

#### Synopsis

Lists the active roles in Azure AD and what users are part of the role.

#### Syntax

\`Get-AADRoleMembers\`

#### Description

Gathers the AAD role members. This is different than Azure RBAC roles.

#### Examples

\` Get-AADRoleMembers\`

#### Required Modules

Azure CLI

AzureAD PowerShell

#### Parameters

None

#### Output

List of AAD Role members

#### *Get-User*

#### Synopsis

Gathers info on a specific user

#### Syntax

\`Get-User -User Test\@domain.com \`

#### Description

Gathers the UPN, Object ID, On-premise distinguished name, and if the account is
enabled. Also lists the roles the user has in Azure RBAC.

#### Examples

\`Get-User -User [Test\@domain.com\`](mailto:Test@domain.com%60)

#### Required Modules

Azure CLI

#### Parameters

\-User

User Principal Name

#### Output

Details of user

#### *Get-AllGroups*

#### Synopsis

Gathers all the groups in the tenant

#### Syntax

\`Get-AllGroups\`

#### Description

#### Gathers all the groups in the tenant 

#### Examples

\`Get-AllGroups\`

\`Get-AllGroups -OutFile users.csv\`

\`Get-AllGroups -OutFile users.txt \`

#### Parameters 

\-OutFile

Output file

#### Output

List of groups in AAD, optionally in the format of a file.

#### *Get-Resources*

#### Synopsis

Lists all resources

#### Syntax

\`Get-Resources\`

#### Description

Lists all the resources in the subscription that the user has access to.

#### Examples

\`Get-Resources\`

#### Parameters

None

#### Required Modules

Azure CLI

#### Output

List of resources the user can see

#### *Get-Apps*

#### Synopsis

Returns all applications and their Ids

#### Syntax

\`Get-Apps\`

#### Description

Returns all the applications in Azure AD and their IDs

#### Examples

\`Get-Apps\`

#### Parameters 

None

#### Required Modules

Azure CLI

#### Output

Applications in AAD

### **Get-GroupMembers**

#### Synopsis

Gets all the members of a specific group. Group does NOT mean role.

#### Syntax

\`Get-GroupMembers -Group 'SQL Users' \`

#### Description

Will get the members of a specific AAD group.

#### Examples

\`Get-GroupMembers -Group 'SQL Users' \`

\`Get-GroupMembers -Group 'SQL Users' -OutFile users.csv\`

#### Parameters

\-Group

Group name

\-OutFile

Output file

#### Required Modules

Azure CLI

#### Output

Group members of the specified group, optionally to a file.

### **Get-AllGroupMembers**

#### Synopsis

Gathers all the group members of all the groups.

#### Syntax

\`Get-AllGroupMembers\`

#### Description

Goes through each group in AAD and lists the members.

#### Examples

\`Get-AllGroupMembers -OutFile members.txt \`

\`Get-AllGroupMembers\`

#### Parameters 

\-OutFile

Output filename/type

#### Required Modules

Azure CLI

#### Output

List of group members for each group in AAD.

### **Get-AllRoleMembers**

#### Synopsis

Gets all the members of all roles. Roles does not mean groups.

#### Syntax

\`Get-AllRoleMembers\`

#### Description

#### Examples

#### \`Get-AllRoleMembers\`

#### \`Get-AllRoleMembers -OutFile users.csv\`

#### \`Get-AllRoleMembers -OutFile users.txt\`

#### Parameters 

\-OutFile

Output filename/type

#### Required Modules

Azure CLI

#### Output

All members of all roles

### **Get-RoleMembers** 

#### Synopsis

Gets the members of a role.

#### Syntax

\`Get-RoleMembers -Role [Role name]\`

#### Description

Gets the members of a role. Capitalization matters (i.e. reader vs Reader
\<---correct)

#### Examples

\`Get-RoleMembers -Role Reader\`

#### Parameters

\-Role

Name of role. Needs to be properly capitalized

#### Required Modules

Azure CLI

#### Output

Members of specified role.

#### *Get-Roles*

#### Synopsis

Lists the roles of a specific user.

#### Syntax

\`Get-Roles -User [UPN] \`

#### Description

Lists the Azure RBAC roles of a specific user based on their UPN.

#### Examples

\`Get-Roles -User john\@contoso.com\`

#### Parameters 

\-User

UPN of the user

#### Required Modules

Azure CLI

#### Output

Roles of the specified user

#### *Get-ServicePrincipals*

#### Synopsis

Returns all service principals

#### Syntax

\`Get-ServicePrincipals\`

#### Description

Returns all service principals in AAD.

#### Examples

\`Get-ServicePrincipals\`

#### Parameters

None

#### Required Modules

Azure CLI

#### Output

List of SPs in AAD

#### *Get-ServicePrincipal*

#### Synopsis

Returns all info on a service principal

#### Syntax

\`Get-ServicePrincipal –id [SP ID]\`

#### Description

Returns all details on a service principal via the SP’s ID.

#### Examples

\`Get-ServicePrincipal -id fdb54b57-a416-4115-8b21-81c73d2c2deb\`

#### Parameters 

\-id

ID of the Service Principal

#### Required Modules

Azure CLI

#### Output

Details of specified service principal

#### *Get-AppPermissions*

#### Synopsis

Returns the permissions of an app

#### Syntax

\` Get-AppPermissions -Id [App ID]\`

#### Description

Gathers the permissions an application has.

#### Examples

\`Get-AppPermissions -Id fdb54b57-a416-4115-8b21-81c73d2c2deb\`

#### Parameters

\-Id

ID of the Application

#### Required Modules

Azure CLI

#### Output

Application’s permissions

### **Get-WebApps**

#### Synopsis

Gets running webapps

#### Syntax

\`Get-WebApps\`

#### Description

Gathers the names of the running web applications

#### Examples

\`Get-WebApps\`

#### Parameters

None

#### Required Modules

Azure CLI

#### Output

Web application names

### **Get-WebAppDetails** 

#### Synopsis

Gets running webapps details

#### Permissions

#### Syntax

\`Get-WebAppDetails -Name [WebAppName]\`

#### Description

Gets the details of a web application

#### Examples

\`Get-WebAppDetails -Name AppName\`

#### Parameters 

\-name

Name of web application

#### Required Modules

Azure CLI

#### Output

Details of web application

### **Get-RunAsCertificate** 

#### Synopsis

Will gather a RunAs accounts certificate which can then be used to login as that
account.

#### Permissions

#### Syntax

\`Get-RunAsCertificate -ResourceGroup [RG Name] -AutomationAccount [AA Name]\`

#### Description

Will gather a RunAs accounts certificate which can then be used to login as that
account. By default, RunAs accounts are contributors over the subscription. This
function does take a minute to run as it creates a runbook, uploads it, runs it,
then parses the output to gather the certificate.

#### Examples

\`Get-RunAsCertificate -ResourceGroup Test_RG -AutomationAccount TestAccount\`

#### Parameters

\-ResourceGroup

Name of the resource group the Automation Account is located in.

\-AutomationAccount

The name of the Automation Account.

#### Required Modules

Azure CLI

Azure PowerShell

#### Output

Connection string for the RunAs account

### **Get-AADRole** 

#### Synopsis

#### Finds a specified AAD Role and its definitions

#### Permissions

#### Syntax

\` Get-AADRole -Role [Role]\`

#### Description

#### Finds a specified AAD Role and its definitions. Role must be properly capitalized. If role has a space in the name, use single quotes around the name.

#### Examples

\`Get-AADRole -Role 'Company Administrator'\`

#### Parameters

None

#### Required Modules

Azure CLI

AzureAD PowerShell

#### Output

Active roles

### **Get-AADRoleMembers** 

#### Synopsis

Lists the active roles in Azure AD and what users are part of the role.

#### Permissions

#### Syntax

\`Get-AADRoleMembers\`

#### Description

Lists the active roles in Azure AD and what users are part of the role.

#### Examples

\`Get-AADRoleMembers\`

#### Parameters

None

#### Required Modules

Azure CLI

#### Output

Active roles

## Operational

#### *Execute-Command*

#### Synopsis

Will run a command or script on a specified VM

#### Permissions

#### Syntax

\`Execute-Command -OS [OS] -ResourceGroup [RG Name] -VM [VM Name] -Command
[Command]\`

#### Description

Executes a command on a virtual machine in Azure using \`az vm run-command
invoke\`

#### Examples

\`Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command
whoami\`

#### Parameters 

\-OS

Operating system, options are \`Linux\` or \`Windows\`

\-ResourceGroup

Resource group name the VM is located in

\-VM

Name of the virtual machine to execute the command on

\-Command

The command to be executed

#### Required Modules

Azure CLI

#### Output

Output of command being run or a failure message if failed

### **Execute-MSBuild** 

#### Synopsis

Will run a supplied MSBuild payload on a specified VM. By default, Azure VMs
have .NET 4.0 installed. Requires Contributor Role. Will run as SYSTEM.

#### Permissions

#### Syntax

\`Execute-MSBuild -ResourceGroup [RG Name] -VM [Virtual Machine name] -File
[C:/path/to/payload/onyourmachine.xml]\`

#### Description

Uploads an MSBuild payload as a .ps1 script to the target VM then calls
msbuild.exe with \`az run-command invoke\`.

#### Examples

\`Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File
C:\\temp\\build.xml\`

#### Parameters 

#### \-ResourceGroup

#### Resource group name the VM is located in

#### \-VM

#### Name of the virtual machine to execute the command on

#### \-File

Location of build.xml file

#### Required Modules

Azure CLI

#### Output

Success message of msbuild starting the build if successful, error message if
upload failed.

### **Execute-Program** 

#### Synopsis

Will run a given binary on a specified VM

#### Permissions

#### Syntax

\`Execute-Program -ResourceGroup [RG Name] -VM [Virtual Machine name] -File
[C:/path/to/payload.exe]\`

#### Description

Takes a supplied binary, base64 encodes the byte stream to a file, uploads that
file to the VM, then runs a command via \`az run-command invoke\` to decode the
base64 byte stream to a .exe file, then executes the binary.

#### Examples

\`Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File
C:\\temp\\beacon.exe\`

#### Parameters 

\-ResourceGroup

Resource group name the VM is located in

\-VM

Name of the virtual machine to execute the command on

\-File

Location of executable binary

#### Required Modules

Azure CLI

#### Output

“Provisioning Succeeded” output. Because it’s a binary being executed, there
will be no native output unless the binary is meant to return data to stdout.

### **Create-Backdoor** 

#### Synopsis

Creates a backdoor in Azure via Runbooks

#### Permissions

#### Syntax

\`Create-Backdoor -Username [Username] -Password [Password] -AutomationAccount
[AA name] -ResourceGroup [RG Name] -NewUsername [New UN] -NewPassword [New
Password]\`

#### Description

Will create a Runbook that creates an Azure account and generates a Webhook to
that Runbook so it can be executed if you lose access to Azure. Also gives the
ability to upload your own .ps1 file as a Runbook (Customization)

This requires an account that is part of the 'Administrators' Role (Needed to
make a user)

#### Examples

\`Create-Backdoor -Username Administrator\@contoso.com -Password Password!
-AutomationAccount AutomationAccountExample -ResourceGroup ResourceGroupName
-NewUsername Test01\@contoso.com -NewPassword Passw0rd \`

#### Parameters 

\-Username

Username you used to login to Azure with, that has permissions to create a
Runbook and user

\-Password

Password to that account

\-AutomationAccount

Azure Automation Account name

\-ResourceGroup

Resource Group name

\-NewUsername

Username you want to create

\-NewPassword

Password for that new account

#### Required Modules

Azure CLI

Azure PowerShell

#### Output

URI if successful, permissions error if failure

### **Execute-Backdoor** 

#### Synopsis

This runs the backdoor URI that is created with "Create-Backdoor”

#### Permissions

#### Syntax

\`Execute-Backdoor -URI [URI]\`

#### Description

Executes the URI created by Create-Backdoor

#### Examples

\`Execute-Backdoor -URI
https://s16events.azure-automation.net/webhooks?token=qol1XudydN13%2bI5bilBZzbCjdzTIcfs4Fj4yH61WvQ%3d\`

#### Parameters 

\-URI

The URI generated by Create-Backdoor

#### Required Modules

Azure CLI  
Azure PowerShell

#### Output

Webhook successfully executed

### **Execute-CommandRunbook** 

#### Synopsis

Will execute a supplied command or script from a Runbook if the Runbook is
configured with a "RunAs" account

#### Permissions

#### Syntax

\`Execute-CommandRunbook -AutomationAccount [AA Name] -ResourceGroup [RG Name]
-VM [VM Name] -Command [Command]\`

#### Description

If an Automation Account is utilizing a ‘Runas’ account, this allows you to run
commands against a virtual machine if that RunAs account has the correct
permissions over the VM.

#### Examples

\`Execute-CommandRunbook -AutomationAccount TestAccount -ResourceGroup TestRG
-VM Win10Test -Command whoami\`

\`Execute-CommandRunbook -AutomationAccount TestAccount -ResourceGroup TestRG
-VM Win10Test -Script "C:\\temp\\test.ps1"\`

#### Parameters 

\-AutomationAccount

Automation Account name

\-ResourceGroup

Resource Group name

\-VM

VM name

\-Command (optional)

Command to be run against the VM. Choose this or -Script if executing an entire
script

\-Script (optional)

Run an entire script instead of just one command.

#### Required Modules

Azure CLI

Azure PowerShell

#### Output

Output of command if successfully ran.

### **Upload-StorageContent** 

#### Synopsis

Uploads a supplied file to a storage share.

#### Permissions

#### Syntax

\`Upload-StorageContent -StorageAccount [Storage Account name] -Share [Storage
share name] -File [File name to upload]\`

#### Description

Uploads a supplied file to a storage container located in a storage account

#### Examples

\`Upload-StorageContent -StorageAccount TestName -Share TestShare -File
secret.txt\`

#### Parameters 

\-StorageAccount

Name of Storage account. Try Get-StorageAccounts for a list.

\-File

File to upload

\-Share

Share name to upload to

#### Required Modules

Azure CLI

Azure Powershell

#### Output

Success message

### **Stop-VM** 

#### Synopsis

Stops a Virtual Machine

#### Permissions

#### Syntax

\` Stop-VM -VM [VM name] -ResourceGroup [RG] \`

#### Description

Stops a VM

#### Examples

\` Stop-VM -VM Example2016R2 -ResourceGroup Test_RG\`

#### Parameters 

\-VM

Name of machine

\-ResourceGroup

Resource group the VM is located in

#### Required Modules

Azure CLI

#### Output

VM successfully stops

### Start-VM 

**Synopsis**

Starts a Virtual Machine

**Permissions**

**Syntax**

\` Start-VM -VM [VM name] -ResourceGroup [RG] \`

**Description**

Starts a VM

**Examples**

\` Start-VM -VM Example2016R2 -ResourceGroup Test_RG\`

**Parameters**

\-VM

Name of machine

\-ResourceGroup

Resource group the VM is located in

#### Required Modules

Azure CLI

**Output**

VM successfully starts

### Restart-VM 

**Synopsis**

Restarts a Virtual Machine

**Permissions**

**Syntax**

\` Restart-VM -VM [VM name] -ResourceGroup [RG] \`

**Description**

Restarts a VM

**Examples**

\` Restart-VM -VM Example2016R2 -ResourceGroup Test_RG\`

**Parameters**

\-VM

Name of machine

\-ResourceGroup

Resource group the VM is located in

#### Required Modules

Azure CLI

**Output**

VM successfully restarts

### **Start-Runbook** 

#### Synopsis

Starts a Runbook

#### Permissions

#### Syntax

\` Start-Runbook -Account [Automation Account name] -ResourceGroup [Resource
Group name] -Runbook [Runbook name] \`

#### Description

Starts a specified Runbook

#### Examples

\` Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook
TestRunbook \`

#### Parameters 

\-Account

Name of Automation Account the Runbook is in

\-ResourceGroup

Resource group it's located in

\-Runbook

Name of runbook

#### Required Modules

Azure CLI

Azure PowerShell

#### Output

Runbook output

### **Set-Role** 

#### Synopsis

Assigns a user a role for a specific resource or subscription

#### Permissions

#### Syntax

\`Set-Role -Role Owner -User [UPN] -Resource [Resource name]\`

#### Description

Sets a role over a resource or subscription.

#### Examples

\`Set-Role -Role Owner -User john\@contoso.com -Resource WIN10VM\`

\`Set-Role -Role Owner -User john\@contoso.com -Subscription SubName\`

#### Parameters 

\-User

Name of user in format user\@domain.com

\-Role

Role name (must be properly capitalized)

\-Resource

Name of Resource

\-Subscription

Name of subscription

#### Required Modules

Azure CLI

#### Output

Role successfully applied

### Remove-Role 

**Synopsis**

Removes a user from a role for a specific resource or subscription

**Permissions**

**Syntax**

\`Set-Role -Role Owner -User [UPN] -Resource [Resource name]\`

**Description**

Removes a role over a resource or subscription.

**Examples**

\`Remove-Role -Role Owner -User john\@contoso.com -Resource WIN10VM\`

\`Remove-Role -Role Owner -User john\@contoso.com -Subscription SubName\`

**Parameters**

\-User

Name of user in format user\@domain.com

\-Role

Role name (must be properly capitalized)

\-Resource

Name of Resource

\-Subscription

Name of subscription

#### Required Modules

Azure CLI

**Output**

Role successfully Removed

### **Set-Group** 

#### Synopsis

Adds a user to an Azure AD Group

#### Permissions

#### Syntax

\`Set-Group -User [UPN] -Group [Group name]\`

#### Description

Adds a user to an AAD group. If the group name has spaces, put the group name in
single quotes.

#### Examples

\`Set-Group -User john\@contoso.com -Group 'SQL Users' \`

#### Parameters 

\-User

UPN of the user

\-Group

AAD Group name

#### Required Modules

Azure CLI

#### Output

User added to group

### **Set-Password** 

#### Synopsis

Sets a user's password

#### Permissions

#### Syntax

\`Set-Password -Username [UPN] -Password [new password]\`

#### Description

Sets a user’s password. Requires AAD PS Module.

#### Examples

\`Set-Password -Username john\@contoso.com -Password newpassw0rd1\`

#### Parameters 

\-Password

New password for user

\-Username

Name of user

#### Required Modules

Azure CLI

AzureAD PowerShell

#### Output

Password successfully set

## Secret/Key/Certificate Gathering

#### *Get-KeyVaults*

#### Synopsis

Lists the Key Vaults

#### Permissions

#### Syntax

\`Get-KeyVaults\`

#### Description

Gathers the Keyvaults in the subscription

#### Examples

\`Get-KeyVaults\`

#### Parameters 

None

#### Required Modules

Azure CLI

#### Output

List of KeyVaults

### **Get-KeyVaultContents** 

#### Synopsis

Get the secrets from a specific Key Vault

#### Permissions

#### Syntax

\`Get-KeyVaultContents -Name [VaultName] \`

#### Description

Takes a supplied KeyVault name and edits the access policy to allow the current
user to view the vault. Once the secrets are displayed, it re-edits the policy
and removes your access.

#### Examples

\`Get-KeyVaultContents -Name TestVault\`

#### Parameters 

\-Name

Vault name

#### Required Modules

Azure CLI

#### Output

KeyVault contents

### **Get-AllKeyVaultContents** 

#### Synopsis

Gets ALL the secrets from all Key Vaults. If the logged in user cannot access a
key vault, it tries to edit the access policy to allow access.

#### Permissions

#### Syntax

\`Get-AllKeyVaultContents\`

#### Description

Goes through each key vault and edits the access policy to allow the user to
view the contents, displays the contents, then re-edits the policies to remove
the user from the access policy.

#### Examples

\`Get-AllKeyVaultContents\`

#### Parameters 

None

#### Required Modules

Azure CLI

#### Output

Key vault content

## Data Exfiltration

### **Get-StorageAccounts** 

#### Synopsis

Get a list of storage accounts and their blobs

#### Permissions

#### Syntax

\`Get-StorageAccounts\`

#### Description

Gets a list of storage account blobs

#### Examples

\`Get-StorageAccounts\`

#### Parameters 

None

#### Required Modules

Azure CLI

Azure Powershell

#### Output

List of storage accounts

### **Get-StorageAccountKeys** 

#### Synopsis

Gets the account keys for a storage account

#### Permissions

#### Syntax

\`Get-StorageAccountKeys -ResourceGroup [Resource Group name] -Account
[StorageAccountName]\`

#### Description

Gets the account keys for a storage account to be used to access the storage
account.

#### Examples

\`Get-StorageAccountKeys -ResourceGroup MyGroup -Account StorageAccountName
-kerb \`

#### Parameters 

\- ResourceGroup

Resource group the Storage account is located in

\-Account

Storage account name

\-kerb (optional, use if kerberos keys are suspected)

Also grab the “Kerberos keys”

#### Required Modules

Azure CLI

Azure Powershell

#### Output

List of keys in plain text

### **Get-StorageContents** 

#### Synopsis

Gets the contents of a storage container or file share.

#### Permissions

#### Syntax

\`Get-StorageContents -StorageAccount [Storage account name] -ResourceGroup
[Resource group name] -File [File name]\`

#### Description

Gets the contents of a storage container or file share. OAuth is not support to
access file shares via cmdlets, so you must have access to the Storage Account's
key.

#### Examples

\` Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup -File
secret.txt -NoDelete\`

#### Parameters 

\-ResourceGroup

Resource Group name

\-StorageAccount

Name of Storage account. Try Get-StorageAccounts for a list.

\-File

Gets the contents of a specified file. If file is in a path, include the full
path. Optional

\-NoDelete

Does not delete the file after it's downloaded. Optional

#### Required Modules

Azure CLI

Azure Powershell

#### Output

File contents are displayed

### **Get-Runbooks** 

#### Synopsis

Lists all the run books in all Automation accounts under the subscription

#### Permissions

#### Syntax

\`Get-Runbooks\`

#### Description

Recursively goes through each Automation Account and lists the runbook names,
it’s state, the creation and modification time, and what AA it is under.

#### Examples

\`Get-Runbooks\`

#### Parameters 

None

#### Required Modules

Azure CLI

Azure PowerShell

#### Output

List of runbooks and their associated Automation Accounts

### **Get-RunbookContent** 

#### Synopsis

Gets a specific Runbook and displays its contents. Use -NoDelete to not delete
after reading

#### Permissions

#### Syntax

\`Get-RunbookContent -Account [AutomationAccountName] -ResourceGroup
[ResourceGroupName] -Runbook [Runbook name]\`

#### Description

#### Examples

\`Get-RunbookContent -Account AutomationAccountexample -ResourceGroup TestGroup
-Runbook TestBook\`

\`Get-RunbookContent -Account AutomationAccountexample -ResourceGroup TestGroup
-Runbook TestBook -Slot "Published"\`

\`Get-RunbookContent -Account AutomationAccountexample -ResourceGroup TestGroup
-Runbook TestBook -Slot "Draft"\`

#### Parameters 

\-Runbook

Name of Runbook

\-Group

Resource group it's located in

\-Account

Automation Account Name

\-NoDelete

Do not delete after displaying contents

\-Slot

Optional; use if differenciating between published or drafted Runbook

#### Required Modules

Azure CLI

Azure PowerShell

#### Output

Runbook content

### **Get-AvailableVMDisks** 

#### Synopsis

Lists the VM disks available.

#### Permissions

#### Syntax

\`Get-AvailableVMDisks\`

#### Description

Lists the VM disks available in the subscription

#### Examples

\`Get-AvailableVMDisks\`

#### Parameters 

None

#### Required Modules

Azure CLI

#### Output

List of VM Disks

### **Get-VMDisk** 

#### Synopsis

Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour.

#### Permissions

#### Syntax

\` Get-VMDisk -DiskName [Disk name] -ResourceGroup [RG Name]\`

#### Description

Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour. Note that you’re downloading a VM Disk, so it’s probably
going to be many GBs in size. Hope you have fiber!

#### Examples

\` Get-VMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5
-ResourceGroup TestGroup\`

#### Parameters 

\-ResourceGroup

Resource group name

\-DiskName

Name of VM disk

#### Required Modules

Azure CLI

#### Output

Link to download the VM disk

### **Get-VMs** 

#### Synopsis

Lists all virtual machines available, their disks, and their IPs.

#### Permissions

#### Syntax

\`Get-VMs\`

#### Description

Lists all virtual machines available, their disks, and their IPs, as well their
running state

#### Examples

\`Get-VMs\`

#### Parameters 

None

#### Required Modules

Azure CLI

#### Output

List of VMs and details

### **Get-SQLDBs** 

#### Synopsis

Lists the available SQL Databases on a server

#### Permissions

#### Syntax

\`Get-SQLDBs\`

#### Description

Lists the available SQL Databases on a server. There currently are no cmdlets in
any PS module to interact with said DBs, so the only option is to login via
portal and use the preview browser.

#### Examples

\`Get-SQLDBs\`

#### Parameters 

None

#### Required Modules

Azure CLI

#### Output

List of SQL Databases in the subscription

## Mandatory

### **Set-Subscription**

#### Synopsis

Sets default subscription. Necessary if in a tenant with multiple subscriptions.

#### Permissions

#### Syntax

\`Set-Subscription -Id [Subscription ID]\`

#### Description

Sets the default subscription

#### Examples

\`Set-Subscription -Id b049c906-7000-4899-b644-f3eb835f04d0\`

#### Parameters 

\-Id

Subscription ID

#### Required Modules

Azure CLI

#### Output

Success message

## Help

### **PowerZure**

#### Synopsis

Displays info about this script.

#### Permissions

#### Syntax

\`PowerZure -h\`

#### Description

Displays info about this script.

#### Examples

\`PowerZure -h\`

#### Parameters 

\-h

Help

#### Required Modules

Azure CLI

#### Output

List of functions in this script
