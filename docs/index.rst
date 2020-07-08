About
=====

What is PowerZure?
------------------

PowerZure is a PowerShell project created to assess and exploit
resources within Microsoft’s cloud platform, Azure. PowerZure was
created out of the need for a framework that can both perform
reconnaissance **and** exploitation of Azure.

CLI vs. Portal
--------------

A common question is why use PowerZure or command line at all when you
can just login to the Azure web portal?

This is a fair question and to be honest, you can accomplish 90% of the
functionality in PowerZure through clicking around in the portal,
however by using the Azure PowerShell modules, you can perform tasks
programmatically that are tedious in the portal. E.g, listing the groups
a user belongs to. In addition, the ability to programmatically upload
exploits instead of tinkering around with the messy web UI. Finally, if
you compromise a user who has used the PowerShell module for Azure
before and are able to steal the accesstoken.json file, you can
impersonate that user which effectively bypasses multi-factor
authentication.

Why PowerShell?
---------------

While the offensive security industry has seen a decline in PowerShell
usage due to the advancements of defensive products and solutions, this
project does not contain any malicious code. PowerZure does not exploit
bugs within Azure, it exploits misconfigurations.

C# was also explored for creating this project but there were two main
problems:

1. There were at least four different APIs being used for the project.
   MSOL, Azure REST, Azure SDK, Graph.

2. The documentation for these APIs simply was too poor to continue.
   Entire methods missing, namespaces typo’d, and other problems begged
   the question of what advantage did C# give over PowerShell (Answer:
   none)

Realistically, there is zero reason to ever run PowerZure on a victim’s
machine. Authentication is done by using an existing accesstoken.json
file or by logging in via prompt when logging into Azure CLI.

Author & License
----------------

Author: Ryan Hausknecht (@haus3c)

License: BSD-3

Requirements
============

Azure has many different PowerShell modules, each using a different API.
Some have been deprecated and some do not have nearly as much
functionality as the others, despite all being Microsoft-made. PowerZure
uses three Azure modules, each with a different purpose.

1. `Azure
   CLI <https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest>`__
   (`az`)

The Azure CLI is the primary module used in PowerZure as throughout my
testing and building this project, it became clear the Azure CLI module
had the most functionality and decent support on Github. Azure CLI is
the successor to the AzureRM module and uses the Azure REST API.

2. `Azure
   PowerShell <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__

The Azure PS module is used to fill in gaps where Azure CLI
functionality lacks. Specifically, Azure CLI has no cmdlets for
interacting with Automation Accounts or Runbooks, hence the need for
Azure PS. Azure PS uses the Graph API.

3. `AzureAD <https://docs.microsoft.com/en-us/powershell/module/Azuread/?view=azureadps-2.0>`__

The AzureAD module is used for the more mature cmdlets around
interacting with (you guessed it) Azure Active Directory. While both
Azure CLI and Azure PS have cmdlets for doing basic things, like listing
users and groups, when it came to more advanced things such as adding an
AAD role to a user, the AzureAD module is needed. AzureAD uses the Graph
API.

These three modules are needed to **fully** use PowerZure. If you do not
need to interact with AAD or Automation Accounts, then Azure CLI is the
only module needed. With this being said, PowerZure should also be run
from an elevated PowerShell window.

Operational Usage
=================

PowerZure comes in .ps1 format which requires it to be imported for each
new PowerShell session. To import, simply use 
::
	Import-Module C:/Location/to/Powerzure.ps1

There is zero reason to ever run PowerZure on a victim’s machine.
Authentication is done by using an existing accesstoken.json file or by
logging in via prompt when logging into Azure CLI, meaning you can
safely use PowerZure to interact with a victim’s cloud instance from
your operating machine.

Functions
=========

Information Gathering
---------------------

**Get-Targets**
~~~~~~~~~~~~~~~

Synopsis
^^^^^^^^

Compares your role to your scope to determine what you have access to
and what kind of access it is (Read/write/execute).

Syntax
^^^^^^

::

Get-Targets

Description
^^^^^^^^^^^

Looks at the current signed-in user’s roles, then looks at the role
definitions and scope of that role. Role definitions are then compared
to the scope of the role to determine which resources under that scope
the role definitions are actionable against.

Examples
^^^^^^^^


::
	 Get-Targets`

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Parameters
^^^^^^^^^^

None

Output
^^^^^^

List of resources with what type of access the current user has access
to.

**Get-CurrentUser**
^^^^^^^^^^^^^^^^^^^

.. _synopsis-1:

Synopsis
^^^^^^^^

Returns the current logged in user name and any owned objects

.. _syntax-1:

Syntax
^^^^^^


::
	 Get-CurrentUser

.. _description-1:

Description
^^^^^^^^^^^

Looks at the current logged in username and compares that to the role
assignment list to determine what objects/resources the user has
ownership over.

.. _examples-1:

Examples
^^^^^^^^

` Get-CurrentUser`

` Get-CurrentUser -All`

.. _required-modules-1:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _parameters-1:

Parameters 
^^^^^^^^^^

-All

Grabs all details

.. _output-1:

Output
^^^^^^

Current username and owned objects by that user

**Get-AllUsers**
^^^^^^^^^^^^^^^^

.. _synopsis-2:

Synopsis
^^^^^^^^

List all Azure users in the tenant

.. _syntax-2:

Syntax
^^^^^^

`Get-AllUsers `

.. _description-2:

Description
^^^^^^^^^^^

Lists all users in the tenant including their email, object type,
distinguished name, Principal name, and usertype.

.. _examples-2:

Examples
^^^^^^^^

` Get-AllUsers `

`Get-AllUsers -OutFile users.csv`

`Get-AllUsers -OutFile users.txt`

.. _required-modules-2:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _parameters-2:

Parameters 
^^^^^^^^^^

-Outfile

Specifies the output of the data.

.. _output-2:

Output
^^^^^^

List of all users in AAD, optionally in a file.

**Get-AADRoleMembers**

.. _synopsis-3:

Synopsis
^^^^^^^^

Lists the active roles in Azure AD and what users are part of the role.

.. _syntax-3:

Syntax
^^^^^^

`Get-AADRoleMembers`

.. _description-3:

Description
^^^^^^^^^^^

Gathers the AAD role members. This is different than Azure RBAC roles.

.. _examples-3:

Examples
^^^^^^^^

` Get-AADRoleMembers`

.. _required-modules-3:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

AzureAD PowerShell

.. _parameters-3:

Parameters
^^^^^^^^^^

None

.. _output-3:

Output
^^^^^^

List of AAD Role members

**Get-User**
^^^^^^^^^^^^

.. _synopsis-4:

Synopsis
^^^^^^^^

Gathers info on a specific user

.. _syntax-4:

Syntax
^^^^^^

`Get-User -User Test@domain.com `

.. _description-4:

Description
^^^^^^^^^^^

Gathers the UPN, Object ID, On-premise distinguished name, and if the
account is enabled. Also lists the roles the user has in Azure RBAC.

.. _examples-4:

Examples
^^^^^^^^

`Get-User -User Test@domain.com%60

.. _required-modules-4:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _parameters-4:

Parameters
^^^^^^^^^^

-User

User Principal Name

.. _output-4:

Output
^^^^^^

Details of user

**Get-AllGroups**
^^^^^^^^^^^^^^^^^

.. _synopsis-5:

Synopsis
^^^^^^^^

Gathers all the groups in the tenant

.. _syntax-5:

Syntax
^^^^^^

`Get-AllGroups`

.. _description-5:

Description
^^^^^^^^^^^

Gathers all the groups in the tenant 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. _examples-5:

Examples
^^^^^^^^

`Get-AllGroups`

`Get-AllGroups -OutFile users.csv`

`Get-AllGroups -OutFile users.txt `

.. _parameters-5:

Parameters 
^^^^^^^^^^

-OutFile

Output file

.. _output-5:

Output
^^^^^^

List of groups in AAD, optionally in the format of a file.

**Get-Resources**
^^^^^^^^^^^^^^^^^

.. _synopsis-6:

Synopsis
^^^^^^^^

Lists all resources

.. _syntax-6:

Syntax
^^^^^^

`Get-Resources`

.. _description-6:

Description
^^^^^^^^^^^

Lists all the resources in the subscription that the user has access to.

.. _examples-6:

Examples
^^^^^^^^

`Get-Resources`

.. _parameters-6:

Parameters
^^^^^^^^^^

None

.. _required-modules-5:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-6:

Output
^^^^^^

List of resources the user can see

**Get-Apps**
^^^^^^^^^^^^

.. _synopsis-7:

Synopsis
^^^^^^^^

Returns all applications and their Ids

.. _syntax-7:

Syntax
^^^^^^

`Get-Apps`

.. _description-7:

Description
^^^^^^^^^^^

Returns all the applications in Azure AD and their IDs

.. _examples-7:

Examples
^^^^^^^^

`Get-Apps`

.. _parameters-7:

Parameters 
^^^^^^^^^^

None

.. _required-modules-6:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-7:

Output
^^^^^^

Applications in AAD

**Get-GroupMembers**
~~~~~~~~~~~~~~~~~~~~

.. _synopsis-8:

Synopsis
^^^^^^^^

Gets all the members of a specific group. Group does NOT mean role.

.. _syntax-8:

Syntax
^^^^^^

`Get-GroupMembers -Group 'SQL Users' `

.. _description-8:

Description
^^^^^^^^^^^

Will get the members of a specific AAD group.

.. _examples-8:

Examples
^^^^^^^^

`Get-GroupMembers -Group 'SQL Users' `

`Get-GroupMembers -Group 'SQL Users' -OutFile users.csv`

.. _parameters-8:

Parameters
^^^^^^^^^^

-Group

Group name

-OutFile

Output file

.. _required-modules-7:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-8:

Output
^^^^^^

Group members of the specified group, optionally to a file.

**Get-AllGroupMembers**
~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-9:

Synopsis
^^^^^^^^

Gathers all the group members of all the groups.

.. _syntax-9:

Syntax
^^^^^^

`Get-AllGroupMembers`

.. _description-9:

Description
^^^^^^^^^^^

Goes through each group in AAD and lists the members.

.. _examples-9:

Examples
^^^^^^^^

`Get-AllGroupMembers -OutFile members.txt `

`Get-AllGroupMembers`

.. _parameters-9:

Parameters 
^^^^^^^^^^

-OutFile

Output filename/type

.. _required-modules-8:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-9:

Output
^^^^^^

List of group members for each group in AAD.

**Get-AllRoleMembers**
~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-10:

Synopsis
^^^^^^^^

Gets all the members of all roles. Roles does not mean groups.

.. _syntax-10:

Syntax
^^^^^^

`Get-AllRoleMembers`

.. _description-10:

Description
^^^^^^^^^^^

.. _examples-10:

Examples
^^^^^^^^

.. _get-allrolemembers-1:

`Get-AllRoleMembers`
^^^^^^^^^^^^^^^^^^^^^^

`Get-AllRoleMembers -OutFile users.csv`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

`Get-AllRoleMembers -OutFile users.txt`
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. _parameters-10:

Parameters 
^^^^^^^^^^

-OutFile

Output filename/type

.. _required-modules-9:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-10:

Output
^^^^^^

All members of all roles

**Get-RoleMembers** 
~~~~~~~~~~~~~~~~~~~

.. _synopsis-11:

Synopsis
^^^^^^^^

Gets the members of a role.

.. _syntax-11:

Syntax
^^^^^^

`Get-RoleMembers -Role [Role name]`

.. _description-11:

Description
^^^^^^^^^^^

Gets the members of a role. Capitalization matters (i.e. reader vs
Reader <---correct)

.. _examples-11:

Examples
^^^^^^^^

`Get-RoleMembers -Role Reader`

.. _parameters-11:

Parameters
^^^^^^^^^^

-Role

Name of role. Needs to be properly capitalized

.. _required-modules-10:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-11:

Output
^^^^^^

Members of specified role.

**Get-Roles**
^^^^^^^^^^^^^

.. _synopsis-12:

Synopsis
^^^^^^^^

Lists the roles of a specific user.

.. _syntax-12:

Syntax
^^^^^^

`Get-Roles -User [UPN] `

.. _description-12:

Description
^^^^^^^^^^^

Lists the Azure RBAC roles of a specific user based on their UPN.

.. _examples-12:

Examples
^^^^^^^^

`Get-Roles -User john@contoso.com`

.. _parameters-12:

Parameters 
^^^^^^^^^^

-User

UPN of the user

.. _required-modules-11:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-12:

Output
^^^^^^

Roles of the specified user

**Get-ServicePrincipals**
^^^^^^^^^^^^^^^^^^^^^^^^^

.. _synopsis-13:

Synopsis
^^^^^^^^

Returns all service principals

.. _syntax-13:

Syntax
^^^^^^

`Get-ServicePrincipals`

.. _description-13:

Description
^^^^^^^^^^^

Returns all service principals in AAD.

.. _examples-13:

Examples
^^^^^^^^

`Get-ServicePrincipals`

.. _parameters-13:

Parameters
^^^^^^^^^^

None

.. _required-modules-12:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-13:

Output
^^^^^^

List of SPs in AAD

**Get-ServicePrincipal**
^^^^^^^^^^^^^^^^^^^^^^^^

.. _synopsis-14:

Synopsis
^^^^^^^^

Returns all info on a service principal

.. _syntax-14:

Syntax
^^^^^^

`Get-ServicePrincipal –id [SP ID]`

.. _description-14:

Description
^^^^^^^^^^^

Returns all details on a service principal via the SP’s ID.

.. _examples-14:

Examples
^^^^^^^^

`Get-ServicePrincipal -id fdb54b57-a416-4115-8b21-81c73d2c2deb`

.. _parameters-14:

Parameters 
^^^^^^^^^^

-id

ID of the Service Principal

.. _required-modules-13:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-14:

Output
^^^^^^

Details of specified service principal

**Get-AppPermissions**
^^^^^^^^^^^^^^^^^^^^^^

.. _synopsis-15:

Synopsis
^^^^^^^^

Returns the permissions of an app

.. _syntax-15:

Syntax
^^^^^^

` Get-AppPermissions -Id [App ID]`

.. _description-15:

Description
^^^^^^^^^^^

Gathers the permissions an application has.

.. _examples-15:

Examples
^^^^^^^^

`Get-AppPermissions -Id fdb54b57-a416-4115-8b21-81c73d2c2deb`

.. _parameters-15:

Parameters
^^^^^^^^^^

-Id

ID of the Application

.. _required-modules-14:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-15:

Output
^^^^^^

Application’s permissions

**Get-WebApps**
~~~~~~~~~~~~~~~

.. _synopsis-16:

Synopsis
^^^^^^^^

Gets running webapps

.. _syntax-16:

Syntax
^^^^^^

`Get-WebApps`

.. _description-16:

Description
^^^^^^^^^^^

Gathers the names of the running web applications

.. _examples-16:

Examples
^^^^^^^^

`Get-WebApps`

.. _parameters-16:

Parameters
^^^^^^^^^^

None

.. _required-modules-15:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-16:

Output
^^^^^^

Web application names

**Get-WebAppDetails** 
~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-17:

Synopsis
^^^^^^^^

Gets running webapps details

Permissions
^^^^^^^^^^^

.. _syntax-17:

Syntax
^^^^^^

`Get-WebAppDetails -Name [WebAppName]`

.. _description-17:

Description
^^^^^^^^^^^

Gets the details of a web application

.. _examples-17:

Examples
^^^^^^^^

`Get-WebAppDetails -Name AppName`

.. _parameters-17:

Parameters 
^^^^^^^^^^

-name

Name of web application

.. _required-modules-16:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-17:

Output
^^^^^^

Details of web application

**Get-RunAsCertificate** 
~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-18:

Synopsis
^^^^^^^^

Will gather a RunAs accounts certificate which can then be used to login
as that account.

.. _permissions-1:

Permissions
^^^^^^^^^^^

.. _syntax-18:

Syntax
^^^^^^

`Get-RunAsCertificate -ResourceGroup [RG Name] -AutomationAccount [AA
Name]`

.. _description-18:

Description
^^^^^^^^^^^

Will gather a RunAs accounts certificate which can then be used to login
as that account. By default, RunAs accounts are contributors over the
subscription. This function does take a minute to run as it creates a
runbook, uploads it, runs it, then parses the output to gather the
certificate.

.. _examples-18:

Examples
^^^^^^^^

`Get-RunAsCertificate -ResourceGroup Test_RG -AutomationAccount
TestAccount`

.. _parameters-18:

Parameters
^^^^^^^^^^

-ResourceGroup

Name of the resource group the Automation Account is located in.

-AutomationAccount

The name of the Automation Account.

.. _required-modules-17:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure PowerShell

.. _output-18:

Output
^^^^^^

Connection string for the RunAs account

**Get-AADRole** 
~~~~~~~~~~~~~~~

.. _synopsis-19:

Synopsis
^^^^^^^^

Finds a specified AAD Role and its definitions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. _permissions-2:

Permissions
^^^^^^^^^^^

.. _syntax-19:

Syntax
^^^^^^

` Get-AADRole -Role [Role]`

.. _description-19:

Description
^^^^^^^^^^^

Finds a specified AAD Role and its definitions. Role must be properly capitalized. If role has a space in the name, use single quotes around the name.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. _examples-19:

Examples
^^^^^^^^

`Get-AADRole -Role 'Company Administrator'`

.. _parameters-19:

Parameters
^^^^^^^^^^

None

.. _required-modules-18:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

AzureAD PowerShell

.. _output-19:

Output
^^^^^^

Active roles

**Get-AADRoleMembers** 
~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-20:

Synopsis
^^^^^^^^

Lists the active roles in Azure AD and what users are part of the role.

.. _permissions-3:

Permissions
^^^^^^^^^^^

.. _syntax-20:

Syntax
^^^^^^

`Get-AADRoleMembers`

.. _description-20:

Description
^^^^^^^^^^^

Lists the active roles in Azure AD and what users are part of the role.

.. _examples-20:

Examples
^^^^^^^^

`Get-AADRoleMembers`

.. _parameters-20:

Parameters
^^^^^^^^^^

None

.. _required-modules-19:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-20:

Output
^^^^^^

Active roles

Operational
-----------

**Execute-Command**
^^^^^^^^^^^^^^^^^^^

.. _synopsis-21:

Synopsis
^^^^^^^^

Will run a command or script on a specified VM

.. _permissions-4:

Permissions
^^^^^^^^^^^

.. _syntax-21:

Syntax
^^^^^^

`Execute-Command -OS [OS] -ResourceGroup [RG Name] -VM [VM Name]
-Command [Command]`

.. _description-21:

Description
^^^^^^^^^^^

Executes a command on a virtual machine in Azure using `az vm
run-command invoke`

.. _examples-21:

Examples
^^^^^^^^

`Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10
-Command whoami`

.. _parameters-21:

Parameters 
^^^^^^^^^^

-OS

Operating system, options are `Linux` or `Windows`

-ResourceGroup

Resource group name the VM is located in

-VM

Name of the virtual machine to execute the command on

-Command

The command to be executed

.. _required-modules-20:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-21:

Output
^^^^^^

Output of command being run or a failure message if failed

**Execute-MSBuild** 
~~~~~~~~~~~~~~~~~~~

.. _synopsis-22:

Synopsis
^^^^^^^^

Will run a supplied MSBuild payload on a specified VM. By default, Azure
VMs have .NET 4.0 installed. Requires Contributor Role. Will run as
SYSTEM.

.. _permissions-5:

Permissions
^^^^^^^^^^^

.. _syntax-22:

Syntax
^^^^^^

`Execute-MSBuild -ResourceGroup [RG Name] -VM [Virtual Machine name]
-File [C:/path/to/payload/onyourmachine.xml]`

.. _description-22:

Description
^^^^^^^^^^^

Uploads an MSBuild payload as a .ps1 script to the target VM then calls
msbuild.exe with `az run-command invoke`.

.. _examples-22:

Examples
^^^^^^^^

`Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File
C:tempbuild.xml`

.. _parameters-22:

Parameters 
^^^^^^^^^^

-ResourceGroup
^^^^^^^^^^^^^^

Resource group name the VM is located in
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-VM
^^^

Name of the virtual machine to execute the command on
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-File
^^^^^

Location of build.xml file

.. _required-modules-21:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-22:

Output
^^^^^^

Success message of msbuild starting the build if successful, error
message if upload failed.

**Execute-Program** 
~~~~~~~~~~~~~~~~~~~

.. _synopsis-23:

Synopsis
^^^^^^^^

Will run a given binary on a specified VM

.. _permissions-6:

Permissions
^^^^^^^^^^^

.. _syntax-23:

Syntax
^^^^^^

`Execute-Program -ResourceGroup [RG Name] -VM [Virtual Machine name]
-File [C:/path/to/payload.exe]`

.. _description-23:

Description
^^^^^^^^^^^

Takes a supplied binary, base64 encodes the byte stream to a file,
uploads that file to the VM, then runs a command via `az run-command
invoke` to decode the base64 byte stream to a .exe file, then executes
the binary.

.. _examples-23:

Examples
^^^^^^^^


::
	Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File
C:tempbeacon.exe`

.. _parameters-23:

Parameters 
^^^^^^^^^^

-ResourceGroup

Resource group name the VM is located in

-VM

Name of the virtual machine to execute the command on

-File

Location of executable binary

.. _required-modules-22:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-23:

Output
^^^^^^

“Provisioning Succeeded” output. Because it’s a binary being executed,
there will be no native output unless the binary is meant to return data
to stdout.

**Create-Backdoor** 
~~~~~~~~~~~~~~~~~~~

.. _synopsis-24:

Synopsis
^^^^^^^^

Creates a backdoor in Azure via Runbooks

.. _permissions-7:

Permissions
^^^^^^^^^^^

.. _syntax-24:

Syntax
^^^^^^

`Create-Backdoor -Username [Username] -Password [Password]
-AutomationAccount [AA name] -ResourceGroup [RG Name] -NewUsername [New
UN] -NewPassword [New Password]`

.. _description-24:

Description
^^^^^^^^^^^

Will create a Runbook that creates an Azure account and generates a
Webhook to that Runbook so it can be executed if you lose access to
Azure. Also gives the ability to upload your own .ps1 file as a Runbook
(Customization)

This requires an account that is part of the 'Administrators' Role
(Needed to make a user)

.. _examples-24:

Examples
^^^^^^^^

`Create-Backdoor -Username Administrator@contoso.com -Password
Password! -AutomationAccount AutomationAccountExample -ResourceGroup
ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd
`

.. _parameters-24:

Parameters 
^^^^^^^^^^

-Username

Username you used to login to Azure with, that has permissions to create
a Runbook and user

-Password

Password to that account

-AutomationAccount

Azure Automation Account name

-ResourceGroup

Resource Group name

-NewUsername

Username you want to create

-NewPassword

Password for that new account

.. _required-modules-23:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure PowerShell

.. _output-24:

Output
^^^^^^

URI if successful, permissions error if failure

**Execute-Backdoor** 
~~~~~~~~~~~~~~~~~~~~

.. _synopsis-25:

Synopsis
^^^^^^^^

This runs the backdoor URI that is created with "Create-Backdoor”

.. _permissions-8:

Permissions
^^^^^^^^^^^

.. _syntax-25:

Syntax
^^^^^^

`Execute-Backdoor -URI [URI]`

.. _description-25:

Description
^^^^^^^^^^^

Executes the URI created by Create-Backdoor

.. _examples-25:

Examples
^^^^^^^^

`Execute-Backdoor -URI
https://s16events.azure-automation.net/webhooks?token=qol1XudydN13%2bI5bilBZzbCjdzTIcfs4Fj4yH61WvQ%3d`

.. _parameters-25:

Parameters 
^^^^^^^^^^

-URI

The URI generated by Create-Backdoor

.. _required-modules-24:

Required Modules
^^^^^^^^^^^^^^^^

| Azure CLI
| Azure PowerShell

.. _output-25:

Output
^^^^^^

Webhook successfully executed

**Execute-CommandRunbook** 
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-26:

Synopsis
^^^^^^^^

Will execute a supplied command or script from a Runbook if the Runbook
is configured with a "RunAs" account

.. _permissions-9:

Permissions
^^^^^^^^^^^

.. _syntax-26:

Syntax
^^^^^^

`Execute-CommandRunbook -AutomationAccount [AA Name] -ResourceGroup [RG
Name] -VM [VM Name] -Command [Command]`

.. _description-26:

Description
^^^^^^^^^^^

If an Automation Account is utilizing a ‘Runas’ account, this allows you
to run commands against a virtual machine if that RunAs account has the
correct permissions over the VM.

.. _examples-26:

Examples
^^^^^^^^

`Execute-CommandRunbook -AutomationAccount TestAccount -ResourceGroup
TestRG -VM Win10Test -Command whoami`

`Execute-CommandRunbook -AutomationAccount TestAccount -ResourceGroup
TestRG -VM Win10Test -Script "C:temptest.ps1"`

.. _parameters-26:

Parameters 
^^^^^^^^^^

-AutomationAccount

Automation Account name

-ResourceGroup

Resource Group name

-VM

VM name

-Command (optional)

Command to be run against the VM. Choose this or -Script if executing an
entire script

-Script (optional)

Run an entire script instead of just one command.

.. _required-modules-25:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure PowerShell

.. _output-26:

Output
^^^^^^

Output of command if successfully ran.

**Upload-StorageContent** 
~~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-27:

Synopsis
^^^^^^^^

Uploads a supplied file to a storage share.

.. _permissions-10:

Permissions
^^^^^^^^^^^

.. _syntax-27:

Syntax
^^^^^^

`Upload-StorageContent -StorageAccount [Storage Account name] -Share
[Storage share name] -File [File name to upload]`

.. _description-27:

Description
^^^^^^^^^^^

Uploads a supplied file to a storage container located in a storage
account

.. _examples-27:

Examples
^^^^^^^^

`Upload-StorageContent -StorageAccount TestName -Share TestShare -File
secret.txt`

.. _parameters-27:

Parameters 
^^^^^^^^^^

-StorageAccount

Name of Storage account. Try Get-StorageAccounts for a list.

-File

File to upload

-Share

Share name to upload to

.. _required-modules-26:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure Powershell

.. _output-27:

Output
^^^^^^

Success message

**Stop-VM** 
~~~~~~~~~~~

.. _synopsis-28:

Synopsis
^^^^^^^^

Stops a Virtual Machine

.. _permissions-11:

Permissions
^^^^^^^^^^^

.. _syntax-28:

Syntax
^^^^^^

` Stop-VM -VM [VM name] -ResourceGroup [RG] `

.. _description-28:

Description
^^^^^^^^^^^

Stops a VM

.. _examples-28:

Examples
^^^^^^^^

` Stop-VM -VM Example2016R2 -ResourceGroup Test_RG`

.. _parameters-28:

Parameters 
^^^^^^^^^^

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-27:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-28:

Output
^^^^^^

VM successfully stops

Start-VM 
~~~~~~~~

**Synopsis**

Starts a Virtual Machine

**Permissions**

**Syntax**

` Start-VM -VM [VM name] -ResourceGroup [RG] `

**Description**

Starts a VM

**Examples**

` Start-VM -VM Example2016R2 -ResourceGroup Test_RG`

**Parameters**

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-28:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

**Output**

VM successfully starts

.. _section-1:

Restart-VM 
~~~~~~~~~~

**Synopsis**

Restarts a Virtual Machine

**Permissions**

**Syntax**

` Restart-VM -VM [VM name] -ResourceGroup [RG] `

**Description**

Restarts a VM

**Examples**

` Restart-VM -VM Example2016R2 -ResourceGroup Test_RG`

**Parameters**

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-29:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

**Output**

VM successfully restarts

**Start-Runbook** 
~~~~~~~~~~~~~~~~~

.. _synopsis-29:

Synopsis
^^^^^^^^

Starts a Runbook

.. _permissions-12:

Permissions
^^^^^^^^^^^

.. _syntax-29:

Syntax
^^^^^^

` Start-Runbook -Account [Automation Account name] -ResourceGroup
[Resource Group name] -Runbook [Runbook name] `

.. _description-29:

Description
^^^^^^^^^^^

Starts a specified Runbook

.. _examples-29:

Examples
^^^^^^^^

` Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook
TestRunbook `

.. _parameters-29:

Parameters 
^^^^^^^^^^

-Account

Name of Automation Account the Runbook is in

-ResourceGroup

Resource group it's located in

-Runbook

Name of runbook

.. _required-modules-30:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure PowerShell

.. _output-29:

Output
^^^^^^

Runbook output

**Set-Role** 
~~~~~~~~~~~~

.. _synopsis-30:

Synopsis
^^^^^^^^

Assigns a user a role for a specific resource or subscription

.. _permissions-13:

Permissions
^^^^^^^^^^^

.. _syntax-30:

Syntax
^^^^^^

`Set-Role -Role Owner -User [UPN] -Resource [Resource name]`

.. _description-30:

Description
^^^^^^^^^^^

Sets a role over a resource or subscription.

.. _examples-30:

Examples
^^^^^^^^

`Set-Role -Role Owner -User john@contoso.com -Resource WIN10VM`

`Set-Role -Role Owner -User john@contoso.com -Subscription SubName`

.. _parameters-30:

Parameters 
^^^^^^^^^^

-User

Name of user in format user@domain.com

-Role

Role name (must be properly capitalized)

-Resource

Name of Resource

-Subscription

Name of subscription

.. _required-modules-31:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-30:

Output
^^^^^^

Role successfully applied

Remove-Role 
~~~~~~~~~~~

**Synopsis**

Removes a user from a role for a specific resource or subscription

**Permissions**

**Syntax**

`Set-Role -Role Owner -User [UPN] -Resource [Resource name]`

**Description**

Removes a role over a resource or subscription.

**Examples**

`Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM`

`Remove-Role -Role Owner -User john@contoso.com -Subscription SubName`

**Parameters**

-User

Name of user in format user@domain.com

-Role

Role name (must be properly capitalized)

-Resource

Name of Resource

-Subscription

Name of subscription

.. _required-modules-32:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

**Output**

Role successfully Removed

**Set-Group** 
~~~~~~~~~~~~~

.. _synopsis-31:

Synopsis
^^^^^^^^

Adds a user to an Azure AD Group

.. _permissions-14:

Permissions
^^^^^^^^^^^

.. _syntax-31:

Syntax
^^^^^^

`Set-Group -User [UPN] -Group [Group name]`

.. _description-31:

Description
^^^^^^^^^^^

Adds a user to an AAD group. If the group name has spaces, put the group
name in single quotes.

.. _examples-31:

Examples
^^^^^^^^

`Set-Group -User john@contoso.com -Group 'SQL Users' `

.. _parameters-31:

Parameters 
^^^^^^^^^^

-User

UPN of the user

-Group

AAD Group name

.. _required-modules-33:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-31:

Output
^^^^^^

User added to group

**Set-Password** 
~~~~~~~~~~~~~~~~

.. _synopsis-32:

Synopsis
^^^^^^^^

Sets a user's password

.. _permissions-15:

Permissions
^^^^^^^^^^^

.. _syntax-32:

Syntax
^^^^^^

`Set-Password -Username [UPN] -Password [new password]`

.. _description-32:

Description
^^^^^^^^^^^

Sets a user’s password. Requires AAD PS Module.

.. _examples-32:

Examples
^^^^^^^^

`Set-Password -Username john@contoso.com -Password newpassw0rd1`

.. _parameters-32:

Parameters 
^^^^^^^^^^

-Password

New password for user

-Username

Name of user

.. _required-modules-34:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

AzureAD PowerShell

.. _output-32:

Output
^^^^^^

Password successfully set

Secret/Key/Certificate Gathering
--------------------------------

**Get-KeyVaults**
^^^^^^^^^^^^^^^^^

.. _synopsis-33:

Synopsis
^^^^^^^^

Lists the Key Vaults

.. _permissions-16:

Permissions
^^^^^^^^^^^

.. _syntax-33:

Syntax
^^^^^^

`Get-KeyVaults`

.. _description-33:

Description
^^^^^^^^^^^

Gathers the Keyvaults in the subscription

.. _examples-33:

Examples
^^^^^^^^

`Get-KeyVaults`

.. _parameters-33:

Parameters 
^^^^^^^^^^

None

.. _required-modules-35:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-33:

Output
^^^^^^

List of KeyVaults

**Get-KeyVaultContents** 
~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-34:

Synopsis
^^^^^^^^

Get the secrets from a specific Key Vault

.. _permissions-17:

Permissions
^^^^^^^^^^^

.. _syntax-34:

Syntax
^^^^^^

`Get-KeyVaultContents -Name [VaultName] `

.. _description-34:

Description
^^^^^^^^^^^

Takes a supplied KeyVault name and edits the access policy to allow the
current user to view the vault. Once the secrets are displayed, it
re-edits the policy and removes your access.

.. _examples-34:

Examples
^^^^^^^^

`Get-KeyVaultContents -Name TestVault`

.. _parameters-34:

Parameters 
^^^^^^^^^^

-Name

Vault name

.. _required-modules-36:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-34:

Output
^^^^^^

KeyVault contents

**Get-AllKeyVaultContents** 
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-35:

Synopsis
^^^^^^^^

Gets ALL the secrets from all Key Vaults. If the logged in user cannot
access a key vault, it tries to edit the access policy to allow access.

.. _permissions-18:

Permissions
^^^^^^^^^^^

.. _syntax-35:

Syntax
^^^^^^

`Get-AllKeyVaultContents`

.. _description-35:

Description
^^^^^^^^^^^

Goes through each key vault and edits the access policy to allow the
user to view the contents, displays the contents, then re-edits the
policies to remove the user from the access policy.

.. _examples-35:

Examples
^^^^^^^^

`Get-AllKeyVaultContents`

.. _parameters-35:

Parameters 
^^^^^^^^^^

None

.. _required-modules-37:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-35:

Output
^^^^^^

Key vault content

Data Exfiltration
-----------------

**Get-StorageAccounts** 
~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-36:

Synopsis
^^^^^^^^

Get a list of storage accounts and their blobs

.. _permissions-19:

Permissions
^^^^^^^^^^^

.. _syntax-36:

Syntax
^^^^^^

`Get-StorageAccounts`

.. _description-36:

Description
^^^^^^^^^^^

Gets a list of storage account blobs

.. _examples-36:

Examples
^^^^^^^^

`Get-StorageAccounts`

.. _parameters-36:

Parameters 
^^^^^^^^^^

None

.. _required-modules-38:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure Powershell

.. _output-36:

Output
^^^^^^

List of storage accounts

**Get-StorageAccountKeys** 
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-37:

Synopsis
^^^^^^^^

Gets the account keys for a storage account

.. _permissions-20:

Permissions
^^^^^^^^^^^

.. _syntax-37:

Syntax
^^^^^^

`Get-StorageAccountKeys -ResourceGroup [Resource Group name] -Account
[StorageAccountName]`

.. _description-37:

Description
^^^^^^^^^^^

Gets the account keys for a storage account to be used to access the
storage account.

.. _examples-37:

Examples
^^^^^^^^

`Get-StorageAccountKeys -ResourceGroup MyGroup -Account
StorageAccountName -kerb `

.. _parameters-37:

Parameters 
^^^^^^^^^^

- ResourceGroup

Resource group the Storage account is located in

-Account

Storage account name

-kerb (optional, use if kerberos keys are suspected)

Also grab the “Kerberos keys”

.. _required-modules-39:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure Powershell

.. _output-37:

Output
^^^^^^

List of keys in plain text

**Get-StorageContents** 
~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-38:

Synopsis
^^^^^^^^

Gets the contents of a storage container or file share.

.. _permissions-21:

Permissions
^^^^^^^^^^^

.. _syntax-38:

Syntax
^^^^^^

`Get-StorageContents -StorageAccount [Storage account name]
-ResourceGroup [Resource group name] -File [File name]`

.. _description-38:

Description
^^^^^^^^^^^

Gets the contents of a storage container or file share. OAuth is not
support to access file shares via cmdlets, so you must have access to
the Storage Account's key.

.. _examples-38:

Examples
^^^^^^^^

` Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup
-File secret.txt -NoDelete`

.. _parameters-38:

Parameters 
^^^^^^^^^^

-ResourceGroup

Resource Group name

-StorageAccount

Name of Storage account. Try Get-StorageAccounts for a list.

-File

Gets the contents of a specified file. If file is in a path, include the
full path. Optional

-NoDelete

Does not delete the file after it's downloaded. Optional

.. _required-modules-40:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure Powershell

.. _output-38:

Output
^^^^^^

File contents are displayed

**Get-Runbooks** 
~~~~~~~~~~~~~~~~

.. _synopsis-39:

Synopsis
^^^^^^^^

Lists all the run books in all Automation accounts under the
subscription

.. _permissions-22:

Permissions
^^^^^^^^^^^

.. _syntax-39:

Syntax
^^^^^^

`Get-Runbooks`

.. _description-39:

Description
^^^^^^^^^^^

Recursively goes through each Automation Account and lists the runbook
names, it’s state, the creation and modification time, and what AA it is
under.

.. _examples-39:

Examples
^^^^^^^^

`Get-Runbooks`

.. _parameters-39:

Parameters 
^^^^^^^^^^

None

.. _required-modules-41:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure PowerShell

.. _output-39:

Output
^^^^^^

List of runbooks and their associated Automation Accounts

**Get-RunbookContent** 
~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-40:

Synopsis
^^^^^^^^

Gets a specific Runbook and displays its contents. Use -NoDelete to not
delete after reading

.. _permissions-23:

Permissions
^^^^^^^^^^^

.. _syntax-40:

Syntax
^^^^^^

`Get-RunbookContent -Account [AutomationAccountName] -ResourceGroup
[ResourceGroupName] -Runbook [Runbook name]`

.. _description-40:

Description
^^^^^^^^^^^

.. _examples-40:

Examples
^^^^^^^^

`Get-RunbookContent -Account AutomationAccountexample -ResourceGroup
TestGroup -Runbook TestBook`

`Get-RunbookContent -Account AutomationAccountexample -ResourceGroup
TestGroup -Runbook TestBook -Slot "Published"`

`Get-RunbookContent -Account AutomationAccountexample -ResourceGroup
TestGroup -Runbook TestBook -Slot "Draft"`

.. _parameters-40:

Parameters 
^^^^^^^^^^

-Runbook

Name of Runbook

-Group

Resource group it's located in

-Account

Automation Account Name

-NoDelete

Do not delete after displaying contents

-Slot

Optional; use if differenciating between published or drafted Runbook

.. _required-modules-42:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

Azure PowerShell

.. _output-40:

Output
^^^^^^

Runbook content

**Get-AvailableVMDisks** 
~~~~~~~~~~~~~~~~~~~~~~~~

.. _synopsis-41:

Synopsis
^^^^^^^^

Lists the VM disks available.

.. _permissions-24:

Permissions
^^^^^^^^^^^

.. _syntax-41:

Syntax
^^^^^^

`Get-AvailableVMDisks`

.. _description-41:

Description
^^^^^^^^^^^

Lists the VM disks available in the subscription

.. _examples-41:

Examples
^^^^^^^^

`Get-AvailableVMDisks`

.. _parameters-41:

Parameters 
^^^^^^^^^^

None

.. _required-modules-43:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-41:

Output
^^^^^^

List of VM Disks

**Get-VMDisk** 
~~~~~~~~~~~~~~

.. _synopsis-42:

Synopsis
^^^^^^^^

Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour.

.. _permissions-25:

Permissions
^^^^^^^^^^^

.. _syntax-42:

Syntax
^^^^^^

` Get-VMDisk -DiskName [Disk name] -ResourceGroup [RG Name]`

.. _description-42:

Description
^^^^^^^^^^^

Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour. Note that you’re downloading a VM Disk, so it’s
probably going to be many GBs in size. Hope you have fiber!

.. _examples-42:

Examples
^^^^^^^^

` Get-VMDisk -DiskName
AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5 -ResourceGroup
TestGroup`

.. _parameters-42:

Parameters 
^^^^^^^^^^

-ResourceGroup

Resource group name

-DiskName

Name of VM disk

.. _required-modules-44:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-42:

Output
^^^^^^

Link to download the VM disk

**Get-VMs** 
~~~~~~~~~~~

.. _synopsis-43:

Synopsis
^^^^^^^^

Lists all virtual machines available, their disks, and their IPs.

.. _permissions-26:

Permissions
^^^^^^^^^^^

.. _syntax-43:

Syntax
^^^^^^

`Get-VMs`

.. _description-43:

Description
^^^^^^^^^^^

Lists all virtual machines available, their disks, and their IPs, as
well their running state

.. _examples-43:

Examples
^^^^^^^^

`Get-VMs`

.. _parameters-43:

Parameters 
^^^^^^^^^^

None

.. _required-modules-45:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-43:

Output
^^^^^^

List of VMs and details

**Get-SQLDBs** 
~~~~~~~~~~~~~~

.. _synopsis-44:

Synopsis
^^^^^^^^

Lists the available SQL Databases on a server

.. _permissions-27:

Permissions
^^^^^^^^^^^

.. _syntax-44:

Syntax
^^^^^^

`Get-SQLDBs`

.. _description-44:

Description
^^^^^^^^^^^

Lists the available SQL Databases on a server. There currently are no
cmdlets in any PS module to interact with said DBs, so the only option
is to login via portal and use the preview browser.

.. _examples-44:

Examples
^^^^^^^^

`Get-SQLDBs`

.. _parameters-44:

Parameters 
^^^^^^^^^^

None

.. _required-modules-46:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-44:

Output
^^^^^^

List of SQL Databases in the subscription

Mandatory
---------

**Set-Subscription**
~~~~~~~~~~~~~~~~~~~~

.. _synopsis-45:

Synopsis
^^^^^^^^

Sets default subscription. Necessary if in a tenant with multiple
subscriptions.

.. _permissions-28:

Permissions
^^^^^^^^^^^

.. _syntax-45:

Syntax
^^^^^^

`Set-Subscription -Id [Subscription ID]`

.. _description-45:

Description
^^^^^^^^^^^

Sets the default subscription

.. _examples-45:

Examples
^^^^^^^^

`Set-Subscription -Id b049c906-7000-4899-b644-f3eb835f04d0`

.. _parameters-45:

Parameters 
^^^^^^^^^^

-Id

Subscription ID

.. _required-modules-47:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-45:

Output
^^^^^^

Success message

Help
----

**PowerZure**
~~~~~~~~~~~~~

.. _synopsis-46:

Synopsis
^^^^^^^^

Displays info about this script.

.. _permissions-29:

Permissions
^^^^^^^^^^^

.. _syntax-46:

Syntax
^^^^^^

`PowerZure -h`

.. _description-46:

Description
^^^^^^^^^^^

Displays info about this script.

.. _examples-46:

Examples
^^^^^^^^

`PowerZure -h`

.. _parameters-46:

Parameters 
^^^^^^^^^^

-h

Help

.. _required-modules-48:

Required Modules
^^^^^^^^^^^^^^^^

Azure CLI

.. _output-46:

Output
^^^^^^

List of functions in this script
