Operational
===========

Set-AzureSubscription
----------------

**Synopsis**

Sets default subscription. Necessary if in a tenant with multiple
subscriptions.

**Syntax**

::

  Set-AzureSubscription -Id [Subscription ID]

**Description**

Sets the default subscription

**Examples**

::

  Set-AzureSubscription -Id b049c906-7000-4899-b644-f3eb835f04d0

**Parameters** 

-Id

Subscription ID

**Output**


Success message

Invoke-AzureRunCommand
---------------

**Synopsis**


Will run a command or script on a specified VM

**Syntax**


::

  Invoke-AzureRunCommand -VMName [VM Name] -Command [Command]
  
::

  Invoke-AzureRunCommand -VMName [VM Name] -Script [Full Path To Script]  

**Description**


Executes a command on a virtual machine in Azure using Invoke-AzVMRunCommand

**Examples**


::

  Invoke-AzureRunCommand -VMName AzureWin10 -Command whoami
  
::

  Invoke-AzureRunCommand -VMName AzureWin10 -Script 'C:\temp\test.ps1'

**Parameters** 


-VMName

Name of the virtual machine to execute the command on

-Command

The command to be executed

-Script

The path to the script to execute

**Output**


Output of command being run or a failure message if failed


Invoke-AzureRunMSBuild
---------------


**Synopsis**


Will run a supplied MSBuild payload on a specified VM. By default, Azure
VMs have .NET 4.0 installed. Requires Contributor Role. Will run as
SYSTEM.


**Syntax**

::

  Invoke-AzureRunMSBuild -VMName [Virtual Machine name] -File [C:/path/to/payload/onyourmachine.xml]



**Description**


Uploads an MSBuild payload as a .ps1 script to the target VM then calls
msbuild.exe with 

::

  Invoke-AzVMRunCommand



**Examples**



::

  Invoke-AzureRunMSBuildd -VMName AzureWin10 -File 'C:\temp\build.xml'


**Parameters** 



-VMName


Name of the virtual machine to execute the command on


-File


Path location of build.xml file


**Output**


Success message of msbuild starting the build if successful, error
message if upload failed.

Invoke-AzureRunProgram
---------------


**Synopsis**


Will run a given binary on a specified VM


**Syntax**

::

  Invoke-AzureRunProgram  -VMName [Virtual Machine name] -File [C:/path/to/payload.exe]


**Description**


Takes a supplied binary, base64 encodes the byte stream to a file, uploads that file to the VM, then runs a command via Invoke-AzVMRunCommand to decode the base64 byte stream to a .exe file, then executes the binary.

**Examples**


::

	Invoke-AzureRunProgram -VMName AzureWin10 -File C:\tempbeacon.exe


**Parameters** 

-VMName

Name of the virtual machine to execute the command on

-File

Location of executable binary


**Output**


“Provisioning Succeeded” Output. Because it’s a binary being executed,
there will be no native Output unless the binary is meant to return data
to stdout.

Invoke-AzureCommandRunbook
----------------------

**Synopsis**

Will execute a supplied command or script from a Runbook if the Runbook
is configured with a "RunAs" account

**Syntax**

::

  Invoke-AzureCommandRunbook -AutomationAccount [Automation Account name] -VMName [VM Name] -Command [command]

::

  Invoke-AzureCommandRunbook -AutomationAccount [Automation Account name] -VMName [VM Name] -Script [Path to script]
  
**Description**


If an Automation Account is utilizing a ‘Runas’ account, this allows you
to run commands against a virtual machine if that RunAs account has the
correct  over the VM.

**Examples**

::

  Invoke-AzureCommandRunbook -AutomationAccount TestAccount -VMName Win10Test -Command whoami

::

  Invoke-AzureCommandRunbook -AutomationAccount TestAccount -VMName Win10Test -Script "C:temptest.ps1"

**Parameters** 


-AutomationAccount

Automation Account name

-VMName

VM name

-Command

Command to be run against the VM. Choose this or -Script if executing an
entire script

-Script

Run an entire script instead of just one command.

**Output**

Output of command if successfully ran.


Create-AzureBackdoor
---------------

**Synopsis**


Creates a backdoor in Azure via Service Principal

**Syntax**


::

  Create-AzureBackdoor -Username [Username] -Password [Password] 

**Description**


Will create a new Service Principal in Azure and assign it to the Global Administrator/Company Administrator role in AzureAD. This can then be logged into and escalated to User Administrator in Azure RBAC with Set-AzureElevatedPrivileges

**Examples**

::

  Create-AzureBackdoor -Username 'testserviceprincipal' -Password 'Password!'


**Parameters** 


-Username

Desired name of the Service Principal

-Password

Desired password for the account

**Output**


Success message if successful,  error if failure


Get-AzureRunAsCertificate
--------------------

**Synopsis**


Will gather a RunAs accounts certificate if one is being used by an automation account, which can then be used to login as that account. By default, RunAs accounts are contributors over the subscription. This function does take a minute to run.


**Syntax**

::

  Get-AzureRunAsCertificate  -AutomationAccount [AA Name]


**Description**

Creates a Runbook for the RunAs account to run, which will gather the RunAs Account's certificate and write it to the job output as base64. The function then grabs the job output, decodes the base64 certificate into a .pfx certificate, and automatically imports it. The function then spits out a one-liner that can be copy+pasted to login as the RunAs account.


**Examples**

::

  Get-AzureRunAsCertificate -AutomationAccount TestAccount



**Parameters**

-AutomationAccount

The name of the Automation Account.


**Output**


Connection string for the RunAs account

Start-AzureRunbook
-------------



**Synopsis**


Starts a Runbook


**Syntax**

::

   Start-AzureRunbook -Account [Automation Account name] -Runbook [Runbook name] 

**Description**


Starts a specified Runbook


**Examples**

::

   Start-AzureRunbook -Account AutoAccountTest -Runbook TestRunbook 


**Parameters** 

-Account

Name of Automation Account the Runbook is in

-Runbook

Name of runbook

**Output**


Runbook Output

Add-AzureADRole
--------

**Synopsis**

Assigns a specific Azure AD role to a User

**Syntax**

::

  Add-AzureADRole -Username [User Principal Name] -Role '[Role name]'\

::

  Add-AzureADRole -UserId [UserId] -RoleId '[Role Id]'
  

**Description**


Assigns a specific Azure AD role to a User using either the role name or ID and username or user ID.

**Examples**



::

  Add-AzureADRole -Username test@test.com -Role 'Company Administrator'


::

  Add-AzureADRole -UserId 6eca6b85-7a3d-4fcf-b8da-c15a4380d286 -Role '4dda258a-4568-4579-abeb-07709e34e307'

**Parameters** 


-Username

Name of user in format user@domain.com

-UserId

Id of the user

-Role

Role name (must be properly capitalized)

-RoleId

ID of the role

**Output**

Role successfully applied

Add-AzureADGroup 
---------

**Synopsis**


Adds a user to an Azure AD Group

**Syntax**

::

  Add-AzureADGroup  -User [UPN] -Group [Group name]

**Description**


Adds a user to an AAD group. If the group name has spaces, put the group
name in single quotes.

**Examples**

::

  Add-AzureADGroup  -User john@contoso.com -Group 'SQL Users' 

**Parameters** 


-User

UPN of the user

-Group

AAD Group name

**Output**


User added to group

Set-AzureUserPassword
------------

**Synopsis**


Sets a user's password


**Syntax**

::

  Set-AzureUserPassword -Username [UPN] -Password [new password]

**Description**


Sets a user’s password. 


**Examples**

::

  Set-AzureUserPassword -Username john@contoso.com -Password newpassw0rd1



**Parameters** 


-Password

New password for user

-Username

Name of user



**Output**


Password successfully set


New-AzureUser
------------



**Synopsis**


Creates a user in Azure Active Directory



**Syntax**

::

   New-AzureUser -Username [User Principal Name] -Password [Password]



**Description**

Creates a user in Azure Active Directory



**Examples**

::

   New-AzureUser -Username 'test@test.com' -Password Password1234


**Parameters** 


-Username 

Name of user including domain

-Password 

New password for the user



**Output**


User is created


Add-AzureSPSecret
------------



**Synopsis**


Adds a secret to a service principal



**Syntax**

::

  Add-AzureSPSecret -ApplicationName [ApplicationName name] -Password [new secret]


**Description**

Adds a secret to a service principal so you can login as that service principal.



**Examples**

::

   Add-AzureSPSecret -ApplicationName "MyTestApp" -Password password123



**Parameters** 

-ApplicationName


Name of the Service Principal or application that is using the Service principal


-Password 


New password "secret" for the Service Principal.


**Output**

Connection string to login as new user if successful


Set-AzureElevatedPrivileges
------------



**Synopsis**


Elevates the user's privileges from Global Administrator in AzureAD to include User Access Administrator in Azure RBAC.




**Syntax**

::

   Set-AzureElevatedPrivileges



**Description**


This works by making a Graph API call. You must be logged in as a user with Global Administator role assigned. You cannot elevate if you are a service principal due to API limitiations.



**Examples**

::

   Set-AzureElevatedPrivileges



**Parameters** 

None



**Output**

No Error message if successful

Add-AzureSPSecret
------------



**Synopsis**

Adds a secret to a service principal



**Syntax**

::

   Add-AzureSPSecret -ApplicationName [Name of application] -Password [Password]



**Description**


Adds a secret to a service principal so a known password is set and can then be used to login as that principal.



**Examples**

::

   Add-AzureSPSecret -ApplicationName "ApplicationName" -Password password123



**Parameters** 


-ApplicationName


Name of application the Service Principal is tied to


-Password

Desired password/secret



**Output**

No Error message if successful

Get-AzureKeyVaultContent
------------


**Synopsis**

Get the secrets and certificates from a specific Key Vault or all of them



**Syntax**

::

   Get-AzureKeyVaultContent -VaultName [Name of vault]



**Description**

Searches for all available key vaults and modifies the access policy to allow downloading of the contents in the vault. Then gets the secrets and certificates from the vault. This will display the contents of any certificates. To export a key or certificate, use Export-AzureKeyVaultContent



**Examples**

::

   Get-AzureKeyVaultContent -VaultName VaultName



**Parameters** 


-VaultName


Key Vault Name


-All 


All Key Vaults


**Output**

Contents of the key vault contents

Export-AzureKeyVaultContent
------------



**Synopsis**

Exports a Key as PEM or Certificate as PFX from the Key Vault



**Syntax**

::

   Export-AzureKeyVaultContent -VaultName [Vault Name] -Type [Key or Certificate] -Name [Name of Key or Cert] -OutFilePath  [Full path of where to export]



**Description**

Searches for all available key vaults and modifies the access policy to allow downloading of the contents in the vault. Exports a Key as PEM or Certificate as PFX from the Key Vault



**Examples**

::

   Export-AzureKeyVaultContent -VaultName VaultTest -Type Key -Name Testkey1234 -OutFilePath C:\Temp



**Parameters** 

-VaultName


Key Vault Name


-All 


All Key Vaults


-Type

Key or Certificate


-Name 


Name of Key or Certificate that is being extracted


-OutFilePath

Where to extract the key or certificate



**Output**

Successful export

Get-AzureStorageContent
------------



**Synopsis**

Gathers a file from a specific blob or File Share



**Syntax**

::

   Get-AzureStorageContent -StorageAccountName TestAcct -Type Container 



**Description**

Gathers a file from a specific blob or File Share



**Examples**

::

   Get-AzureStorageContent

::

   Get-AzureStorageContent -StorageAccountName TestAcct -Type Container 
   


**Parameters** 

-Share


Name of the share the file is located in 


-Path 


Path of the file in the target share

-Blob 


Name of the blob the file is located in 

-StorageAccountName

Name of a specific account

-ResourceGroup


The RG the Storage account is located in

-ContainerName 


Name of the Container the file is located in



**Output**

Display of contents

Get-AzureStorageContent
------------


**Synopsis**

Generates a link to download a Virtual Machiche's disk. The link is only available for 24 hours.


**Syntax**

::

  Get-AzureVMDisk -DiskName [Name of Disk]    


**Description**

The VM must be turned off/disk not in use. While the link is active, the VM cannot be turned on.


**Examples**

::

  Get-AzureVMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5     


**Parameters** 

-DiskName


Name of the disk

**Output**

Link to download the disk

Get-AzureRunbookContent
------------


**Synopsis**

Gets a specific Runbook and displays its contents or all runbook contents



**Syntax**

::

  Get-AzureRunbookContent -Runbook [Name of Runbook] -OutFilePath [Path of where to export runbooks]



**Description**

Gets a specific Runbook and displays its contents or all runbook contents



**Examples**

::

  Get-AzureRunbookContent -Runbook Runbooktest -OutFilePath 'C:\temp'

::

  Get-AzureRunbookContent -All -OutFilePath 'C:\temp 
  


**Parameters** 

-Runbook 


Name of Runbook


-All 


-OutFilePath 


Where to save Runbook



**Output**

Successful export of the runbooks