Data Exfiltration
=================

Get-StorageAccounts
-------------------

.. _**Synopsis**-36:

**Synopsis**


Get a list of storage accounts and their blobs






.. _**Syntax**-36:

**Syntax**



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

Get-StorageAccountKeys
----------------------

.. _**Synopsis**-37:

**Synopsis**


Gets the account keys for a storage account






.. _**Syntax**-37:

**Syntax**



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

Get-StorageContents 
-------------------

.. _**Synopsis**-38:

**Synopsis**


Gets the contents of a storage container or file share.






.. _**Syntax**-38:

**Syntax**



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

Get-Runbooks
------------

.. _**Synopsis**-39:

**Synopsis**


Lists all the run books in all Automation accounts under the
subscription






.. _**Syntax**-39:

**Syntax**



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

Get-RunbookContent 
------------------

.. _**Synopsis**-40:

**Synopsis**


Gets a specific Runbook and displays its contents. Use -NoDelete to not
delete after reading






.. _**Syntax**-40:

**Syntax**



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

Get-AvailableVMDisks
--------------------

.. _**Synopsis**-41:

**Synopsis**


Lists the VM disks available.






.. _**Syntax**-41:

**Syntax**



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

Get-VMDisk
----------

.. _**Synopsis**-42:

**Synopsis**


Generates a link to download a Virtual Machiche's disk. The link is only
available for an hour.






.. _**Syntax**-42:

**Syntax**



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

   Get-VMDisk -DiskName AzureWin10_OsDisk_1_c2c7da5a0838404c84a70d6ec097ebf5 -ResourceGroup TestGroup

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

Get-VMs
-------

.. _**Synopsis**-43:

**Synopsis**


Lists all virtual machines available, their disks, and their IPs.






.. _**Syntax**-43:

**Syntax**



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

Get-SQLDBs
----------

.. _**Synopsis**-44:

**Synopsis**


Lists the available SQL Databases on a server






.. _**Syntax**-44:

**Syntax**



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