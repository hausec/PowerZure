Information Gathering
=====================

Get-AzureADRole
------------------

**Synopsis**

Gets the members of one or all Azure AD role. Roles does not mean groups.

**Syntax**

::

  Get-AzureADRole -All
  
::

  Get-AzureADRole -Role '[RoleName]'
  
::

  Get-AzureADRole -Role '[RoleId]'

**Description**

Uses a Graph API call to list the role, roleid, members name, and if there's any application service principal members. Application Service Principals will show up as '$null', as it's a bug within the Graph API output. This property can be expanded to reveal the actual name, e.g. 
::
  
  $a = Get-AzureAdRoleMember; $a.Applicationmembers

Due to mismatch in documentation, role names my not be 100% accurate to what the API's backend has, e.g. Company Administrator is what the API uses, but it's displayed as Global Administrator. Because of this, using a Role ID is more accurate.

**Examples**

::

  Get-AzureADRole -All

::

  Get-AzureADRole -Role '4dda258a-4568-4579-abeb-07709e34e307'

::

  Get-AzureADRole -Role 'Company Administrator'

**Parameters** 

-All


List all role's members


-Role 


The role ID or role name of the target role

**Output**

All members of all roles, their IDs, and any Application Service Principal members.

Get-AzureAppOwner
--------

**Synopsis**


Returns all owners of all Applications in AAD

**Syntax**

::

  Get-AzureAppOwner

**Description**

Recursively looks through each application in AAD and lists the owners

**Examples**

::

  Get-AzureAppOwner

**Parameters** 

None

**Output**

Application owners in AAD


Get-AzureDeviceOwner
--------

**Synopsis**


Lists the owners of devices in AAD. This will only show devices that have an owner.

**Syntax**

::

  Get-AzureDeviceOwner

**Description**

Lists the owners of devices in AAD. This will only show devices that have an owner.

**Examples**

::

  Get-AzureDeviceOwner

**Parameters** 

None

**Output**

Device owners from AAD


Get-AzureGroup
-------------

**Synopsis**


Gathers a specific group or all groups in AzureAD and lists their members. 

**Syntax**

::

  Get-AzureGroup -Group '[Name of Group]'
  
::

  Get-AzureGroup -All

**Description**

Uses Graph API call to gather a group, the group's ID, the member's name, and the member's ID.

**Examples**
  
::

  Get-AzureGroup -Group 'Sql Admins'


::

  Get-AzureGroup -All 

**Parameters** 

-All

Switch; Gathers all group's members


-Group

Name of group to collect


**Output**

Group members and their IDs

Get-AzureRole
---------------
**Synopsis**

Gets the members of a role.

**Syntax**

::

  Get-AzureRole -Role [Role name]

::

  Get-AzureRole -All

.. _**Description**-11:

**Description**


Gets the members of a role or all roles. -All will only return roles that have users assigned.

**Examples**

::

  Get-AzureRole -Role Reader
  
::

  Get-AzureRole -All

**Parameters**

-Role


Name of role


-All


Get all roles

**Output**


Members of specified role, their Ids, and the scope.

Get-AzureRunAsAccounts
------------------

**Synopsis**


Finds any RunAs accounts being used by an Automation Account

**Syntax**

::

  Get-AzureRunAsAccounts

**Description**

Finds any RunAs accounts being used by an Automation Account by recursively going through each resource group and Automation Account. If one is discovered, you can extract it's certificate (if you have the correct permissions) by using Get-AzureRunAsCertificate

**Examples**

::

  Get-AzureRunAsAccounts

**Parameters**

None

**Output**

List of RunAsAccounts and their details

Get-AzureRolePermission
-------------

**Synopsis**

Finds all roles with a certain permission

**Syntax**

::

  Get-AzureRolePermission -Permission [role definition]
  
**Description**

Finds all builtin roles with a certain permission

**Output**

Role(s) with the supplied definition present

Get-AzureSQLDB
-------------

**Synopsis**


Lists the available SQL Databases on a server

**Syntax**

::

  Get-AzureSQLDB -All
  
::

  Get-AzureSQLDB -Server [Name of server]

**Description**

Lists the available SQL DBs, the server they're on, and what the Administrator username is

**Examples**

::

  Get-AzureSQLDB -All

::

  Get-AzureSQLDB -Server 'SQLServer01'

**Parameters** 

-Server


Name of the SQL Server

**Output**

Get-AzureTargets
-----------

**Synopsis**


Compares your role to your scope to determine what you have access to
and what kind of access it is (Read/write/execute).

**Syntax**

::

  Get-AzureTargets

**Description**


Looks at the current signed-in user’s roles, then looks at the role
definitions and scope of that role. Role definitions are then compared
to the scope of the role to determine which resources under that scope
the role definitions are actionable against.

**Examples**

::

  Get-AzureTargets

**Parameters**


None

**Output**


List of resources with what type of access the current user has access
to.

Get-AzureUser
------------


**Synopsis**

Gathers info on a specific user or all users including their groups and roles in Azure & AzureAD

**Syntax**

::

  Get-AzureUser -Username [Usename]
  
::

  Get-AzureUser -All

**Description**

Gathers a user's Azure role by calling Get-AzRoleAssignment, then uses Graph API calls to gather their Azure AD roles. Uses Graph API call to gather assigned groups.

**Examples**

::

  Get-AzureUser -Username john@contoso.com

::

  Get-AzureUser -All

**Parameters** 

-All

Switch; Gathers all users in AzureAD.

-Username 

Full user principal name of the target user in format: name@domain.com

**Output**

User ID, their AAD roles, their RBAC roles, and the scope of those roles

Show-AzureCurrentUser
---------------

**Synopsis**


Returns the current logged in user name and any owned objects


**Syntax**


::

  Show-AzureCurrentUser

**Description**


Looks at the current logged in username and compares that to the role
assignment list to determine what objects/resources the user has
ownership over.

**Examples**

::

  Show-AzureCurrentUser


**Parameters** 

None

**Output**


Current username and roles of the logged in User

Show-AzureKeyVaultContent
-------------

**Synopsis**


Lists all available content in a key vault

**Syntax**

::

  Show-AzureKeyVaultContent -All
  
::

  Show-AzureKeyVaultContent -Name ]VaultName]

**Description**

Recursively goes through a key vault and lists what is within the vault (secret, certificate, and key names). Use Get-AzureKeyVaultContent to grab the values of a secret or certificate and Export-AzureKeyVaultcontent to get a key value.

**Examples**

::

  Show-AzureKeyVaultContent -Name Vaulttest

::

  Show-AzureKeyVaultContent -All

**Parameters** 


-VaultName


Name of vault


-All

**Output**

Vault contents

Show-AzureStorageContent
-------------

**Synopsis**


Lists all available storage containers, shares, and tables


**Syntax**

::

  Show-AzureStorageContent -All
  
::

  Show-AzureStorageContent -StorageAccountName [Name of Storage Account]

**Description**

Recursively goes through a storage account (or multiple) and lists the available containers + blobs, File Shares, and tables.

**Examples**

::

  Show-AzureStorageContent -StorageAccountName TestAcct

::

  Show-AzureStorageContent -All
  
**Parameters** 

-All


-StorageAccountName

**Output**

List of contents 