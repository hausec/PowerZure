Information Gathering
=====================

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

Show-AzureCurrentUser
---------------


.. _**Synopsis**-1:

**Synopsis**


Returns the current logged in user name and any owned objects

.. _**Syntax**-1:

**Syntax**


::

  Show-AzureCurrentUser

.. _**Description**-1:

**Description**


Looks at the current logged in username and compares that to the role
assignment list to determine what objects/resources the user has
ownership over.

.. _**Examples**-1:

**Examples**

::

  Show-AzureCurrentUser


.. _**Parameters**-1:

**Parameters** 

None

.. _**Output**-1:

**Output**


Current username and roles of the logged in User


Get-AzureUser
------------

.. _**Synopsis**-2:

**Synopsis**

Gathers info on a specific user or all users including their groups and roles in Azure & AzureAD

.. _**Syntax**-2:

**Syntax**

::

  Get-AzureUser -Username [Usename]
  
::

  Get-AzureUser -All

.. _**Description**-2:

**Description**

Gathers a user's Azure role by calling Get-AzRoleAssignment, then uses Graph API calls to gather their Azure AD roles. Uses Graph API call to gather assigned groups.

.. _**Examples**-2:

**Examples**

::

  Get-AzureUser -Username john@contoso.com

::

  Get-AzureUser -All

.. _**Parameters**-2:

**Parameters** 

-All

Switch; Gathers all users in AzureAD.

-Username 

Full user principal name of the target user in format: name@domain.com

.. _**Output**-2:

**Output**

User ID, their AAD roles, their RBAC roles, and the scope of those roles

Get-AzureGroup
-------------


.. _**Synopsis**-5:

**Synopsis**


Gathers a specific group or all groups in AzureAD and lists their members. 

.. _**Syntax**-5:

**Syntax**

::

  Get-AzureGroup -Group '[Name of Group]'
  
::

  Get-AzureGroup -All


.. _**Description**-5:

**Description**

Uses Graph API call to gather a group, the group's ID, the member's name, and the member's ID.

.. _**Examples**-5:

**Examples**
  
::

  Get-AzureGroup -Group 'Sql Admins'


::

  Get-AzureGroup -All 

.. _**Parameters**-5:

**Parameters** 


-Username

-All
Switch; Gathers all group's members


-Group
Name of group to collect


**Output**

Group members and their IDs


Get-AzureAppOwners
--------


.. _**Synopsis**-7:

**Synopsis**


Returns all owners of all Applications in AAD

.. _**Syntax**-7:

**Syntax**

::

  Get-AzureAppOwners


.. _**Description**-7:

**Description**

Recursively looks through each application in AAD and lists the owners

.. _**Examples**-7:

**Examples**


::

  Get-AzureAppOwners


.. _**Parameters**-7:

**Parameters** 


None

.. _**Output**-7:

**Output**

Application owners in AAD


Get-AzureADRoleMember
------------------

.. _**Synopsis**-10:

**Synopsis**


Gets the members of one or all Azure AD role. Roles does not mean groups.

.. _**Syntax**-10:

**Syntax**

::

  Get-AzureADRoleMember -All
  
::

  Get-AzureADRoleMember -Role '[RoleName]'
  
::

  Get-AzureADRoleMember -Role '[RoleId]'

.. _**Description**-10:

**Description**

Uses a Graph API call to list the role, roleid, members name, and if there's any application service principal members. Application Service Principals will show up as '$null', as it's a bug within the Graph API output. This property can be expanded to reveal the actual name, e.g. $a = GetAzureAdRoleMember; $a.Applicationmembers

Due to mismatch in documentation, role names my not be 100% accurate to what the API's backend has, e.g. Company Administrator is what the API uses, but it's displayed as Global Administrator. Because of this, using a Role ID is more accurate.

.. _**Examples**-10:

**Examples**

::

  Get-AzureADRoleMember -All

::

  Get-AzureADRoleMember -Role '4dda258a-4568-4579-abeb-07709e34e307'

::

  Get-AzureADRoleMember -Role 'Company Administrator'

.. _**Parameters**-10:

**Parameters** 


-All
List all role's members

-Role 
The role ID or role name of the target role

.. _**Output**-10:

**Output**


All members of all roles, their IDs, and any Application Service Principal members.

Get-AzureRole
---------------

.. _**Synopsis**-11:

**Synopsis**


Gets the members of a role.

.. _**Syntax**-11:

**Syntax**

::

  Get-AzureRole -Role [Role name]

::

  Get-AzureRole -All

.. _**Description**-11:

**Description**


Gets the members of a role or all roles. -All will only return roles that have users assigned.

.. _**Examples**-11:

**Examples**

::

  Get-AzureRole -Role Reader
  
::

  Get-AzureRole -All

.. _**Parameters**-11:

**Parameters**

-Role
Name of role. 

-All
Get all roles

.. _**Output**-11:

**Output**


Members of specified role, their Ids, and the scope.


Get-AzureRunAsAccounts
------------------

.. _**Synopsis**-20:

**Synopsis**


Finds any RunAs accounts being used by an Automation Account



.. _**Syntax**-20:

**Syntax**

::

  Get-RunAsAccounts

.. _**Description**-20:

**Description**


Finds any RunAs accounts being used by an Automation Account by recursively going through each resource group and Automation Account. If one is discovered, you can extract it's certificate (if you have the correct permissions) by using Get-AzureRunAsCertificate

.. _**Examples**-20:

**Examples**

::

  Get-RunAsAccounts

.. _**Parameters**-20:

**Parameters**


None

.. _**Output**-20:

**Output**

List of Automation Accounts, the resource group name, and the connection type

Show-AzureStorageContent
-------------


.. _**Synopsis**-5:

**Synopsis**


Lists all available storage containers, shares, and tables


.. _**Syntax**-5:

**Syntax**

::

  Show-AzureStorageContent -All
  
::

  Show-AzureStorageContent -StorageAccountName [Name of Storage Account]

.. _**Description**-5:

**Description**

Recursively goes through a storage account (or multiple) and lists the available containers + blobs, File Shares, and tables.

.. _**Examples**-5:

**Examples**

::

  Show-AzureStorageContent -StorageAccountName TestAcct

::

  Show-AzureStorageContent -All

.. _**Parameters**-5:

**Parameters** 

-All
-StorageAccountName

**Output**

List of contents 


Show-AzureKeyVaultContent
-------------

.. _**Synopsis**-5:

**Synopsis**


Lists all available content in a key vault


.. _**Syntax**-5:

**Syntax**

::

  Show-AzureKeyVaultContent -All
  
::

  Show-AzureKeyVaultContent -Name ]VaultName]

.. _**Description**-5:

**Description**

Recursively goes through a key vault and lists what is within the vault (secret, certificate, and key names). Use Get-AzureKeyVaultContent to grab the values of a secret or certificate and Export-AzureKeyVaultcontent to get a key value.

.. _**Examples**-5:

**Examples**

::

  Show-AzureKeyVaultContent -Name Vaulttest

::

  Show-AzureKeyVaultContent -All

.. _**Parameters**-5:

**Parameters** 


-VaultName
Name of vault

-All

.. _**Output**-5:

**Output**

vault contents

Get-AzureSQLDB
-------------

.. _**Synopsis**-5:

**Synopsis**


Lists the available SQL Databases on a server


.. _**Syntax**-5:

**Syntax**

::

  Get-AzureSQLDB -All
  
::

  Get-AzureSQLDB -Server [Name of server]

.. _**Description**-5:

**Description**

Lists the available SQL DBs, the server they're on, and what the Administrator username is

.. _**Examples**-5:

**Examples**

::

  Get-AzureSQLDB -All

::

  Get-AzureSQLDB -Server 'SQLServer01'

.. _**Parameters**-5:

**Parameters** 

-Server
Name of the SQL Server

.. _**Output**-5:

**Output**

Get-AzureRolePermission
-------------

.. _**Synopsis**-5:

**Synopsis**

Finds all roles with a certain permission


.. _**Syntax**-5:


**Syntax**

::

  Get-AzureRolePermission -Permission [role definition]
  
.. _**Description**-5:

**Description**

Finds all builtin roles with a certain permission


**Output**


All members of all roles

