Information Gathering
=====================

Get-AzureADAppOwner
--------

**Synopsis**


Returns all owners of all Applications in AAD

**Syntax**

::

  Get-AzureADAppOwner

**Description**

Recursively looks through each application in AAD and lists the owners

**Examples**

::

  Get-AzureADAppOwner

**Parameters** 

None

**Output**

Application owners in AAD

Get-AzureADDeviceOwner
--------

**Synopsis**


Lists the owners of devices in AAD. This will only show devices that have an owner.

**Syntax**

::

  Get-AzureADDeviceOwner

**Description**

Lists the owners of devices in AAD. This will only show devices that have an owner.

**Examples**

::

  Get-AzureADDeviceOwner

**Parameters** 

None

**Output**

Device owners from AAD


Get-AzureADGroupMember
-------------

**Synopsis**


Gets all the members of a specific group

**Syntax**

::

  Get-AzureADGroupMember -Group '[Name of Group]'
  

**Description**

Uses Graph API call to gather a group, the group's ID, the member's name, and the member's ID.

**Examples**
  
::

  Get-AzureADGroupMember -Group 'Sql Admins'

**Parameters** 

-Group

Name of group to collect

**Output**

Group members and their IDs

Get-AzureADRoleMember
------------------

**Synopsis**

Lists the members of a given role in AAD

**Syntax**

::

  Get-AzureADRoleMember -All
  
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

  Get-AzureADRoleMember -Role 'Global Administrator'

**Parameters** 

-Role 


The role name of the target role

**Output**

All members of all roles, their IDs, and any Application Service Principal members.

Get-AzureADUser
------------


**Synopsis**

Gathers info on a specific user or all users including their groups and roles in Azure & AzureAD

**Syntax**

::

  Get-AzureADUser -Username [Usename]
  
::

  Get-AzureADUser -All

**Description**

Gathers a user's Azure role by calling Get-AzRoleAssignment, then uses Graph API calls to gather their Azure AD roles. Uses Graph API call to gather assigned groups.

**Examples**

::

  Get-AzureADUser -Username john@contoso.com

::

  Get-AzureADUser -All

**Parameters** 

-All

Switch; Gathers all users in AzureAD.

-Username 

Full user principal name of the target user in format: name@domain.com

**Output**

User ID, their AAD roles, their RBAC roles, and the scope of those roles

Get-AzureCurrentUser
---------------

**Synopsis**


Returns the current logged in user name and any owned objects


**Syntax**


::

  Get-AzureCurrentUser

**Description**


Looks at the current logged in username and compares that to the role
assignment list to determine what objects/resources the user has
ownership over.

**Examples**

::

  Get-AzureCurrentUser


**Parameters** 

None

**Output**


Current username and roles of the logged in User


Get-AzureIntuneScript
-------------

**Synopsis**


Lists available Intune scripts in Azure Intune

**Syntax**

::

  Get-AzureInTuneScript
  

**Description**

Uses a Graph API call to get any Intune scripts. This requires credentials in order to request a delegated token on behalf of the 'Office' Application in AAD, which has the correct permissions to access Intune data, where 'Azure PowerShell' Application does not.
	
**Examples**
  
::

  Get-AzureInTuneScript

**Parameters** 

None

**Output**

List of scripts available in Intune

Get-AzureLogicAppConnector
-------------

**Synopsis**


Lists the connector APIs in Azure

**Syntax**

::

  Get-AzureLogicAppConnector
  

**Description**

Lists the connector APIs in AzureLists the connector APIs in Azure which may be connected to another resource, subscription, tenant, or service.
	
**Examples**
  
::

  Get-AzureLogicAppConnector

**Parameters** 

None

**Output**

List of connections established in a Logic App. 

Get-AzureManagedIdentity
---------------

**Synopsis**


Gets a list of all Managed Identities and their roles.
**Syntax**

::

Get-AzureManagedIdentity
  

**Description**

Gathers any resources that are using a system assigned managed identity in Azure.
	
**Examples**
  
::

  Get-AzureManagedIdentity

**Parameters** 

None

**Output**

List of system assigned managed identities.

Get-AzurePIMAssignment
---------------

**Synopsis**


Gathers the Privileged Identity Management assignments.

**Syntax**

::

Get-AzurePIMAssignment
  

**Description**

Gathers the Privileged Identity Management assignments in Azure resources. 

**Examples**
  
::

  Get-AzurePIMAssignment

**Parameters** 

None

**Output**

List of PIM assignments for Azure resources.

Get-AzureRole
---------------
**Synopsis**

Gets the members of a role.

**Syntax**

::

  Get-AzureRole -Role [Role name]

::

  Get-AzureRole -All

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

Get-AzureRunAsAccount
------------------

**Synopsis**


Finds any RunAs accounts being used by an Automation Account

**Syntax**

::

  Get-AzureRunAsAccount

**Description**

Finds any RunAs accounts being used by an Automation Account by recursively going through each resource group and Automation Account. If one is discovered, you can extract it's certificate (if you have the correct permissions) by using Get-AzureRunAsCertificate

**Examples**

::

  Get-AzureRunAsAccount

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

Get-AzureTarget
-----------

**Synopsis**


Compares your role to your scope to determine what you have access to
and what kind of access it is (Read/write/execute).

**Syntax**

::

  Get-AzureTarget

**Description**


Looks at the current signed-in user’s roles, then looks at the role
definitions and scope of that role. Role definitions are then compared
to the scope of the role to determine which resources under that scope
the role definitions are actionable against.

**Examples**

::

  Get-AzureTarget

**Parameters**


None

**Output**


List of resources with what type of access the current user has access
to.

Get-AzureTenantId
-----------

**Synopsis**


Returns the ID of a tenant belonging to a domain

**Syntax**

::

  Get-AzureTenantId

**Description**


By looking at the the openid-configuration of a domain, the tenant ID can be retrieved. 

**Examples**

::

  Get-AzureTenantId -Domain 'testdomain.onmicrosoft.com'

**Parameters**


-Domain

Name of the domain

**Output**


The target domain's tenant ID.


Show-AzureKeyVaultContent
-------------

**Synopsis**


Lists all available content in a key vault

**Syntax**

::

  Show-AzureKeyVaultContent -All
  
::

  Show-AzureKeyVaultContent -Name [VaultName]

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