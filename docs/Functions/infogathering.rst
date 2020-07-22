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

<<<<<<< Updated upstream
=======

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

List of all users in AAD, optionally in a file.

Get-AzureGroup
-------------
>>>>>>> Stashed changes

.. _**Synopsis**-5:

**Synopsis**


Gathers a specific group or all groups in AzureAD and lists their members. 

.. _**Syntax**-5:

**Syntax**

::

  Get-AzureGroup -Group '[Name of Group]'
  
::

<<<<<<< Updated upstream
  Get-User -Username Test@domain.com 

::

  Get-User -All
=======
  Get-AzureGroup -All
>>>>>>> Stashed changes

.. _**Description**-5:

**Description**

Uses Graph API call to gather a group, the group's ID, the member's name, and the member's ID.

.. _**Examples**-5:

**Examples**

::

<<<<<<< Updated upstream
  Get-User -Username Test@domain.com
  
::

  Get-User -All
=======
  Get-AzureGroup -Group 'Sql Admins'
>>>>>>> Stashed changes

::

  Get-AzureGroup -All 

.. _**Parameters**-5:

**Parameters** 

<<<<<<< Updated upstream
-Username
=======
-All
Switch; Gathers all group's members
>>>>>>> Stashed changes

-Group
Name of group to collect

<<<<<<< Updated upstream
-All
Gets all users


.. _**Output**-4:
=======
.. _**Output**-5:
>>>>>>> Stashed changes

**Output**

Group members and their IDs

<<<<<<< Updated upstream
User's UPN, Object ID, On-premise distinguished name, and if the
account is enabled. Also lists the roles the user has in Azure RBAC.



Get-Groups
-------------
=======

Get-AzureAppOwners
--------
>>>>>>> Stashed changes

.. _**Synopsis**-7:

**Synopsis**


Returns all owners of all Applications in AAD

.. _**Syntax**-7:

**Syntax**

::

<<<<<<< Updated upstream
  Get-Groups
=======
  Get-AppOwners
>>>>>>> Stashed changes

.. _**Description**-7:

**Description**

Recursively looks through each application in AAD and lists the owners

.. _**Examples**-7:

**Examples**

<<<<<<< Updated upstream


::

  Get-Groups


=======
::

  Get-AzureAppOwners
>>>>>>> Stashed changes

.. _**Parameters**-7:

**Parameters** 


None
<<<<<<< Updated upstream
=======

>>>>>>> Stashed changes

.. _**Output**-7:

**Output**


<<<<<<< Updated upstream
List of group names, IDs, onprem Domain name, onprem Account name, and onprem SID.
=======
Application owners in AAD
>>>>>>> Stashed changes


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

<<<<<<< Updated upstream
Application owners in AAD



Get-GroupMembers
----------------
=======
Show-AzureStorageContent
-------------
>>>>>>> Stashed changes

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
Switch; Gathers all group's members

-Group
Name of group to collect

<<<<<<< Updated upstream
Group name

-OutFile

Output file

.. _required-modules-7:

**Required Modules**


Azure CLI

.. _**Output**-8:
=======
.. _**Output**-5:
>>>>>>> Stashed changes

**Output**

Group members and their IDs

Show-AzureKeyVaultContent
-------------

.. _**Synopsis**-5:

**Synopsis**


Lists all available content in a key vault


.. _**Syntax**-5:

**Syntax**

::

  Show-AzureStorageContent -All
  
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

-All
Switch; Gathers all group's members

<<<<<<< Updated upstream
-OutFile

Output filename/type

.. _required-modules-8:

**Required Modules**


Azure CLI
=======
-VaultName
Name of vault
>>>>>>> Stashed changes

.. _**Output**-5:

**Output**

Name of vault contents

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

-All
Switch; Gathers all group's members

<<<<<<< Updated upstream
  Get-AllRoleMembers -OutFile users.csv
=======
-Server
Name of the SQL Server

.. _**Output**-5:
>>>>>>> Stashed changes

**Output**

<<<<<<< Updated upstream
  Get-AllRoleMembers -OutFile users.txt
  
=======
Name of vault contents
>>>>>>> Stashed changes

Get-AzureRolePermission
-------------

.. _**Synopsis**-5:

**Synopsis**

Finds all roles with a certain permission

<<<<<<< Updated upstream
Output filename/type
=======
.. _**Syntax**-5:
>>>>>>> Stashed changes

**Syntax**

::

  Get-AzureRolePermission -Permission [role definition]
  
.. _**Description**-5:

**Description**

Finds all builtin roles with a certain permission

<<<<<<< Updated upstream
**Output**


All members of all roles

Get-RoleMembers
---------------

.. _**Synopsis**-11:

**Synopsis**


Gets the members of a role.

.. _**Syntax**-11:

**Syntax**

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


Get-ServicePrincipals
---------------------

.. _**Synopsis**-13:

**Synopsis**


Returns all service principals

.. _**Syntax**-13:

**Syntax**



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

Get-ServicePrincipal
--------------------


.. _**Synopsis**-14:

**Synopsis**


Returns all info on a service principal

.. _**Syntax**-14:

**Syntax**



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

Get-App
------------------


.. _**Synopsis**-15:

**Synopsis**


Returns the  of an app

.. _**Syntax**-15:

**Syntax**



::

   Get-App -Id [App ID]

.. _**Description**-15:

**Description**


Gathers the  an application has.

.. _**Examples**-15:

**Examples**



::

  Get-App -Id fdb54b57-a416-4115-8b21-81c73d2c2deb

.. _**Parameters**-15:

**Parameters**


-Id

ID of the Application

.. _required-modules-14:

**Required Modules**


Azure CLI

.. _**Output**-15:

**Output**


Application’s 

Get-WebApps
-----------

.. _**Synopsis**-16:

**Synopsis**


Gets running webapps

.. _**Syntax**-16:

**Syntax**



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

Get-WebAppDetails
-----------------

.. _**Synopsis**-17:

**Synopsis**


Gets running webapps details




.. _**Syntax**-17:

**Syntax**



::

  Get-WebAppDetails -Name [WebAppName]

.. _**Description**-17:

**Description**


Gets the details of a web application

.. _**Examples**-17:
=======
.. _**Examples**-5:
>>>>>>> Stashed changes

**Examples**

::

  Get-AzureRolePermission -Permission 'virtualMachines/*'

.. _**Parameters**-5:

**Parameters** 

-Permission
The permission to search for

<<<<<<< Updated upstream
-name

Name of web application

.. _required-modules-16:

**Required Modules**


Azure CLI

.. _**Output**-17:

**Output**


Details of web application



Get-AADRole
-----------

.. _**Synopsis**-19:

**Synopsis**


Finds a specified AAD Role and its definitions







.. _**Syntax**-19:

**Syntax**

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


.. _**Output**-19:

**Output**


Active roles

Get-AADRoles
------------------

.. _**Synopsis**-20:

**Synopsis**


Lists the active roles in Azure AD and what users are part of the role.



.. _**Syntax**-20:

**Syntax**

::

  Get-AADRoleMembers

.. _**Description**-20:

**Description**


Uses the Graph API to get a list of the roles, then checks for a member in each of those roles.

.. _**Examples**-20:

**Examples**

::

  Get-AADRoles 
  
::

  Get-AADRoles -All

.. _**Parameters**-20:

**Parameters**

-All 

Lists all roles, even those without a user in them


.. _required-modules-19:

**Required Modules**


Azure CLI

.. _**Output**-20:

**Output**


AAD Role name, AAD Role Id, and the users with that role

Get-RunAsAccounts
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


Finds any RunAs accounts being used by an Automation Account by recursively going through each resource group and Automation Account. If one is discovered, you can extract it's certificate (if you have the correct permissions) by using Get-RunAsCertificate

.. _**Examples**-20:

**Examples**

::

  Get-RunAsAccounts

.. _**Parameters**-20:

**Parameters**


None

.. _required-modules-19:

**Required Modules**


Azure CLI
Azure PowerShell

.. _**Output**-20:
=======
.. _**Output**-5:
>>>>>>> Stashed changes

**Output**

Any roles containing that permission/definition
