Information Gathering
=====================

<<<<<<< HEAD
Get-Targets
-----------

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

Get-CurrentUser
---------------


.. _**Synopsis**-1:

**Synopsis**


Returns the current logged in user name and any owned objects

.. _**Syntax**-1:

**Syntax**


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

Get-AllUsers
------------


.. _**Synopsis**-2:

**Synopsis**


List all Azure users in the tenant

.. _**Syntax**-2:

**Syntax**



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


**Get-User**


.. _**Synopsis**-4:

**Synopsis**


Gathers info on a specific user

.. _**Syntax**-4:

**Syntax**



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

Get-AllGroups
-------------

.. _**Synopsis**-5:

**Synopsis**


Gathers all the groups in the tenant

.. _**Syntax**-5:

**Syntax**



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

Get-Resources
-------------

.. _**Synopsis**-6:

**Synopsis**


Lists all resources

.. _**Syntax**-6:

**Syntax**



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

Get-Apps
--------

.. _**Synopsis**-7:

**Synopsis**


Returns all applications and their Ids

.. _**Syntax**-7:

**Syntax**

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


Get-AppOwners
--------

.. _**Synopsis**-7:

**Synopsis**


Returns all owners of all Applications in AAD

.. _**Syntax**-7:

**Syntax**

::

  Get-AppOwners

.. _**Description**-7:

**Description**

Recursively looks through each application in AAD and lists the owners

.. _**Examples**-7:

**Examples**

::

  Get-AppOwners

.. _**Parameters**-7:

**Parameters** 


None

.. _required-modules-6:

**Required Modules**


AzureAD PowerShell

.. _**Output**-7:

**Output**


Application owners in AAD





Get-GroupMembers
----------------

.. _**Synopsis**-8:

**Synopsis**


Gets all the members of a specific group. Group does NOT mean role.

.. _**Syntax**-8:

**Syntax**



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

Get-AllGroupMembers
-------------------

.. _**Synopsis**-9:

**Synopsis**


Gathers all the group members of all the groups.

.. _**Syntax**-9:

**Syntax**



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

Get-AllRoleMembers
------------------

.. _**Synopsis**-10:
=======
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

Get-AzureAppOwners
--------
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
Gets all the members of all roles. Roles does not mean groups.

.. _**Syntax**-10:

**Syntax**



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

Get-RoleMembers
---------------

.. _**Synopsis**-11:
=======
Returns all owners of all Applications in AAD

**Syntax**

::

  Get-AzureAppOwners

**Description**

Recursively looks through each application in AAD and lists the owners

**Examples**

::

  Get-AzureAppOwners

**Parameters** 

None

**Output**

Application owners in AAD

Get-AzureGroup
-------------
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
Gets the members of a role.

.. _**Syntax**-11:
=======
Gathers a specific group or all groups in AzureAD and lists their members. 
>>>>>>> Dev

**Syntax**

::

<<<<<<< HEAD
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

Get-Roles
---------


.. _**Synopsis**-12:

**Synopsis**


Lists the roles of a specific user.

.. _**Syntax**-12:

**Syntax**


::

  Get-Roles -User [UPN] 

.. _**Description**-12:
=======
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
>>>>>>> Dev

**Description**


<<<<<<< HEAD
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
=======
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
>>>>>>> Dev

**Output**


<<<<<<< HEAD
Roles of the specified user

Get-ServicePrincipals
---------------------

.. _**Synopsis**-13:
=======
Members of specified role, their Ids, and the scope.

Get-AzureRunAsAccounts
------------------
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
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
=======
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
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
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
=======
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
>>>>>>> Dev

**Description**


<<<<<<< HEAD
Gathers the names of the running web applications

.. _**Examples**-16:

**Examples**



::

  Get-WebApps

.. _**Parameters**-16:
=======
Looks at the current signed-in user’s roles, then looks at the role
definitions and scope of that role. Role definitions are then compared
to the scope of the role to determine which resources under that scope
the role definitions are actionable against.

**Examples**

::

  Get-AzureTargets
>>>>>>> Dev

**Parameters**


None

<<<<<<< HEAD
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



Get-AADRole
-----------

.. _**Synopsis**-19:
=======
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
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
Finds a specified AAD Role and its definitions







.. _**Syntax**-19:

**Syntax**

::

   Get-AADRole -Role [Role]

.. _**Description**-19:
=======
Returns the current logged in user name and any owned objects


**Syntax**


::

  Show-AzureCurrentUser
>>>>>>> Dev

**Description**


<<<<<<< HEAD
Finds a specified AAD Role and its definitions. Role must be properly capitalized. If role has a space in the name, use single quotes around the name.


.. _**Examples**-19:
=======
Looks at the current logged in username and compares that to the role
assignment list to determine what objects/resources the user has
ownership over.
>>>>>>> Dev

**Examples**

::

<<<<<<< HEAD
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

Get-AADRoleMembers
------------------

.. _**Synopsis**-20:
=======
  Show-AzureCurrentUser


**Parameters** 

None

**Output**


Current username and roles of the logged in User

Show-AzureKeyVaultContent
-------------
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
Lists the active roles in Azure AD and what users are part of the role.






.. _**Syntax**-20:
=======
Lists all available content in a key vault
>>>>>>> Dev

**Syntax**

::

<<<<<<< HEAD
  Get-AADRoleMembers

.. _**Description**-20:

**Description**


Lists the active roles in Azure AD and what users are part of the role.

.. _**Examples**-20:
=======
  Show-AzureKeyVaultContent -All
  
::

  Show-AzureKeyVaultContent -Name ]VaultName]

**Description**

Recursively goes through a key vault and lists what is within the vault (secret, certificate, and key names). Use Get-AzureKeyVaultContent to grab the values of a secret or certificate and Export-AzureKeyVaultcontent to get a key value.
>>>>>>> Dev

**Examples**

::

<<<<<<< HEAD
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


Get-RunAsAccounts
------------------

.. _**Synopsis**-20:
=======
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
>>>>>>> Dev

**Synopsis**


<<<<<<< HEAD
Finds any RunAs accounts being used by an Automation Account



.. _**Syntax**-20:

=======
Lists all available storage containers, shares, and tables


>>>>>>> Dev
**Syntax**

::

<<<<<<< HEAD
  Get-RunAsAccounts

.. _**Description**-20:

**Description**


Finds any RunAs accounts being used by an Automation Account by recursively going through each resource group and Automation Account. If one is discovered, you can extract it's certificate (if you have the correct permissions) by using Get-RunAsCertificate

.. _**Examples**-20:
=======
  Show-AzureStorageContent -All
  
::

  Show-AzureStorageContent -StorageAccountName [Name of Storage Account]

**Description**

Recursively goes through a storage account (or multiple) and lists the available containers + blobs, File Shares, and tables.
>>>>>>> Dev

**Examples**

::

<<<<<<< HEAD
  Get-RunAsAccounts

.. _**Parameters**-20:

**Parameters**


None

.. _required-modules-19:

**Required Modules**


Azure CLI
Azure PowerShell

.. _**Output**-20:

**Output**


List of Automation Accounts, the resource group name, and the connection type
=======
  Show-AzureStorageContent -StorageAccountName TestAcct

::

  Show-AzureStorageContent -All
  
**Parameters** 

-All


-StorageAccountName

**Output**

List of contents 
>>>>>>> Dev
