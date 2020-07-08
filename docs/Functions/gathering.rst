Secret/Key/Certificate Gathering
================================

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