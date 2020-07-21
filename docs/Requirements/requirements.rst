Requirements
============

Azure has many different PowerShell modules, interacting with either Azure's REST or Graph API. 
Some have been deprecated and some do not have nearly as much functionality as the others, despite all being Microsoft-made. PowerZure uses two Azure modules, each with a different purpose. If you do not have these modules installed, PowerZure will automatically give you the option to install them when importing PowerZure.

1. `Azure
   CLI <https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest>`__

The Azure CLI is the primary module used in PowerZure as throughout my
testing and building this project, it became clear the Azure CLI module
had the most functionality and decent support on Github. Azure CLI uses the Azure REST API.

2. `Azure
   PowerShell Az <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__

The Azure PS "Az" module is used to fill in gaps where Azure CLI
functionality lacks. Specifically, Azure CLI has no cmdlets for
interacting with Automation Accounts or Runbooks, hence the need for
Az PowerShell. Az PowerShell is the successor to the AzureRM module uses the Graph API.



****

If you are in a tenant with multiple subscriptions, you must set your default subscription with


Set-Subscription
----------------

.. _**Synopsis**-45:

**Synopsis**


Sets default subscription. Necessary if in a tenant with multiple
subscriptions.




.. _**Syntax**-45:

**Syntax**



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
