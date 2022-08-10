Requirements
============
The `Azure PowerShell Az <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__  module is the successor to the AzureRM module and is the primary module used in PowerZure, as it is handles the requests interacting with Azure resources.. The Az module interacts using the Azure REST API.

PowerZure requires an Administrative PowerShell (at least 5.0) session and the `Az PowerShell <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__  module.


****

The first function you should run is 'Set-AzureSubscription' as this will set the default subscription Azure functions will operate under. You may supply a subscription id via the '-id' option or running 'Set-AzureSubscription' without any options will bring an interactive menu to choose from.


Set-AzureSubscription
----------------


**Synopsis**

Sets default subscription. This command must be run for Azure functions to properly work. 


**Syntax**

::

  Set-AzureSubscription

**Description**

Sets the default subscription via an interactive menu or via subscription Id.


**Examples**

::

  Set-AzureSubscription -Id b049c906-7000-4899-b644-f3eb835f04d0


**Parameters** 

-Id

Subscription ID (optional)

**Output**

Success message
