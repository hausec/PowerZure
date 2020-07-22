Requirements
============
The `Azure PowerShell Az <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__  module is the only module used in PowerZure, as it is the most current module for Azure. The Az module interacts using the Azure REST API.



Az PowerShell is the successor to the AzureRM module uses the Graph API.


PowerZure requires an Administrative PowerShell (at least 5.0) session and the `Az PowerShell <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__  module.

The Azure "Az" PowerShell module is the only module used in PowerZure, as it is the most current module for Azure. The Az module interacts using the Azure REST API.


****

If you are in a tenant with multiple subscriptions, you must set your default subscription with


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
