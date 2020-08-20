Operational Usage
=================

PowerZure comes in .ps1 format which requires it to be imported for each
new PowerShell session. To import, simply use 
::
	Import-Module C:\Location\to\Powerzure.ps1

There is zero reason to ever run PowerZure on a victim’s machine.
Authentication is done by using an existing accesstoken.json file or by
<<<<<<< HEAD
logging in via prompt when logging into Azure CLI, meaning you can
=======
logging in via prompt when logging into Azure, meaning you can
>>>>>>> Dev
safely use PowerZure to interact with a victim’s cloud instance from
your operating machine.

If the target environment is contraining Azure access to their network/VPN, then consider using a proxy.

You must sign-in to Azure before PowerZure functions are made available. To sign in, use the cmdlet 

::

<<<<<<< HEAD
   az login
   
If you are using functions that use the AzureAD module, you must additionally sign in with

::

   Connect-AzureAD
   
If you are using functions that use the Azure PowerShell module, you must additionally sign in with

::

   Connect-AzAccount
   
Check out the functions pages on the left to see which functions use which modules. Majority of PowerZure uses the az (Azure CLI) module.
=======
   Connect-AzAccount
   
>>>>>>> Dev

Once you are signed in to Azure, you can import PowerZure:


::

   ipmo C:\Path\To\Powerzure.ps1
   
   
Upon importing, it will list your current role and available subscriptions. If you're in a tenant with multiple subscriptions, you must set a default subscription with

::
   
<<<<<<< HEAD
   Set-Subscription -Id [Subscription ID]
=======
   Set-AzureSubscription -Id [Subscription ID]
>>>>>>> Dev

Once set, you can run

::

<<<<<<< HEAD
   Get-Targets

   
To get a list of resources you have access to and exploit them accordingly. 
=======
   Get-AzureTargets

   
To get a list of resources you have access to and exploit them accordingly.
>>>>>>> Dev
