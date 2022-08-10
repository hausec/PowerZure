Operational Usage
=================

PowerZure is a PowerShell module. To begin using PowerZure, import the manifest file:
::
	Import-Module C:\Location\to\Powerzure.psd1

There is zero reason to ever run PowerZure on a victim’s machine.
Authentication is done by using an existing accesstoken.json file or by
logging in via prompt when logging into Azure, meaning you can
safely use PowerZure to interact with a victim’s cloud instance from
your operating machine.

If the target environment is contraining Azure access to their network/VPN, then consider using a proxy.

You must sign-in to Azure before PowerZure functions are made available. To sign in, use the cmdlet 

::

   Connect-AzAccount
   

Once you are signed in to Azure, you can import PowerZure:


::

   ipmo C:\Path\To\Powerzure.psd1
   
   
Upon importing, it will list your current role and available subscriptions. If you're in a tenant with multiple subscriptions, you must set a default subscription with

::
   
   Set-AzureSubscription

Once set, you can run

::

   Get-AzureTarget

   
To get a list of AzureAD and Azure objects you have access to and exploit them accordingly.