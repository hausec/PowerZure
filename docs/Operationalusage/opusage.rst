Operational Usage
=================

PowerZure comes in .ps1 format which requires it to be imported for each
new PowerShell session. To import, simply use 
::
	Import-Module C:\Location\to\Powerzure.ps1

There is zero reason to ever run PowerZure on a victim’s machine.
Authentication is done by using an existing accesstoken.json file or by
logging in via prompt when logging into Azure CLI, meaning you can
safely use PowerZure to interact with a victim’s cloud instance from
your operating machine.