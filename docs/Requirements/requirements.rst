Requirements
============

Azure has many different PowerShell modules, each using a different API.
Some have been deprecated and some do not have nearly as much
functionality as the others, despite all being Microsoft-made. PowerZure
uses three Azure modules, each with a different purpose.

1. `Azure
   CLI <https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest>`__
   (`az`)

The Azure CLI is the primary module used in PowerZure as throughout my
testing and building this project, it became clear the Azure CLI module
had the most functionality and decent support on Github. Azure CLI is
the successor to the AzureRM module and uses the Azure REST API.

2. `Azure
   PowerShell <https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0>`__

The Azure PS module is used to fill in gaps where Azure CLI
functionality lacks. Specifically, Azure CLI has no cmdlets for
interacting with Automation Accounts or Runbooks, hence the need for
Azure PS. Azure PS uses the Graph API.

3. `AzureAD <https://docs.microsoft.com/en-us/powershell/module/Azuread/?view=azureadps-2.0>`__

The AzureAD module is used for the more mature cmdlets around
interacting with (you guessed it) Azure Active Directory. While both
Azure CLI and Azure PS have cmdlets for doing basic things, like listing
users and groups, when it came to more advanced things such as adding an
AAD role to a user, the AzureAD module is needed. AzureAD uses the Graph
API.

These three modules are needed to **fully** use PowerZure. If you do not
need to interact with AAD or Automation Accounts, then Azure CLI is the
only module needed. With this being said, PowerZure should also be run
from an elevated PowerShell window.