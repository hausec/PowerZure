![powerzure](https://i.imgur.com/d5B0U0B.png)

### For a list of functions, their usage, and more, check out https://powerzure.readthedocs.io


<<<<<<< HEAD
=======

>>>>>>> Dev
## What is PowerZure?

PowerZure is a PowerShell project created to assess and exploit resources within
Microsoft’s cloud platform, Azure. PowerZure was created out of the need for a
framework that can both perform reconnaissance **and** exploitation of Azure, AzureAD, and the associated resources.

## CLI vs. Portal

A common question is why use PowerZure or command line at all when you can just
login to the Azure web portal?

This is a fair question and to be honest, you can accomplish 90% of the
functionality in PowerZure through clicking around in the portal, however by
using the Azure PowerShell modules, you can perform tasks programmatically that
are tedious in the portal. E.g, listing the groups a user belongs to. In
addition, the ability to programmatically upload exploits instead of tinkering
around with the messy web UI. Finally, if you compromise a user who has used the
PowerShell module for Azure before and are able to steal the accesstoken.json
file, you can impersonate that user which effectively bypasses multi-factor
authentication.

## Why PowerShell?

While the offensive security industry has seen a decline in PowerShell usage due
to the advancements of defensive products and solutions, this project does not
contain any malicious code. PowerZure does not exploit bugs within Azure, it
exploits misconfigurations.

C\# was also explored for creating this project but there were two main
problems:

1.  There were at least four different APIs being used for the project. MSOL,
    Azure REST, Azure SDK, Graph.

2.  The documentation for these APIs simply was too poor to continue. Entire
    methods missing, namespaces typo’d, and other problems begged the question
    of what advantage did C\# give over PowerShell (Answer: none)

Realistically, there is zero reason to ever run PowerZure on a victim’s machine.
Authentication is done by using an existing accesstoken.json file or by logging
in via prompt when logging into Azure CLI.

# Requirements

<<<<<<< HEAD
Azure has many different PowerShell modules, each using a different API. Some
have been deprecated and some do not have nearly as much functionality as the
others, despite all being Microsoft-made. PowerZure uses three Azure modules,
each with a different purpose.

1.  [Azure
    CLI](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest)

The Azure CLI is the primary module used in PowerZure as throughout my
testing and building this project, it became clear the Azure CLI module
had the most functionality and decent support on Github. Azure CLI uses the Azure REST API.

2.  [Azure
    PowerShell](https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0)

The Azure PS "Az" module is used to fill in gaps where Azure CLI
functionality lacks. Specifically, Azure CLI has no cmdlets for
interacting with Automation Accounts or Runbooks, hence the need for
Azure PS. Azure PS is the successor to the AzureRM module uses the Graph API.

3.  [AzureAD](https://docs.microsoft.com/en-us/powershell/module/Azuread/?view=azureadps-2.0)

    The AzureAD module is used for the more mature cmdlets around interacting
    with (you guessed it) Azure Active Directory. While both Azure CLI and Azure
    PS have cmdlets for doing basic things, like listing users and groups, when
    it came to more advanced things such as adding an AAD role to a user, the
    AzureAD module is needed. AzureAD uses the Graph API.

    These three modules are needed to **fully** use PowerZure. If you do not
    need to interact with AAD or Automation Accounts, then Azure CLI is the only
    module needed. With this being said, PowerZure should also be run from an
    elevated PowerShell window.
=======
The "Az" [Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/?view=azps-4.2.0) module is the only module used in PowerZure, as it is the most current module for Azure. The Az module interacts using the Azure REST API.
>>>>>>> Dev

## Author & License

Author: Ryan Hausknecht (@haus3c)

License: BSD-3
