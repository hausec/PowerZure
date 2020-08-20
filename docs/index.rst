.. meta::
   description lang=en: Assess and Exploit Azure

.. image:: https://i.imgur.com/AQCbTn5.png
   :align: center
   :width: 800px
   :alt: PowerZure logo


PowerZure is a PowerShell project created to assess and exploit
resources within Microsoft’s cloud platform, Azure. PowerZure was
created out of the need for a framework that can both perform
reconnaissance **and** exploitation of Azure.

Getting Started
---------------

An overview of Azure, Azure AD, and PowerZure is covered in my blog post here https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a

<<<<<<< HEAD
To get started with PowerZure, make sure the `requirements <https://powerzure.readthedocs.io/en/latest/Requirements/requirements.html>`__ are met. If you do not have the modules, PowerZure will ask you if you'd like to install them automatically when importing PowerZure as a module. PowerZure does require an Administrative PowerShell window, >= version 5.0. 
=======
To get started with PowerZure, make sure the `requirements <https://powerzure.readthedocs.io/en/latest/Requirements/requirements.html>`__ are met. If you do not have the Az Module, PowerZure will ask you if you'd like to install it automatically when importing PowerZure as a module. PowerZure does require an Administrative PowerShell window, >= version 5.0. 
>>>>>>> Dev
There is no advantage to running PowerZure on a compromised/pwned machine. Since you're interacting with the cloud, it's opsec safe to use from a bastion operating host, or if you're feeling adventurous, your own host. Read the operational usage page `here <https://powerzure.readthedocs.io/en/latest/Operationalusage/opusage.html>`__ 

Additionally, you must sign-in to Azure before PowerZure functions are made available. To sign in, use the cmdlet 

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
   
   
Upon importing, it will list your current role and available subscriptions. From there, you can run

::

<<<<<<< HEAD
   Get-Targets
=======
   Get-AzureTargets
>>>>>>> Dev

   
To get a list of resources you have access to.


.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: About
   
   About/about
   
.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Requirements
   
   Requirements/requirements

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Operational Usage
   
   Operationalusage/opusage


.. toctree::
   :maxdepth: 3
   :hidden:
   :caption: Functions
   
   Functions/help   
   Functions/infogathering
   Functions/operational
<<<<<<< HEAD
   Functions/exfil
=======
>>>>>>> Dev

   