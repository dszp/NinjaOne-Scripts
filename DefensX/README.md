# Deploy-DefensX.ps1
## Synopsis
Install, Upgrade, or Uninstall DefenseX provided a valid [DefensX](https://www.defensx.com) KEY from the PowerShell Deployment for a given tenant.

## Description
Install, Upgrade, or Uninstall DefenseX provided a valid DefensX KEY from the PowerShell Deployment for a given tenant with KEY provided via parameter, environment variables, or NinjaRMM Custom Field.
  
With no parameters, installation will be attempted, but only if the DefenseX services does not exist. Version will be ignored without the -Upgrade parameter.

This script uses NinjaRMM Custom Fields to get the KEY by default (see CONFIG), but they can be passed in as parameters or Script Variables (environment variables) if desired.

The Ninja Custom Field should be a single string with either a 16-character (alphanumeric) Short KEY or 224-character Long KEY (alphanumeric plus limited symbols such as -, _, and period), pulled out of the DefensX Deployments RMM field for a given client. The short key is recommended, configurable from the RMM popup.

As long as you pass in a -KEY parameter, or provide a KEY environment variable, this script will function entirely separate from NinjaRMM.

## Parameter List
The additional parameters in the param() array that are not individually documented are all switches that are true if they exist and false if they are not provided. They can be checkboxes in NinjaRMM Script Variables (environment variables) or passed in on the command line, and will be converted to a 1 or 0 and passed to the appropriate argument to the MSI installer, as defined in the DefensX documentation and user interface. The argument names are simplified for ease of typing, and don't correspond precisely to the MSI arguments, but the mapping should be relatively simple to understand.
 
### PARAMETER KEY
If this parameter is passed to the DefensX PowerShell Deployment Script, it will be used instead of NinjaRMM Custom Fields. This key is located in the the DefensX Customer Console under Policies-\>Policy Groups-\>Deployments-\>RMM button, then turn on "Use Short Deployment Key" and then get the 16-character key at the very end of the command after the equals sign. The parameter should also accept the default 224-character key, but the 16-character short key is recommended. Required for install or upgrade unless supplied via $env:KEY (like via Ninja Script Variables) or NinjaRMM Custom Field. Not required for uninstall or Info check.

### PARAMETER Upgrade
Install Reinstall/Upgrade DefensX if it's already installed and at an older version than the current version available online, or if it's not installed at all (will also install from scratch, just won't quit if it's already installed and will check if it's outdated and upgrade if it is).

If the most current version is already installed, the agent will not be reinstalled unless you add the -Force parameter.

### PARAMETER Force
Add to the -Upgrade parameter to attempt to reinstall even if the same version is already installed.

### PARAMETER Uninstall
If DefensX is already installed, uninstall it, using the uninstall GUID from the Windows Registry. Other parameters will be ignored.

### PARAMETER Info
Confirm installation status and print version info, then exit. Also queries the version number of the cloud installer file and reports the current installer version. Other parameters will be ignored.

### PARAMETER SpecificVersion
If you provide a specifica installer version that the DefensX cloud has available to download, the installation will use this version of the MSI file to install the agent. This is an untested feature without much error checking or reporting, but uses the installer version URL provided directly in DefensX documentation.
## EXAMPLES
```
Deploy-DefensX.ps1
Deploy-DefensX.ps1 -KEY 'yourKEY'
Deploy-DefensX.ps1 -KEY 'yourKEY' -Upgrade
Deploy-DefensX.ps1 -KEY 'yourKEY' -Upgrade -Force
Deploy-DefensX.ps1 -Info
Deploy-DefensX.ps1 -KEY 'yourKEY' -SpecificVersion 1.9.70
Deploy-DefensX.ps1 -Uninstall
Deploy-DefensX.ps1 -Upgrade
```

## Version History
Version 0.1.0 - 2024-03-21 - by David Szpunar - Initial released version

Version 0.0.3 - 2024-03-21 - by David Szpunar - Updated comments and formatting to better describe where to obtain the KEY, refactor some logic (internal)

Version 0.0.2 - 2024-03-21 - by David Szpunar - Updated comment docs and made slight code adjustments (internal)

Version 0.0.1 - 2024-03-20 - by David Szpunar - Initial version by David Szpunar (internal)