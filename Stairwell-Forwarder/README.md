# Deploy Stairwell Agent to Windows, or Uninstall
This script Installs the Stairwell.com file-forwarding Inception Forwarder agent to Windows machines, including file download (the installer works from their site directly if you locate it and add to the script, from their knowledge base, though I've left direct links out of this script for now), using the Auth Token and Environment ID from a Stairwell tenant (their knowledge base also contains documentation on where to find these) stored in two Custom Fields (recommend Organization level but up to you). If the values don't match the right pattern for these values, the script will error and exit.

I stored the Auth Token in a NinjaRMM **Secure Custom Field** with Script Read access and the Environment ID in a **Text Custom Field** with Script Read access. The field names are defined at the top of the script. These custom fields must have Automation Read access allowed. The format of the two tokens are validated by the script to be in the correct format.

This script has been kept somewhat generic for easy modification/reuse. It defines a service name variable and the script will quit and not install if the service exists on the system already. It also confirms the service exists after the installation completes. The script attempts to delete the installer after it's finished. You will likely need to modify any token validation regular expressions if you need to supply one or more values from custom fields as well.

The installer is a WiX-generated .exe file and the silent installation flags are straightforward and could be adapted in $ArgumentList to many other installers.

## Usage
Update the EDIT ME section of the script to adjust any variables that are custom to you, and define the $DownloadURL variable to have the correct URL.

Run without arguments to install using values provided by Custom Fields. Add the `-Force` parameter or Script Variable Checkbox to attempt the installation even if the agent service already exists on the target machine.

Pass the `-Uninstall` switch to the script to trigger removal instead of installation.

The Uninstall command requires the original installer from the same download, but runs it with different flags to trigger silent removal; these arguments are farther down the script and not near the top. I'm told that the installer used for removal should be the same version that's installed, but haven't had multiple versions to test. The .NET 5+ libraries are installed by the bundle (currently a .NET 6 library version is installed), required for the app, and are NOT removed by the uninstallation routine.

You can pass either `-NoScan` or `-NoInitialScan` flags (they do the same thing) to the script to pass an argument that overrides the default state and prevents an initial full system scan and cataloging of all files at installation, instead just uploading executables and scripts as they are written or run going forward.