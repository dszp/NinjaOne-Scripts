# ConnectSecure Deployment scripts
These scripts allow for the deployment of [ConnectSecure](https://www.connectsecure.com) (formerly CyberCNS) agents for either the version 3 or version 4 platforms to Windows endpoints, and optionally allow for the removal/uninstallation of the other version if you choose (and it’s installed).

Both [scripts](https://github.com/dszp/NinjaOne-Scripts/tree/main/ConnectSecure) use the public download endpoints provided by ConnectSecure for their own agent installers that should always be the most current version of each agent. You will need to customize the tenant and client fields, either in the script config statically or via things like parameters or NinjaRMM Custom Fields or Script Variables. Documentation for the separate v3 and v4 installer scripts is below:

- [Docs for Version 4 Deployment Script](#platform-version-4)
- [Docs for Version 3 Deployment Script](#platform-version-3)
- [Warranty](#warranty)

***NOTE:* These scripts and all options have not been fully and exhaustively tested with ConnectSecure's latest v4 release, though installation seems to be working fine with light testing. Due to substantial changes since v4's original release to today's beta version, there could be unknown changes and bugs that I'm not aware of, even though it appears to be working normally. When I eventually test more thoroughly I will remove this note. Feedback from anyone using/testing the script is welcome!**

# Platform Version 4
The [Deploy-ConnectSecure-V4.ps1](https://github.com/dszp/NinjaOne-Scripts/blob/main/ConnectSecure/Deploy-ConnectSecure-V4.ps1) script will attempt to deploy (or remove)  the ConnectSecure Vulnerability Scan Agent to Windows systems. Basic usage documentation is below or at the top of the script:

Running this script without arguments will attempt to install the agent using the EXE installer and the Company ID located in Custom Fields or Script Variables (if any), only if the agent service does not already exist on the system.

**Review the CONFIG section of the script before deploying!**

## Parameters or Script Variables
This script accepts the following arguments, which may also be set as Custom Fields or Script Variables in NinjaRMM:

### CompanyID
This is the ConnectSecure Company ID. Can pass it or hardcode it under the CONFIG section, or use Ninja Script Variable or Custom Fields. It's a number 
3 to 5 digits long. This variable is unique for each customer managed in the ConnectSecure environment. 
A Script Variable version will take precedence, followed by parameter, followed by Documentation Custom Field, followed by the standard Custom Field, 
if those are all blank. The default NinjaOne field name is "connectsecureCompanyId" unless you customize the field name in the CONFIG section.

A Script Variable version will take precedence, followed by parameter, followed by Documentation Custom Field if those are both blank.

### TenantID
This value is your ConnectSecure tenant ID, global for your entire instance. Can pass it or hardcode it under the CONFIG section. Should be 18 digits.

### UserSecret
This is the ConnectSecure User Secret. Can pass it or hardcode it under the CONFIG section. You can also provide this with the NinjaOne Custom Field 
or NinjaOne Custom Documentation Field if you configure the field name under the CONFIG section as the value of the #customUserSecret variable. 
A Script Variable version will take precedence, followed by parameter, followed by Documentation Custom Field, followed by the standard Custom Field, 
if those are all blank.

The value is an alphanumeric string that ConnectSecure's Agent Download page provides as the value of the "-j" parameter inside the deployment 
script for Windows agents. See example screenshot in the documentation at 
https://cybercns.atlassian.net/wiki/spaces/CVB/pages/2111242438/How+To+Install+V4+Agent+Using+RMM+Script#Obtain-Company-ID%2C-Tenant-ID%2C-and-User-Secret-Information

The User Secret ties the installation to the user who generated the installer on the ConnectSecure back-end system, but it may be reused for all 
installations without restriction just like the TenantID, only the CompanyID will be different for each company being scanned/managed. 
The default NinjaOne field name is "connectsecureUserSecret" unless you customize the field name in the CONFIG section.

### Once
Use this switch to run the vulnerability scan once, without installing the agent permanently on the system. Can also be a Script Variables Checkbox.
**NOTE: This option is not yet implemented or available in v4 yet.**

### Force
Adding this switch or Script Variables Checkbox will either force installation (even if the service already exists) on the endpoint, or alternately, if the `-Uninstall` flag is called, will attempt to run the internal removal batch script regardless of whether the uninstall.bat file provided in the installation folder for the agent exists on the system or not (so this flag works with installation or removal).

### UninstallPrevious
Use this switch or Script Variables Checkbox to attempt to remove the V3 agent if it's currently installed on the system. If the V3 service exists, this will be run automatically before installing the V4 agent.

### Uninstall
Use this switch or Script Variables Checkbox to attempt to locate the `uninstall.bat` file inside the agent installation folder and run it if it exists, to remove the installed agent. If the batch file does not exist, nothing is done unless the `-Force` switch is also provided, in which case the contents of the batch script on an existing system has been embedded in this script (as of 2023-11-10) and will be executed anyway to attempt to remove the agent anyway via the internal uninstall method.

Output from each command is provided for feedback. Every parameter or switch can be set via Script Variables, and the first three also support Custom Fields. With minor adjustment, they could also use NinjaRMM Custom Documentation Fields.

## Version History
- Version 0.0.1 - 2023-10-17 - Initial Version by David Szpunar
- Version 0.1.0 - 2023-11-10 - Updated to include removal/uninstallation options and documentation.
- Version 0.1.1 - 2023-11-10 - Fixed spelling error in documentation.
- Version 0.1.2 - 2023-11-13 - Switched to processing Switch Variable Checkboxes automatically from Named Parameters using new handling method
- Version 0.1.3 - 2023-11-13 - Fix logic bug in new Script Variables handling method
- Version 0.2.0 - 2023-12-07 - Update to support ConnectSecure v4 beta and removing the v3 agent if it exists
- Version 0.2.1 - 2024-03-28 - Add a different supported TLS version check before download to attempt and fix
- Version 0.2.2 - 2024-10-25 - Add support for new -j, user secret, parameter described here -  https://cybercns.atlassian.net/wiki/spaces/CVB/pages/2111242438/How+To+Install+V4+Agent+Using+RMM+Script
- Version 0.2.3 - 2024-10-25 - Add additional error checking for User Secret, add custom field configuration for it, and add hardcoded override for User Secret as an option
- Version 0.3.0 - 2024-10-25 - Update documentation at top of script to cover User Secret and provide additional clarifications/details generally.

# Platform Version 3
The [Deploy-ConnectSecure-V3.ps1](https://github.com/dszp/NinjaOne-Scripts/blob/main/ConnectSecure/Deploy-ConnectSecure-V3.ps1) script will attempt to deploy (or remove)  the ConnectSecure Vulnerability Scan Agent to Windows systems. Basic usage documentation is below or at the top of the script.

Running this script without arguments will attempt to install the agent using the EXE installer and the Company ID, Client ID, and Client Secret located in 
Custom Fields or Script Variables (if any), only if the agent service does not already exist on the system.

**NOTE as of 2024-10-25: Version 3 of ConnectSecure/CyberCNS is deprecated and will be shut down at the end of 2024. Please use version 4 instead. This script is available 
for reference or temporary use only prior to migration. The Version 4 deployment script has an option to remove the version 3 agent if it is installed. 
The connectsecureCompanyID custom field name (documentation or regular) for NinjaOne is reused by the Version 4 script but has a DIFFERENT value in each 
system. Please keep this in mind; you may wish to use a Script Variable or parameter or other method with this v3 script to avoid conflicts with v4 
configuration prior to retirement of v3, or while you're moving to deploy v4. You can also rename the custom field in the $customCompanyID variable in 
either script to a non-conflicting name.**

**Review the CONFIG section of the script before deploying!**

This script accepts the following arguments, which may also be set as Custom Fields or Script Variables:

## Parameters or Script Variables
### CompanyID
### ClientID
### ClientSecret
These three values are provided by ConnectSecure CyberCNS in their deployment instructions for each client.
In the CONFIG section below, you can configure the NinjaRMM Custom Field names in `$customCompanyID`, `$customClientID`, and `$customClientSecret` 
to pull the values from custom fields (we use org fields, text for the first two and secure for the client secret), making sure permissions for 
script read are configured! The format of these values is validated via regex and the script will quit if they are not valid.

### CompanyName
This value is your CyberCNS instance name, global for your entire instance. Can pass it or hardcode it under the CONFIG section.

### EXE
### MSI
Use either of these switches to specify the type of installation. The default is EXE if you provide none. Script Variables Checkboxes (one or both) can be created in the NinjaRMM to control these as well, if preferred.

### Once
Use this switch to run the vulnerability scan once, without installing the agent permanently on the system. Can also be a Script Variables Checkbox.


### Force
Adding this switch or Script Variables Checkbox will either force installation (even if the service already exists) on the endpoint, or alternately, if the `-Uninstall` flag is called, will attempt to run the internal removal batch script regardless of whether the `uninstall.bat` file provided in the installation folder for the agent exists on the system or not (so this flag works with installation or removal).

### UninstallNew
Use this switch or Script Variables Checkbox to attempt to remove the V4 agent if it's currently installed on the system. If the V4 service exists, 
this will be run automatically before installing the V3 agent.

### Uninstall
Use this switch or Script Variables Checkbox to attempt to locate the `uninstall.bat` file inside the agent installation folder and run it if it exists, 
to remove the installed agent. If the batch file does not exist, nothing is done unless the `-Force` switch is also provided, in which case the contents 
of the batch script on an existing system has been embedded in this script (as of 2023-11-10) and will be executed anyway to attempt to remove the 
agent anyway via the internal uninstall method.

Output from each command is provided for feedback. Every parameter or switch can be set via Script Variables, and the first three also support Custom Fields. With minor adjustment, they could also use NinjaRMM Custom Documentation Fields.

## Version History
- Version 0.0.1 - 2023-10-17 - Initial Version by David Szpunar
- Version 0.1.0 - 2023-11-10 - Updated to include removal/uninstallation options and documentation.
- Version 0.1.1 - 2023-11-10 - Fixed spelling error in documentation.
- Version 0.1.2 - 2023-11-13 - Switched to processing Switch Variable Checkboxes automatically from Named Parameters using new handling method
- Version 0.1.3 - 2023-11-13 - Fix logic bug in new Script Variables handling method
- Version 0.1.4 - 2023-12-07 - Update to support removing the v4 agent if it exists
- Version 0.1.5 - 2024-03-28 - Add a different supported TLS version check before download to attempt and fix

# Warranty
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

