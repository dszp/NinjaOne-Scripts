# ConnectSecure v3 and v4 Deployment scripts
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
This is the ConnectSecure Company ID. Can pass it or hardcode it under the CONFIG section. Usually 3 digits, might be 4 in larger installs. 

A Script Variable version will take precedence, followed by parameter, followed by Documentation Custom Field if those are both blank.

### TenantID
This value is your ConnectSecure tenant ID, global for your entire instance. Can pass it or hardcode it under the CONFIG section. Should be 18 digits.

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

# Platform Version 3
The [Deploy-ConnectSecure-V3.ps1](https://github.com/dszp/NinjaOne-Scripts/blob/main/ConnectSecure/Deploy-ConnectSecure-V3.ps1) script will attempt to deploy (or remove)  the ConnectSecure Vulnerability Scan Agent to Windows systems. Basic usage documentation is below or at the top of the script:

Running this script without arguments will attempt to install the agent using the EXE installer and the Company ID, Client ID, and Client Secret located in 
Custom Fields or Script Variables (if any), only if the agent service does not already exist on the system.

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

