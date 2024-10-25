<# Deploy-ConnectSecure-V4.ps1
Deploy (or Remove) ConnectSecure Vulnerability Scan Agent to Windows systems.

SOURCE: https://github.com/dszp/NinjaOne-Scripts/tree/main/ConnectSecure

Running this script without arguments will attempt to install the agent using the EXE installer and the Company ID located in 
Custom Fields or Script Variables (if any), only if the agent service does not already exist on the system.

Review the CONFIG section of the script before deploying!

This script accepts the following arguments, which may also be set as Custom Fields or Script Variables:
    -CompanyID
        This is the ConnectSecure Company ID. Can pass it or hardcode it under the CONFIG section. Usually 3 digits, might be 4 in larger installs. 
        A Script Variable version will take precedence, followed by parameter, followed by Documentation Custom Field if those are both blank.

    -TenantID
        This value is your ConnectSecure tenant ID, global for your entire instance. Can pass it or hardcode it under the CONFIG section. Should be 18 digits.

    -Once
        Use this switch to run the vulnerability scan once, without installing the agent permanently on the system. Can also be a Script Variables Checkbox. 
        This option is not yet implemented or available in v4 yet.

    -Force
        Adding this switch or Script Variables Checkbox will either force installation (even if the service already exists) on the endpoint, or alternately, if 
        the -Uninstall flag is called, will attempt to run the internal removal batch script regardless of whether the uninstall.bat file provided in the 
        installation folder for the agent exists on the system or not (so this flag works with installation or removal).

    -UninstallPrevious
        Use this switch or Script Variables Checkbox to attempt to remove the V3 agent if it's currently installed on the system. If the V3 service exists, 
        this will be run automatically before installing the V4 agent.

    -Uninstall
        Use this switch or Script Variables Checkbox to attempt to locate the uninstall.bat file inside the agent installation folder and run it if it exists, 
        to remove the installed agent. If the batch file does not exist, nothing is done unless the -Force switch is also provided, in which case the contents 
        of the batch script on an existing system has been embedded in this script (as of 2023-11-10) and will be executed anyway to attempt to remove the 
        agent anyway via the internal uninstall method.
    
Output from each command is provided for feedback. Every parameter or switch can be set via Script Variables, and the first one also supports a Custom 
Documentation Field that will only be used if another value is not provided.

Source for remove-on-reboot code: https://superuser.com/questions/1700602/using-powershell-to-add-an-entry-to-pendingfilerenameoperations-without-disrup

Version 0.0.1 - 2023-10-17 - Initial Version by David Szpunar
Version 0.1.0 - 2023-11-10 - Updated to include removal/uninstallation options and documentation.
Version 0.1.1 - 2023-11-10 - Fixed spelling error in documentation.
Version 0.1.2 - 2023-11-13 - Switched to processing Switch Variable Checkboxes automatically from Named Parameters using new handling method
Version 0.1.3 - 2023-11-13 - Fix logic bug in new Script Variables handling method
Version 0.2.0 - 2023-12-07 - Update to support ConnectSecure v4 beta and removing the v3 agent if it exists
Version 0.2.1 - 2024-03-28 - Add a different supported TLS version check before download to attempt and fix
Version 0.2.2 - 2024-10-25 - Add support for new -j, user secret, parameter described here -  https://cybercns.atlassian.net/wiki/spaces/CVB/pages/2111242438/How+To+Install+V4+Agent+Using+RMM+Script
Version 0.2.3 - 2024-10-25 - Add additional error checking for User Secret, add custom field configuration for it, and add hardcoded override for User Secret as an option

NOTE: This script and all options have not been fully and exhaustively tested with ConnectSecure's latest v4 release, though installation 
seems to be working fine with light testing. Due to substantial changes since v4's original release to today's beta version, 
there could be unknown changes and bugs that I'm not aware of, even though it appears to be working normally. When I eventually 
test more thoroughly I will remove this note. Feedback from anyone using/testing the script is welcome!

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][int] $CompanyID = $env:companyid,
    [Parameter(Mandatory = $false)][string] $TenantID = $env:tenentid,
    [Parameter(Mandatory = $false)][string] $userSecret = $env:userSecret,
    [switch] $Once,
    [switch] $Force,
    [switch] $UninstallPrevious,
    [switch] $Uninstall
)

### PROCESS NINJRAMM SCRIPT VARIABLES AND ASSIGN TO NAMED SWITCH PARAMETERS
# Get all named parameters and overwrite with any matching Script Variables with value of 'true' from environment variables
# Otherwise, if not a checkbox ('true' string), assign any other Script Variables provided to matching named parameters
$switchParameters = (Get-Command -Name $MyInvocation.InvocationName).Parameters
foreach ($param in $switchParameters.keys) {
    $var = Get-Variable -Name $param -ErrorAction SilentlyContinue
    if ($var) {
        $envVarName = $var.Name.ToLower()
        $envVarValue = [System.Environment]::GetEnvironmentVariable("$envVarName")
        if (![string]::IsNullOrWhiteSpace($envVarValue) -and ![string]::IsNullOrEmpty($envVarValue) -and $envVarValue.ToLower() -eq 'true') {
            # Checkbox variables
            $PSBoundParameters[$envVarName] = $true
            Set-Variable -Name "$envVarName" -Value $true -Scope Script
        }
        elseif (![string]::IsNullOrWhiteSpace($envVarValue) -and ![string]::IsNullOrEmpty($envVarValue) -and $envVarValue -ne 'false') {
            # non-Checkbox string variables
            $PSBoundParameters[$envVarName] = $envVarValue
            Set-Variable -Name "$envVarName" -Value $envVarValue -Scope Script
        }
    }
}
### END PROCESS SCRIPT VARIABLES

##### CONFIG
# Manually set the global Tenant ID for ConnectSecure V4 instance, if not passed in via variable or parameter already:
if ([string]::IsNullOrEmpty($TenantID) -or [string]::IsNullOrWhiteSpace($TenantID)) {
    $TenantID = '000000000000000000'    # Numeric Tenant ID string from the deployment script
}

# Manually set the Script Parameter, Script Variable, or NinjaOne Custom Field or Documentation Custom Field instead of being hardcoded
if ([string]::IsNullOrEmpty($userSecret) -or [string]::IsNullOrWhiteSpace($userSecret)) {
    $userSecret = ''    # User Secret optionally hardcoded to a specific user value (the -j parameter from the install string)
}

# The name of your NinjaRMM Documentation document that contains the custom field below, assumes that there is both a template 
# and a single instance of the document with the same name (otheriwse change to Ninja-Property-Docs-Get calls below with separate 
# template and instance names):
$CustomNinjaDocumentation = 'Deployments'

# NinjaRMM Custom Documentation Field Name (can be secure, all must have Script Read permissions)
$customCompanyID = 'connectsecureCompanyId'

# NinjaRMM Custom Documentation Field Name (can be secure, all must have Script Read permissions)
$customUserSecret = 'connectsecureUserSecret'

$InstallLocation = $env:TEMP        # Temporary downloaded installer location (can leave as temp folder)
$InstallFilename = 'cybercnsagent'  # Temporary downloaded installer filename (can leave as-is)

#Service Name
$ServiceName = "CyberCNSAgent"
$ServiceNameV3 = "CyberCNSAgentV2"
##### END CONFIG

$CheckNinjaCommand = "Ninja-Property-Docs-Get-Single"

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
# If not elevated error out. Admin priveledges are required to install or remove the application.
if (-not (Test-IsElevated)) {
    Write-Error -Message "Access Denied. Please run with Administrator or SYSTEM privileges."
    exit 1
}

##### UNINSTALL/REMOVAL of VERSION 4 AGENT
if ($Uninstall) {
    Write-Host "Uninstalling ConnectSecure CyberCNS Lightweight Agent..."
    If ( (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
        Write-Host "The service" $ServiceName "is installed. Uninstalling."
    }

    # Run Uninstall Batch Script If It Exists
    $UninstallReturnValue = 0
    $uninstallBatPaths = @("${Env:ProgramFiles(x86)}\CyberCNSAgent\uninstall.bat", "$Env:Programfiles\CyberCNSAgent\uninstall.bat")
    $uninstallBatPath = "${Env:ProgramFiles(x86)}\CyberCNSAgent\uninstall.bat"
    foreach ($path in $uninstallBatPaths) {
        Write-Host "Checking if path exists: $path"
        if (Test-Path $path) {
            $uninstallBatPath = $path
            Write-Host "(it does)"
        }
        else {
            Write-Host "(it does not)"
        }
    }
    $alternativeScript = @'
echo Running alternative cleanup script
@echo off
ping 127.0.0.1 -n 6 > nul
cd "C:\PROGRA~2"
:: sc stop ConnectSecureAgentMonitor
:: timeout /T 5 > nul
:: sc delete ConnectSecureAgentMonitor
timeout /T 5 > nul
sc stop CyberCNSAgent
timeout /T 5 > nul
sc delete CyberCNSAgent
ping 127.0.0.1 -n 6 > nul
taskkill /IM osqueryi.exe /F
taskkill /IM nmap.exe /F
taskkill /IM cybercnsagent.exe /F
CyberCNSAgent\cybercnsagent.exe --internalAssetArgument uninstallservice
rmdir CyberCNSAgent /s /q
'@

    if (Test-Path $uninstallBatPath) {
        Write-Host "Uninstall batch script exists. Running it..."
        $UninstallReturnValue = Start-Process -FilePath $uninstallBatPath -Wait
        if (Test-Path $uninstallBatPath) {
            Write-Host "Uninstall batch script still exists after removal attempt, you may wish to verify or manually remove."
        }
        Write-Host "Uninstall batch script removal attempt completed."
        If ( (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceName "is still installed."
        }
        else {
            Write-Host "The service" $ServiceName "is confirmed to not exist."
        }
    }
    elseif ($Force) {
        Write-Host "Uninstall batch script does not exist and -Force flag is set. Running alternative cleanup script..."
        $UninstallReturnValue = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $alternativeScript" -Wait
        Write-Host "Alternative cleanup script removal attempt completed."
        If ( (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceName "is still installed."
        }
        else {
            Write-Host "The service" $ServiceName "is confirmed to not exist."
        }
    }
    else {
        Write-Host "Uninstall batch script does not exist, nothing else done. To try built-in removal anyway, re-run adding -Force flag."
    }

    Write-Host "Uninstallation attempt completed."

    # End Uninstallation by quitting
    exit $UninstallReturnValue
}

##### UNINSTALL/REMOVAL of VERSION 3 AGENT
# Force uninstall ov V3 agent if the V3 agent is installed, before deploying the V4 agent.
If ( (Get-Service $ServiceNameV3 -ErrorAction SilentlyContinue) ) {
    $UninstallPrevious = $true
}
if ($UninstallPrevious) {
    Write-Host "Uninstalling ConnectSecure CyberCNS Lightweight Agent from Version 3..."
    If ( (Get-Service $ServiceNameV3 -ErrorAction SilentlyContinue) ) {
        Write-Host "The service" $ServiceNameV3 "is installed (v3 agent) or force-remove is requested. Uninstalling."
    }

    # Run Uninstall Batch Script If It Exists
    $UninstallReturnValue = 0
    $uninstallBatPaths = @("${Env:ProgramFiles(x86)}\CyberCNSAgentV2\uninstall.bat", "$Env:Programfiles\CyberCNSAgentV2\uninstall.bat")
    $uninstallBatPath = "${Env:ProgramFiles(x86)}\CyberCNSAgentV2\uninstall.bat"
    foreach ($path in $uninstallBatPaths) {
        Write-Host "Checking if path exists: $path"
        if (Test-Path $path) {
            $uninstallBatPath = $path
            Write-Host "(it does)"
        }
        else {
            Write-Host "(it does not)"
        }
    }
    $alternativeScript = @'
echo Running alternative cleanup script
@echo off
ping 127.0.0.1 -n 6 > nul
cd "C:\Program Files (x86)"
sc stop CyberCNSAgentMonitor
timeout /T 5 > nul
sc delete CyberCNSAgentMonitor
timeout /T 5 > nul
sc stop CyberCNSAgentV2
timeout /T 5 > nul
sc delete CyberCNSAgentV2
ping 127.0.0.1 -n 6 > nul
taskkill /IM osqueryi.exe /F
taskkill /IM nmap.exe /F
taskkill /IM cybercnsagentv2.exe /F
CyberCNSAgentV2\cybercnsagentv2.exe --internalAssetArgument uninstallservice
msiexec.exe /X cybercnsagent.msi /norestart  /quiet
rmdir CyberCNSAgentV2 /s /q
'@

    if (Test-Path $uninstallBatPath) {
        Write-Host "Uninstall batch script exists. Running it..."
        $UninstallReturnValue = Start-Process -FilePath $uninstallBatPath -Wait
        if (Test-Path $uninstallBatPath) {
            Write-Host "Uninstall batch script still exists after removal attempt, you may wish to verify or manually remove."
        }
        Write-Host "Uninstall batch script removal attempt completed."
        If ( (Get-Service $ServiceNameV3 -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceNameV3 "is still installed."
        }
        else {
            Write-Host "The service" $ServiceNameV3 "is confirmed to not exist."
        }
    }
    elseif ($Force) {
        Write-Host "Uninstall batch script does not exist and -Force flag is set. Running alternative cleanup script..."
        $UninstallReturnValue = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $alternativeScript" -Wait
        Write-Host "Alternative cleanup script removal attempt completed."
        If ( (Get-Service $ServiceNameV3 -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceNameV3 "is still installed."
        }
        else {
            Write-Host "The service" $ServiceNameV3 "is confirmed to not exist."
        }
    }
    else {
        Write-Host "Uninstall batch script does not exist, nothing else done. To try built-in removal anyway, re-run adding -Force flag."
    }

    Write-Host "Uninstallation attempt of V3 agent completed."
    Write-Host ""

    # # End Uninstallation by quitting
    # exit $UninstallReturnValue
}

##### INSTALLATION

If ( !$Force -and (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
    Write-Host "The service" $ServiceName "is already installed. Retry with -Force to attempt install anyway."
    exit 0
}

# If no script variable was passed, check Ninja Documentation for the CompanyID
if (!$CompanyID -or $CompanyID -eq 0) {
    if ($(Get-Command $CheckNinjaCommand -ErrorAction SilentlyContinue).Name -like $CheckNinjaCommand -and -not [string]::IsNullOrEmpty($customCompanyID) -and -not [string]::IsNullOrWhiteSpace($customCompanyID)) {
        Write-Host "Attempting to get Documentation Custom Field $customCompanyID from the $CustomNinjaDocumentation document."
        $CompanyID = Ninja-Property-Docs-Get-Single $CustomNinjaDocumentation $customCompanyID
    }
}

# If Ninja Documentation did not return a value, check Ninja Custom Fields for the CompanyID
if (!$CompanyID -or $CompanyID -eq 0) {
    Write-Host " Ninja Documentation value not found for CompanyID. Trying Ninja Custom Field."
    $CompanyID = (Ninja-Property-Get $customCompanyID)
}

# If no script variable was passed, check Ninja Documentation for the User Secret
if ([string]::IsNullOrEmpty($userSecret) -or [string]::IsNullOrWhiteSpace($userSecret)) {
    if ($(Get-Command $CheckNinjaCommand -ErrorAction SilentlyContinue).Name -like $CheckNinjaCommand -and -not [string]::IsNullOrEmpty($customUserSecret) -and -not [string]::IsNullOrWhiteSpace($customUserSecret)) {
        Write-Host "Attempting to get Documentation Custom Field $customUserSecret from the $CustomNinjaDocumentation document."
        $userSecret = Ninja-Property-Docs-Get-Single $CustomNinjaDocumentation $customUserSecret
    }
}

# If Ninja Documentation did not return a value, check Ninja Custom Fields for the User Secret
if ([string]::IsNullOrEmpty($userSecret) -or [string]::IsNullOrWhiteSpace($userSecret)) {
    Write-Host " Ninja Documentation value not found gpt User Secret. Trying Ninja Custom Field."
    $userSecret = (Ninja-Property-Get $customUserSecret)
}

# if(!$Uninstall) {
Write-Host "Company ID from $customCompanyID Custom Doc Field, Ninja Custom Field, or passed to script: $CompanyID"

if ($CompanyID -is [int] -and $CompanyID -ge 100 -and $CompanyID -le 999999) {
    Write-Host "Company ID passed basic format validation..."
}
else {
    Write-Host "No Company ID value provided or invalid format, correctly set via script field, arguement, or custom field."
    Write-Host "Format should be: ##### (3 to 5 integer digits)"
    exit 1
}
if ($TenantID -Match "^[a-f0-9]{18}$") {
    Write-Host "Tenant ID passed basic format validation..."
}
else {
    Write-Host "No Tenant ID value provided or invalid format, correctly set via script config, arguement, or custom field."
    Write-Host "Format should be: ################## (18 decimal numbers)"
    exit 1
}
if ([string]::IsNullOrEmpty($userSecret) -or [string]::IsNullOrWhiteSpace($userSecret)) {
    Write-Host "No User secret provided. This new field is mandatory from the -j installer parameter to identify the user generating the installer."
    exit 1
}
else {
    Write-Host "User Secret exists and is not null..."
    
}

# Ensure a secure TLS version is used.
$ProtocolsSupported = [enum]::GetValues('Net.SecurityProtocolType')
if ( ($ProtocolsSupported -contains 'Tls13') -and ($ProtocolsSupported -contains 'Tls12') ) {
    # Use only TLS 1.3 or 1.2
    [Net.ServicePointManager]::SecurityProtocol = (
        [Enum]::ToObject([Net.SecurityProtocolType], 12288) -bOR [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    )
}
else {
    # Use only 1.2
    try {
        # In certain .NET 4.0 patch levels, SecurityProtocolType does not have a TLS 1.2 entry.
        # Rather than check for 'Tls12', we force-set TLS 1.2 and catch the error if it's truly unsupported.
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    }
    catch {
        $msg = $_.Exception.Message
        $err = "ERROR: Unable to use a secure version of TLS. Please verify Hotfix KB3140245 is installed."
        Write-Host "$err : $msg"
        Write-Error "$err : $msg"
        exit 1
    }
}
$ProgressPreference = 'SilentlyContinue'

if ($Once) {
    Write-Host "Running one-time Windows device scan without installing agent."
    Write-Host "Scan once not implemented yet for v4."
    exit 10
    # 
    # $destination = "$InstallLocation\$InstallFilename.exe"
    # if (Test-Path $destination) {
    #     Remove-Item $destination -Force
    # }
    # $source = (Invoke-RestMethod -Method "Get" -URI "https://configuration.mycybercns.com/api/v3/configuration/agentlink?ostype=windows");
    # Invoke-WebRequest -Uri $source -OutFile $destination
    # $exitCode = [Diagnostics.Process]::Start($destination,"-c $CompanyID -a $ClientID -s $ClientSecret -b $BaseURL -e $CompanyName -m Scan").WaitForExit(3600)
    # # Set destination file to be deleted on computer reboot (when it'll be done being used)
    # New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\$destination`0`0") -type MultiString -Force | Out-Null
}
else {
    Write-Host "Installation proceeding"
}

# Install Lightweight Agent EXE
$source = (Invoke-RestMethod -Method "Get" -Uri "https://configuration.myconnectsecure.com/api/v4/configuration/agentlink?ostype=windows")
$destination = "$InstallLocation\$InstallFilename.exe"
Invoke-WebRequest -Uri $source -OutFile $destination
$exitCode = [Diagnostics.Process]::Start($destination, "-c $CompanyID -e $TenantID -j $userSecret -i").WaitForExit(600)
if ($exitCode -eq 0) {
    Write-Host "Installation was initiated."
}
else {
    Write-Host "Installation failed. Check URL and make sure file exists. Exit code: $exitCode"
}
# Set destination file to be deleted on computer reboot (when it'll be done being used)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\$destination`0`0") -type MultiString -Force | Out-Null
