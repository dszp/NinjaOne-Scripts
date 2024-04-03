<# Deploy-ConnectSecure-V3.ps1
Deploy (or Remove) ConnectSecure (CyberCNS) Lightweight Agent to Windows systems.

SOURCE: https://github.com/dszp/NinjaOne-Scripts/tree/main/ConnectSecure

Running this script without arguments will attempt to install the agent using the EXE installer and the Company ID, Client ID, and Client Secret located in 
Custom Fields or Script Variables (if any), only if the agent service does not already exist on the system.

Review the CONFIG section of the script before deploying!

This script accepts the following arguments, which may also be set as Custom Fields or Script Variables:
    -CompanyID
    -ClientID
    -ClientSecret
        These three values are provided by ConnectSecure CyberCNS in their deployment instructions for each client.
        In the CONFIG section below, you can configure the NinjaRMM Custom Field names in $customCompanyID, $customClientID, and $customClientSecret 
        to pull the values from custom fields (we use org fields, text for the first two and secure for the client secret), making sure permissions for 
        script read are configured! The format of these values is validated via regex and the script will quit if they are not valid.

    -CompanyName
        This value is your CyberCNS instance name, global for your entire instance. Can pass it or hardcode it under the CONFIG section.

    -EXE
    -MSI
        Use either of these switches to specify the type of installation. The default is EXE if you provide none. Script Variables Checkboxes (one or both) 
        can be created in the NinjaRMM to control these as well, if preferred.

    -Once
        Use this switch to run the vulnerability scan once, without installing the agent permanently on the system. Can also be a Script Variables Checkbox.

    -Force
        Adding this switch or Script Variables Checkbox will either force installation (even if the service already exists) on the endpoint, or alternately, if 
        the -Uninstall flag is called, will attempt to run the internal removal batch script regardless of whether the uninstall.bat file provided in the 
        installation folder for the agent exists on the system or not (so this flag works with installation or removal).

    -UninstallNew
        Use this switch or Script Variables Checkbox to attempt to remove the V4 agent if it's currently installed on the system. If the V4 service exists, 
        this will be run automatically before installing the V3 agent.

    -Uninstall
        Use this switch or Script Variables Checkbox to attempt to locate the uninstall.bat file inside the agent installation folder and run it if it exists, 
        to remove the installed agent. If the batch file does not exist, nothing is done unless the -Force switch is also provided, in which case the contents 
        of the batch script on an existing system has been embedded in this script (as of 2023-11-10) and will be executed anyway to attempt to remove the 
        agent anyway via the internal uninstall method.
    
Output from each command is provided for feedback. Every parameter or switch can be set via Script Variables, and the first three also support Custom Fields. 
With minor adjustment, they could also use NinjaRMM Custom Documentation Fields.

Source for remove-on-reboot code: https://superuser.com/questions/1700602/using-powershell-to-add-an-entry-to-pendingfilerenameoperations-without-disrup

Version 0.0.1 - 2023-10-17 - Initial Version by David Szpunar
Version 0.1.0 - 2023-11-10 - Updated to include removal/uninstallation options and documentation.
Version 0.1.1 - 2023-11-10 - Fixed spelling error in documentation.
Version 0.1.2 - 2023-11-13 - Switched to processing Switch Variable Checkboxes automatically from Named Parameters using new handling method
Version 0.1.3 - 2023-11-13 - Fix logic bug in new Script Variables handling method
Version 0.1.4 - 2023-12-07 - Update to support removing the v4 agent if it exists
Version 0.1.5 - 2024-03-28 - Add a different supported TLS version check before download to attempt and fix

NOTE: This script and all options have not been fully and exhaustively tested with ConnectSecure's latest v4 release, though installation 
seems to be working fine with light testing. Due to substantial changes since v4's original release to today's beta version, 
there could be unknown changes and bugs that I'm not aware of, even though it appears to be working normally. When I eventually 
test more thoroughly I will remove this note. Feedback from anyone using/testing the script is welcome! This v3 version likely 
works fine but it does have a v4 removal part that not been tested, if you pass in that option.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][string] $CompanyID = $env:companyid,
    [Parameter(Mandatory=$false)][string] $ClientID = $env:clientid,
    [Parameter(Mandatory=$false)][string] $ClientSecret = $env:clientsecret,
    [Parameter(Mandatory=$false)][string] $CompanyName = $env:companyname,
    [switch] $EXE,
    [switch] $MSI,
    [switch] $Once,
    [switch] $Force,
    [switch] $UninstallNew,
    [switch] $Uninstall
)

### PROCESS NINJRAMM SCRIPT VARIABLES AND ASSIGN TO NAMED SWITCH PARAMETERS
# Get all named parameters and overwrite with any matching Script Variables with value of 'true' from environment variables
# Otherwise, if not a checkbox ('true' string), assign any other Script Variables provided to matching named parameters
$switchParameters = (Get-Command -Name $MyInvocation.InvocationName).Parameters;
foreach ($param in $switchParameters.keys) {
    $var = Get-Variable -Name $param -ErrorAction SilentlyContinue;
    if($var) {
        $envVarName = $var.Name.ToLower()
        $envVarValue = [System.Environment]::GetEnvironmentVariable("$envVarName")
        if (![string]::IsNullOrWhiteSpace($envVarValue) -and ![string]::IsNullOrEmpty($envVarValue) -and $envVarValue.ToLower() -eq 'true') {    # Checkbox variables
            $PSBoundParameters[$envVarName] = $true
            Set-Variable -Name "$envVarName" -Value $true -Scope Script
        } elseif (![string]::IsNullOrWhiteSpace($envVarValue) -and ![string]::IsNullOrEmpty($envVarValue) -and $envVarValue -ne 'false') {       # non-Checkbox string variables
            $PSBoundParameters[$envVarName] = $envVarValue
            Set-Variable -Name "$envVarName" -Value $envVarValue -Scope Script
        }
    }
}
### END PROCESS SCRIPT VARIABLES

# Define installer type to use
if($EXE) {
    $TYPE = "EXE"
} elseif($MSI) {
    $TYPE = "MSI"
} else {
    $TYPE = "EXE"   # Default install type
}

##### CONFIG
$BaseURL ='portaluseast2.mycybercns.com'    # Adjust if your instance is not on portaluseast2

if(!$CompanyName) { # For -e argument, CyberCNS Company Instance Name, if not passed in via arguement
    $CompanyName = 'ConnectSecureTenantShortName'
}

$InstallLocation = $env:TEMP        # Temporary downloaded installer location (can leave as temp folder)
$InstallFilename = 'cybercnsagent'  # Temporary downloaded installer filename (can leave as-is)

# NinjaRMM Custom Field Names (third can be secure, all must have Script Read permissions)
$customCompanyID = 'connectsecureCompanyId'
$customClientID = 'connectsecureClientId'
$customClientSecret = 'connectsecureClientSecret'

#Service Name
$ServiceName = "CyberCNSAgentV2"
$ServiceNameV4 = "CyberCNSAgent"
##### END CONFIG

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

##### UNINSTALL/REMOVAL

if($Uninstall) {
    Write-Host "Uninstalling ConnectSecure CyberCNS Lightweight Agent..."
    If ( (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
        Write-Host "The service" $ServiceName "is installed. Uninstalling."
    }

    # Run Uninstall Batch Script If It Exists
    $UninstallReturnValue = 0
    $uninstallBatPaths = @("${Env:ProgramFiles(x86)}\CyberCNSAgentV2\uninstall.bat","$Env:Programfiles\CyberCNSAgentV2\uninstall.bat")
    $uninstallBatPath = "${Env:ProgramFiles(x86)}\CyberCNSAgentV2\uninstall.bat"
    foreach ($path in $uninstallBatPaths) {
        Write-Host "Checking if path exists: $path"
        if (Test-Path $path) {
            $uninstallBatPath = $path
            Write-Host "(it does)"
        } else {
            Write-Host "(it does not)"
        }
    }
    $alternativeScript = @'
echo Running alternative cleanuip script
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
        if(Test-Path $uninstallBatPath) {
            Write-Host "Uninstall batch script still exists after removal attempt, you may wish to verify or manually remove."
        }
        Write-Host "Uninstall batch script removal attempt completed."
        If ( (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceName "is still installed."
        } else {
            Write-Host "The service" $ServiceName "is confirmed to not exist."
        }
    } elseif ($Force) {
        Write-Host "Uninstall batch script does not exist and -Force flag is set. Running alternative cleanup script..."
        $UninstallReturnValue = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $alternativeScript" -Wait
        Write-Host "Alternative cleanup script removal attempt completed."
        If ( (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceName "is still installed."
        } else {
            Write-Host "The service" $ServiceName "is confirmed to not exist."
        }
    } else {
        Write-Host "Uninstall batch script does not exist, nothing else done. To try built-in removal anyway, re-run adding -Force flag."
    }

    Write-Host "Uninstallation attempt completed."

    # End Uninstallation by quitting
    exit $UninstallReturnValue
}

##### UNINSTALL/REMOVAL of VERSION 4 AGENT
# Force uninstall of V4 agent if the V4 agent is installed, before deploying the V3 agent.
If ( (Get-Service $ServiceNameV4 -ErrorAction SilentlyContinue) ) {
    $UninstallNew = $true
}
##### UNINSTALL/REMOVAL of VERSION 4 AGENT
if($UninstallNew) {
    Write-Host "Uninstalling ConnectSecure CyberCNS Lightweight Agent from version 4..."
    If ( (Get-Service $ServiceNameV4 -ErrorAction SilentlyContinue) ) {
        Write-Host "The service" $ServiceNameV4 "is installed (V4 agent) or force-remove is requested. Uninstalling."
    }

    # Run Uninstall Batch Script If It Exists
    $UninstallReturnValue = 0
    $uninstallBatPaths = @("${Env:ProgramFiles(x86)}\CyberCNSAgent\uninstall.bat","$Env:Programfiles\CyberCNSAgent\uninstall.bat")
    $uninstallBatPath = "${Env:ProgramFiles(x86)}\CyberCNSAgent\uninstall.bat"
    foreach ($path in $uninstallBatPaths) {
        Write-Host "Checking if path exists: $path"
        if (Test-Path $path) {
            $uninstallBatPath = $path
            Write-Host "(it does)"
        } else {
            Write-Host "(it does not)"
        }
    }
    $alternativeScript = @'
echo Running alternative cleanuip script
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
        if(Test-Path $uninstallBatPath) {
            Write-Host "Uninstall batch script still exists after removal attempt, you may wish to verify or manually remove."
        }
        Write-Host "Uninstall batch script removal attempt completed."
        If ( (Get-Service $ServiceNameV4 -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceNameV4 "is still installed."
        } else {
            Write-Host "The service" $ServiceNameV4 "is confirmed to not exist."
        }
    } elseif ($Force) {
        Write-Host "Uninstall batch script does not exist and -Force flag is set. Running alternative cleanup script..."
        $UninstallReturnValue = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $alternativeScript" -Wait
        Write-Host "Alternative cleanup script removal attempt completed."
        If ( (Get-Service $ServiceNameV4 -ErrorAction SilentlyContinue) ) {
            Write-Host "The service" $ServiceNameV4 "is still installed."
        } else {
            Write-Host "The service" $ServiceNameV4 "is confirmed to not exist."
        }
    } else {
        Write-Host "Uninstall batch script does not exist, nothing else done. To try built-in removal anyway, re-run adding -Force flag."
    }

    Write-Host "Uninstallation attempt of V4 agent completed."

    # # End Uninstallation by quitting
    # exit $UninstallReturnValue
}

##### INSTALLATION

If ( !$Force -and (Get-Service $ServiceName -ErrorAction SilentlyContinue) ) {
    Write-Host "The service" $ServiceName "is already installed. Retry with -Force to attempt install anyway."
    exit 0
}

if(!$CompanyID) {
    $CompanyID = Ninja-Property-Get $customCompanyID
}
if(!$ClientID) {
    $ClientID = Ninja-Property-Get $customClientID
}
if(!$ClientSecret) {
    $ClientSecret = Ninja-Property-Get $customClientSecret
}

# if(!$Uninstall) {
Write-Host "Company ID from $customCompanyID Custom Field: $CompanyID"
Write-Host "Client ID from $customClientID Custom Field: $ClientID"

if ($CompanyID -Match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") {
    write-host "Company ID passed basic format validation..."
} else {
    write-host "No Company ID value provided or invalid format, correctly set via script field, arguement, or custom field."
    write-host "Format should be: xxxxxxxx-xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (where all x's are hexadecimal characters)"
    exit 1
}
if ($ClientID -Match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") {
    write-host "Client ID passed basic format validation..."
} else {
    write-host "No Client ID value provided or invalid format, correctly set via script field, arguement, or custom field."
    write-host "Format should be: xxxxxxxx-xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (where all x's are hexadecimal characters)"
    exit 1
}
if ($ClientSecret -Match "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") {
    write-host "Client Secret passed basic format validation..."
} else {
    write-host "No Client Secret value provided or invalid format, correctly set via script field, arguement, or custom field."
    write-host "Format should be: xxxxxxxx-xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (where all x's are hexadecimal characters)"
    exit 1
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

if($Once) {
    Write-Host "Running one-time Windows device scan without installing agent."
    $destination = "$InstallLocation\$InstallFilename.exe"
    if (Test-Path $destination) {
        Remove-Item $destination -Force
    }
    $source = (Invoke-RestMethod -Method "Get" -URI "https://configuration.mycybercns.com/api/v3/configuration/agentlink?ostype=windows");
    Invoke-WebRequest -Uri $source -OutFile $destination
    $exitCode = [Diagnostics.Process]::Start($destination,"-c $CompanyID -a $ClientID -s $ClientSecret -b $BaseURL -e $CompanyName -m Scan").WaitForExit(3600)
    # Set destination file to be deleted on computer reboot (when it'll be done being used)
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\$destination`0`0") -type MultiString -Force | Out-Null
} else {
    Write-Host "Installation type: $TYPE proceeding"
}

if($TYPE -eq 'EXE') {
    # Install Lightweight Agent EXE
    $source = (Invoke-RestMethod -Method "Get" -URI "https://configuration.mycybercns.com/api/v3/configuration/agentlink?ostype=windows")
    $destination = "$InstallLocation\$InstallFilename.exe"
    Invoke-WebRequest -Uri $source -OutFile $destination
    $exitCode = [Diagnostics.Process]::Start($destination,"-c $CompanyID -a $ClientID -s $ClientSecret -b $BaseURL -e $CompanyName -i LightWeight").WaitForExit(600)
    # Set destination file to be deleted on computer reboot (when it'll be done being used)
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\$destination`0`0") -type MultiString -Force | Out-Null
    Write-Host "Installation via $TYPE was initiated."
} elseif($TYPE -eq 'MSI') {
    # Install Lightweight Agent MSI
    $source = (Invoke-RestMethod -Method "Get" -URI "https://configuration.mycybercns.com/api/v3/configuration/agentlink?ostype=windows&msi_required=true")
    $destination = "$InstallLocation\$InstallFilename.msi"
    Invoke-WebRequest -Uri $source -OutFile $destination
    $msiArguments = @"
/i "$destination" /quiet WRAPPED_ARGUMENTS="-c $CompanyID -a $ClientID -s $ClientSecret -b $BaseURL -e $CompanyName -i LightWeight"
"@
    Start-Process msiexec -ArgumentList $msiArguments -Wait
    # Set destination file to be deleted on computer reboot (when it'll be done being used)
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $($((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) + "\??\$destination`0`0") -type MultiString -Force | Out-Null
    Write-Host "Installation via $TYPE was initiated."
}
