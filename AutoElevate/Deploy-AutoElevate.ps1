<# Deploy-AutoElevate.ps1
Deploy (or Remove) AutoElevate Agent to Windows systems.

Review the CONFIG section of the script before deploying!

Optionally create one or more Ninja Custom Fields, all standard text fields, with Automation Read permissions, with the names listed in the CONFIG section under "NinjaRMM Custom Field Names" (or ajdust these variables to match your custom field names). If you aren't using any of these custom fields, set the field names to a blank string. Parameters or Script Variables, if you provide them, will override any values pulled from custom fields.

You can mix and match, using some custom fields, some Script Variables/Parameters (which will override matching custom fields), and some defaults.

The arguments to this script are defined at: 
https://support.cyberfox.com/115000883892-New-to-AutoElevate-START-HERE/115003703811-System-Agent-Installation

Most of the arguements are passed to the MSI installer, and the defaults 

This script accepts the following arguments, which may also be set as Custom Fields or Script Variables:
    -LicenseKey (string)
        Pull from custom field "autoelevateLicenseKey" (or as defined in CONFIG) if not provided as parameter or Script Variable.

    -CompanyName (string)
        Default to the Ninja Organization Name, or pull from custom field "autoelevateCompanyName" (or as defined in CONFIG).

    -CompanyInitials (string)
        Pull from custom field "autoelevateCompanyInitials" (or as defined in CONFIG), or parameter/script variable. This is an OPTIONAL setting and can be left blank/excluded, per AutoElevate documentation.
        
    -LocationName (string)
        Default to the Ninja Organization Location Name, or Pull from custom field "autoelevateLocationName"
    
    -AgentMode (string, optional)
        One of the following string values as defined in the AutoElevate documentation, or pull from custom field "autoelevateAgentMode" (or as defined in CONFIG), or leave blank to assume default from AutoElevate documentation OR to not change the existing value if (re)installing/upgrading an already-deployed agent with -Force:
            audit (default)
            live
            policy

    -BlockerMode (string, optional)
        One of the following string values as defined in the AutoElevate documentation, or pull from custom field "autoelevateBlockerMode" (or as defined in CONFIG), or leave blank to assume default from AutoElevate documentation OR to not change the existing value if (re)installing/upgrading an already-deployed agent with -Force:
            disabled (default)
            live
            audit

    -Force (boolean/checkbox)
        Adding this switch or Script Variables Checkbox will attempt (re)installation even if the service already exists on the system.

    -Uninstall (boolean/checkbox)
        Use this switch or Script Variables Checkbox to attempt to uninstall the agent if it's currently installed on the system. If it fails using the registry MSI Uninstall command, it will download the installation MSI and attempt to uninstall with it. If that fails, it's up to you to troubleshoot, but first try a reboot and attempt uninstall again.
    
    -Verbose
        Pass the -Verbose parameter to output additional debugging information when running the script. Do not use this as a Script Variable, only a Parameter. NOTE: Prints details such as the license key or other parameter/custom field values to STDOUT.
    
Output from each command is provided for feedback. Every parameter or switch can be set via Script Variables, and the first four also support Custom Fields.
With minor adjustment, they could also use NinjaRMM Custom Documentation Fields.

Version 0.0.1 - 2024-03-05 - Initial Version by David Szpunar
Version 0.0.2 - 2024-03-05 - Added AgentMode switch, fixed several logic errors in first draft, MSI uninstallation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string] $LicenseKey,
    [Parameter(Mandatory = $false)][string] $CompanyName,
    [Parameter(Mandatory = $false)][string] $CompanyInitials,
    [Parameter(Mandatory = $false)][string] $LocationName,
    [Parameter(Mandatory = $false)][string] $AgentMode,
    [Parameter(Mandatory = $false)][string] $BlockerMode,
    [switch] $Force,
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
if (!$CompanyName) {
    # Default to the Ninja Organization Name, if not passed in via argument
    $CompanyName = $env:NINJA_ORGANIZATION_NAME
}
if (!$LocationName) {
    # Default to the Ninja Organization Location Name, if not passed in via argument
    $LocationName = $env:NINJA_LOCATION_NAME
}

$InstallLocation = $env:TEMP        # Temporary downloaded installer location (can leave as temp folder)
$InstallFilename = 'AutoElevate.msi'  # Temporary downloaded installer filename (can leave as-is)

# NinjaRMM Custom Field Names (third can be secure, all must have Script Read permissions) - leave blank or delete to ignore/not use
$customLicenseKey = 'autoelevateLicenseKey'
$customCompanyName = 'autoelevateCompanyName'
$customCompanyInitials = 'autoelevateCompanyInitials'
$customLocationName = 'autoelevateLocationName'
$customAgentMode = 'autoelevateAgentMode'
$customBlockerMode = 'autoelevateBlockerMode'

# Service Name (from Windows Services list)
$ServiceName = "AutoElevate Agent"

# Application Name (from Add/Remove Programs)
$AppName = "AutoElevate"

# Agent Installer URL
$URL = "https://autoelevate-installers.s3.us-east-2.amazonaws.com/current/AESetup.msi"
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

##### FUNCTIONS
function Uninstall-App-ViaMsi {
    $ErrorActionPreference = "Stop"
    # $InstallerFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".msi")
    $InstallerFile = "$InstallLocation\$InstallFilename.msi"
    (New-Object System.Net.WebClient).DownloadFile($url, $InstallerFile)
    $InstallerLogFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".log")
    Write-Verbose "Installer File for Uninstallation: $InstallerFile"
    # LICENSE_KEY="123456789ABCDEFGYOURLICENSEKEYHERE" COMPANY_NAME="Contoso, Inc." COMPANY_INITIALS="CI" LOCATION_NAME="Main Office" AGENT_MODE="live" BLOCKER_MODE="disabled"
    $Arguments = " /c msiexec /x `"$InstallerFile`" /qn /norestart /l*v `"$InstallerLogFile`" REBOOT=REALLYSUPPRESS "
    Write-Host "UninstallerLogFile: $InstallerLogFile"
    Write-Verbose "Uninstaller Arguments: $Arguments"
    $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
    if ($Process.ExitCode -ne 0) {
        Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 100
    }
    Write-Host "Exit Code: $($Process.ExitCode)"
    Write-Host "ComputerName: $($env:ComputerName)"

    # Return the exit code from the installation as the script exit code:
    exit $($Process.ExitCode)
}


function Uninstall-App {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $AppName
    )
    $InstallInfo = (
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* `
        | Select-Object DisplayName, DisplayVersion, UninstallString, Publisher, InstallDate, InstallLocation `
        | Where-Object { $_.DisplayName -eq $AppName }) + (
        Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
        | Select-Object DisplayName, DisplayVersion, UninstallString, Publisher, InstallDate, InstallLocation `
        | Where-Object { $_.DisplayName -eq $AppName })
    $AppVersion = $InstallInfo.DisplayVersion
    Write-Verbose "Installed Version: $AppVersion"
    $UninstallString = "$(($InstallInfo.UninstallString).Replace('/I{', '/X{')) /quiet /norestart"
    Write-Verbose "Uninstall String: $UninstallString"
  
    if ($InstallInfo) {
        Write-Host "Uninstalling now."
        Write-Verbose $InstallInfo | Format-List
        $Process = Start-Process cmd.exe -ArgumentList "/c $UninstallString" -Wait -PassThru
        if ($Process.ExitCode -eq 1603) {
            Write-Host "Uninstallation attempt failed with error code: $($Process.ExitCode). Please review manually."
            Write-Host "Trying to install via MSI..."
            Uninstall-App-ViaMsi
        }
        elseif ($Process.ExitCode -ne 0) {
            Write-Host "Uninstallation attempt failed with error code: $($Process.ExitCode). Trying to uninstall with MSI..."
            Uninstall-App-ViaMsi
        }
        else {
            Write-Host "Uninstallation attempt completed without error."
        }
        exit $($Process.ExitCode)
    }
    else {
        Write-Host "The application" $AppName "is not installed based on a search of the registry. Quitting"
        exit 0
    }
    exit 0
}

function Install-App {
    $ErrorActionPreference = "Stop"
    # $InstallerFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".msi")
    $InstallerFile = "$InstallLocation\$InstallFilename"
    (New-Object System.Net.WebClient).DownloadFile($url, $InstallerFile)
    $InstallerLogFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".log")
    Write-Verbose "Installer File: $InstallerFile"
    # EXAMPLE: LICENSE_KEY="123456789ABCDEFGYOURLICENSEKEYHERE" COMPANY_NAME="Contoso, Inc." COMPANY_INITIALS="CI" LOCATION_NAME="Main Office" AGENT_MODE="audit" BLOCKER_MODE="disabled"
    $Arguments = " /c msiexec /i `"$InstallerFile`" /qn /norestart /l*v `"$InstallerLogFile`" REBOOT=REALLYSUPPRESS LICENSE_KEY=`"$LicenseKey`" COMPANY_NAME=`"$CompanyName`" LOCATION_NAME=`"$LocationName`""
    if(!([String]::IsNullOrEmpty($AgentMode))) {
        $Arguments += " AGENT_MODE=`"$AgentMode`""
    }
    if(!([String]::IsNullOrEmpty($BlockerMode))) {
        $Arguments += " BLOCKER_MODE=`"$BlockerMode`""
    }
    if(!([String]::IsNullOrEmpty($CompanyInitials))) {
        $Arguments += " COMPANY_INITIALS=`"$CompanyInitials`""
    }
    Write-Host "InstallerLogFile: $InstallerLogFile"
    Write-Verbose "Installer Arguments: $Arguments"
    $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
    if ($Process.ExitCode -ne 0) {
        Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 100
    }
    Write-Host "Exit Code: $($Process.ExitCode)"
    Write-Host "ComputerName: $($env:ComputerName)"

    # Return the exit code from the installation as the script exit code:
    exit $($Process.ExitCode)
}

##### SCRIPT LOGIC

if ($Uninstall) {
    Write-Verbose "Attemtping app uninstall."
    Uninstall-App $AppName
    exit 0
}

if (!$LicenseKey -and !([string]::IsNullOrEmpty($customLicenseKey))) {
    $LicenseKey = Ninja-Property-Get $customLicenseKey
    Write-Host "License Key from $customCompanyName Custom Field: [masked for output]"
}
If (!$CompanyName -and !([string]::IsNullOrEmpty($customCompanyName))) {
    $CompanyName = Ninja-Property-Get $customCompanyName
    Write-Host "Company Name From $customLicenseKey Custom Field: $CompanyName"
}
If (!$CompanyInitials -and $null -eq $customCompanyInitials) {  # Blank is OK for this optional field
    $CompanyInitials = Ninja-Property-Get $customCompanyInitials
    Write-Host "Company Initials from $customCompanyInitials Custom Field: $CompanyInitials"
}
if (!$LocationName -and !([string]::IsNullOrEmpty($customLocationName))) {
    $LocationName = Ninja-Property-Get $customLocationName
    Write-Host "Location Name from $customLocationName Custom Field: $LocationName"
}
if (!$AgentMode -and !([string]::IsNullOrEmpty($customAgentMode))) {
    $AgentMode = Ninja-Property-Get $customAgentMode -ErrorAction SilentlyContinue
    Write-Host "Location Name from $customAgentMode Custom Field: $AgentMode"
}
if (!$BlockerMode -and !([string]::IsNullOrEmpty($customBlockerMode))) {
    $BlockerMode = Ninja-Property-Get $customBlockerMode -ErrorAction SilentlyContinue
    Write-Host "Location Name from $customBlockerMode Custom Field: $BlockerMode"
}
if ($AgentMode -ne '' -and $AgentMode -ne "live" -and $AgentMode -ne "policy" -and $AgentMode -ne "audit") {
    $AgentMode = ""   # Default to audit if not explicitly set (also default if not provided to installer) (use documented default)
}
if ($BlockerMode -ne '' -and $BlockerMode -ne "disabled" -and $BlockerMode -ne "live" -and $BlockerMode -ne "audit") {
    $BlockerMode = ""   # Default to disabled if not explicitly set (use documented default)
}

if (!$Uninstall -and ([string]::IsNullOrEmpty($LicenseKey) -or [string]::IsNullOrEmpty($CompanyName) -or [string]::IsNullOrEmpty($LocationName))) {
    Write-Host "One or more required fields (LicenseKey, CompanyName, LocationName) are empty. Exiting."
    exit 1
}

$IsInstalled = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $AppName }) + (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $AppName }) 

If ( !$Force -and ((Get-Service $ServiceName -ErrorAction SilentlyContinue) -or $IsInstalled) ) {
    Write-Host "The service $ServiceName or app $AppName is already installed. Retry with -Force to attempt install anyway."
    exit 0
}

# Install if we get here and have not already completed
Install-App
