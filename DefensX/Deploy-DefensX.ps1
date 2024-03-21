<#
.SYNOPSIS
    Install, Upgrade, or Uninstall DefenseX provided a valid DefensX KEY from the PowerShell Deployment for a given tenant.

.DESCRIPTION
    Install, Upgrade, or Uninstall DefenseX provided a valid DefensX KEY from the PowerShell Deployment for a given tenant with KEY provided via parameter, environment variables, or NinjaRMM Custom Field.
  
    With no parameters, installation will be attempted, but only if the DefenseX servies does not exist. Version will be ignored without the -Upgrade parameter.

    This script uses NinjaRMM Custom Fields to get the KEY by default (see CONFIG), but they can be passed in as parameters or Script Variables (environment variables) if desired.

    The Ninja Custom Field should be a single string with either a 16-character (alphanumeric) Short KEY or 224-character Long KEY (alphanumeric plus limited symbols such as -, _, and period), pulled out of the DefensX Deployments RMM field for a given client. The short key is recommended, configurable from the RMM popup.
    
    As long as you pass in a -KEY parameter, or provide a KEY environment variable, this script will function entirely separate from NinjaRMM.
    
    The additional parameters in the param() array that are not indidually doucumented are all switches that are true if they exist and false if they are not provided. They can be checkboxes in NinjaRMM Script Variables (environment variables) or passed in on the command line, and will be converted to a 1 or 0 and passed to the appropriate argument to the MSI installer, as defined in the DefensX documentation and user interface. The argument names are simplified for ease of typing, and don't correspond preciesly to the MSI arguments, but the mapping should be relatively simple to understand.
 
.PARAMETER KEY
    If this parameter is passed to the DefensX PowerShell Deployment Script, it will be used instead of NinjaRMM Custom Fields. This key is located in the the DefensX Customer Console under Policies->Policy Groups->Deployments->RMM button, then turn on "Use Short Deployment Key" and then get the 16-character key at the very end of the command after the equals sign. The parameter should also accept the default 224-character key, but the 16-character short key is recommended. Required for install or upgrade unless supplied via $env:KEY (like via Ninja Script Variables) or NinjaRMM Custom Field. Not required for uninstall or Info check.

.PARAMETER Upgrade
    TODO (need to test, should work): Install Reinstall/Upgrade DefensX if it's already installed and at an older version than the current version available online, or if it's not installed at all (will also install from scratch, just won't quit if it's already installed and will check if it's outdated and upgrade if it is).

    If the most current version is already installed, the agent will not be reinstalled unless you add the -Force parameter.

.PARAMETER Force
    Add to the -Upgrade parameter to attempt to reinstall even if the same version is already installed.

.PARAMETER Uninstall
    If DefensX is already installed, uninstall it, using the uninstall GUID from the Windows Registry. Other parameters will be ignored.

.PARAMETER Info
    Confirm installation status and print version info, then exit. Also queries the version number of the cloud installer file and reports the current installer version. Other parameters will be ignored.
    
.PARAMETER SpecificVersion
    If you provide a specifica installer version that the DefensX cloud has available to download, the installation will use this version of the MSI file to install the agent. This is an untested feature without much error checking or reporting, but uses the installer version URL provided directly in DefensX documentation.

.EXAMPLE
    Deploy-DefensX.ps1
.EXAMPLE
    Deploy-DefensX.ps1 -KEY 'yourKEY'
.EXAMPLE
    Deploy-DefensX.ps1 -KEY 'yourKEY' -Upgrade
.EXAMPLE
    Deploy-DefensX.ps1 -KEY 'yourKEY' -Upgrade -Force
.EXAMPLE
    Deploy-DefensX.ps1 -Info
.EXAMPLE
    Deploy-DefensX.ps1 -KEY 'yourKEY' -SpecificVersion 1.9.70
.EXAMPLE
    Deploy-DefensX.ps1 -Uninstall
.EXAMPLE
    Deploy-DefensX.ps1 -Upgrade

.LINK
    https://github.com/dszp/NinjaOne-Scripts/tree/main/DefensX

.NOTES
Version 0.1.0 - 2024-03-21 - by David Szpunar - Initial released version
Version 0.0.3 - 2024-03-21 - by David Szpunar - Updated comments and formatting to better describe where to obtain the KEY, refactor some logic (internal)
Version 0.0.2 - 2024-03-21 - by David Szpunar - Updated comment docs and made slight code adjustments (internal)
Version 0.0.1 - 2024-03-20 - by David Szpunar - Initial version by David Szpunar (internal)
#>
[CmdletBinding()]
param(
    [string] $KEY,
    [switch] $Upgrade,
    [switch] $Force,
    [switch] $Uninstall,
    [switch] $Info,
    [switch] $EnablePrivateChrome,
    [switch] $EnablePrivateEdge,
    [switch] $EnablePrivateFirefox,
    [switch] $DisableLogonUser,
    [switch] $EnableIamUser,
    [switch] $HideFromAddRemove,
    [switch] $DisableUninstall,
    [version] $SpecificVersion
)

##### CONFIG #####
# The page name (such as Deployments) for the custom Ninja Documentation page with the KEY field in it.
# Leave commented or set blank if you're using Device/Role Custom Fields and NOT Documentation Custom Fields, or if you aren't using NinjaRMM custom fields at all.
# $NinjaCustomDocumentationPage = 'Deployments'

# The custom field name of the Ninja Custom field that contains the KEY from the DefensX Customer Console under Poilicies->Policy Group->sDeployments->RMM button, then 
# turn on "Use Short Deployment Key" and then get the 16-character key at the very end of the command after the equals sign, then place it in this Custom Field for each 
# customer/location/device.
# This can be a Device or Role Custom Field, or a Documenation Custom Field (if using the Documentation Template above), as long as Automation Read access is enabled.
# Leave BLANK/empty string (or comment it out) if you're passing in the -KEY parameter to the script directly rather than using NinjaRMM custom fields.
$NinjaCustomFieldName = 'defensxKey'
##### END CONFIG #####

#Service Name and Application Name
$ServiceName = "DefensX Agent"
$Application = "DefensX Agent"

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

##### FUNCTIONS #####
function Get-DefensXCurrentVersion {
    # TODO
    <#
  .SYNOPSIS
      Given the result of WebResponseObject with the DefensX agent, determine the current version of DefensX from the file name.
  .DESCRIPTION
      Given the result of WebResponseObject with the DefensX agent, determine the current version of DefensX from the file name.
  .EXAMPLE
      $version = Get-DefensXCurrentVersion
  #>
    [CmdletBinding()]
    param(
    
    )

    $uri = "https://cloud.defensx.com/defensx-installer/latest.msi"
    Write-Verbose "URI for latest version information: $uri"

    try {
        # Manually invoke a web request
        $Request = [System.Net.WebRequest]::Create($uri)
        $Request.AllowAutoRedirect = $false
        $Response = $Request.GetResponse()
        # Write-Verbose "Response Headers returned from version check:"
        # Write-Verbose ($Response.Headers | Format-List * | Out-String)
        # Write-Verbose "Location header value: $($Response.Headers['Location'])"
    }
    catch {
        Write-Error 'Error: Web request failed.' -ErrorAction Stop
    }
    Write-Verbose "RESPONSE CODE: $($Response.StatusCode.value__)"
    if ($Response.StatusCode.value__ -eq '307' -or $Response.StatusCode.value__ -eq '302') {
        $redirectUrl = $($Response.Headers['Location'])
        Write-Verbose "Redirect URL: $RedirectUrl"
        $FileName = [System.IO.Path]::GetFileName($redirectUrl)
        Write-Verbose "FileName: $FileName"
        if (-not $FileName) { Write-Error 'Error: Failed to resolve file name from URI.' -ErrorAction Stop }
        $FileName -match 'DefensXInstaller\-(\d+\.\d+\.\d+)\.msi' | Out-Null
        $version = $matches[1]
        Write-Verbose "Version: $version"
        return $version
    }
    return $null
}

function Show-DefensXCurrentInfo {
    $AgentInstall=("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | % { Get-ChildItem -Path $_ | % { Get-ItemProperty $_.PSPath } | ? { $_.DisplayName -match "$Application" } }
    $AgentVersion = $AgentInstall.DisplayVersion
    $AgentGUID = $AgentInstall.PSChildName
  
    if ($AgentInstall) {
        Write-Host "$Application is currently installed."
        Write-Host "Agent GUID: $AgentGUID"
        Write-Host "Installed version: $AgentVersion"
    }
    else {
        Write-Host "$Application is not installed."
    }
}

function Check-DefensXKey {
    param(
        [string] $KEY
    )
    if ([string]::IsNullOrWhiteSpace($KEY)) {
        # Make sure this Documentation form, template, and field exist, are script readable, and have the corresponding client KEY saved!
        if ([string]::IsNullOrWhiteSpace($NinjaCustomDocumentationPage)) {
            if (![string]::IsNullOrWhiteSpace($NinjaCustomFieldName)) {
                Write-Host "Attempting to retreive Key from NinjaRMM Custom Field..."
                $KEY = Ninja-Property-Get $NinjaCustomFieldName
            }
            else {
                Write-Host "Ninja Custom Field Name not provided, not attempting to retrieve KEY from NinjaRMM, must use -Key parameter."
            }
        }
        else {
            Write-Host "Attempting to retreive KEY from NinjaRMM Documentation Custom Field..."
            $KEY = Ninja-Property-Docs-Get-Single $NinjaCustomDocumentationPage $NinjaCustomFieldName
        }
    }
    Write-Verbose "KEY Value: $KEY"

    #write-host "DefensX Key from Documentation Field: $KEY"
    # LEN 224 (alphanumeric plus _ and . and -) OR 16 (alphanumeric)
    $regex = "([a-zA-Z0-9]{16})|(\S{224})"
    $KEY -match $regex | Out-Null
    if ($Matches) {
        $KEY = $Matches[1]

        #write-host "Installing with KEY=" $KEY
        $KEYmasked = $KEY.SubString(0, 10) + "******"
        Write-Host "Installing with KEY:" $KEYmasked

        Write-Host "(identifiers partially masked for log)"
    }
    else {
        Write-Host "Nothing found in DefensX KEY field that matches a short or long deployment key, can't deploy for this tenant...Bye."
        exit 1
    }
    return $KEY
}

function Install-DefensX {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $Key
    )

    # Preconfigure variables for installer arguments from parameters passed to script:
    if($EnablePrivateChrome) {
        $PRIV_CHROME = 0
    } else {
        $PRIV_CHROME = 1
    }

    if($EnablePrivateEdge) {
        $PRIV_EDGE = 0
    } else {
        $PRIV_EDGE = 1
    }

    if($EnablePrivateFirefox) {
        $PRIV_FIREFOX = 0
    } else {
        $PRIV_FIREFOX = 1
    }

    if($DisableLogonUser) {
        $ENABLE_LOGON_USER = 0
    } else {
        $ENABLE_LOGON_USER = 1
    }

    if($EnableIamUser) {
        $ENABLE_IAM_USER = 1
    } else { 
        $ENABLE_IAM_USER = 0
    }

    if($HideFromAddRemove) {
        $SYSTEM_COMPONENT = 1
    } else {
        $SYSTEM_COMPONENT = 0
    }

    if($DisableUninstall) {
        $DISABLE_UNINSTALL = 1
    } else {
        $DISABLE_UNINSTALL = 0
    }

    # Download the latest installer, or a specific version instead if the -SpecificVersion parameter is used
    if($SpecificVersion) {
        Write-Verbose "Attempting to download and install specific version: $SpecificVersion"
        $url = "https://cloud.defensx.com/defensx-installer/latest.msi?v=$SpecificVersion"
    } else {
        Write-Verbose "Attempting to download and install latest version"
        $url = "https://cloud.defensx.com/defensx-installer/latest.msi"
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
    
    $ErrorActionPreference = "Stop"
    $InstallerFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".msi")
    (New-Object System.Net.WebClient).DownloadFile($url, $InstallerFile)
    $InstallerLogFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".log")
    $Arguments = " /c msiexec /i `"$InstallerFile`" /qn /norestart /l*v `"$InstallerLogFile`" KEY=$Key ENABLE_LOGON_USER=$ENABLE_LOGON_USER ENABLE_IAM_USER=$ENABLE_IAM_USER EDGE_DISABLE_PRIVATE_WINDOW=$PRIV_EDGE CHROME_DISABLE_PRIVATE_WINDOW=$PRIV_CHROME FIREFOX_DISABLE_PRIVATE_WINDOW=$PRIV_FIREFOX DISABLE_UNINSTALL=$DISABLE_UNINSTALL SYSTEM_COMPONENT=$SYSTEM_COMPONENT /q"
    Write-Verbose "Installer Arguments: $Arguments"
    Write-Host "Installer Log File: $InstallerLogFile"
    $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
    if ($Process.ExitCode -ne 0) {
        Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 100
        Write-Host "Current cloud installer version for reference: " (Get-DefensXCurrentVersion | Out-String)
    }
    Write-Host "Exit Code: $($Process.ExitCode)"
    Write-Host "ComputerName: $($env:ComputerName)"

    # Return the exit code from the installation as the script exit code:
    exit $($Process.ExitCode)
}

function Uninstall-DefensX {
    $AgentInstall=("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | % { Get-ChildItem -Path $_ | % { Get-ItemProperty $_.PSPath } | ? { $_.DisplayName -match "$Application" } }
    $AgentVersion = $AgentInstall.DisplayVersion
    $AgentGUID = $AgentInstall.PSChildName
    # $UninstallString = "$($AgentInstall.UninstallString) /quiet /norestart"
    $UninstallString = "MsiExec.exe /x$AgentGUID /quiet /norestart"
    Show-DefensXCurrentInfo

    if ($AgentInstall) {
        Write-Host "Uninstalling now."
        Write-Verbose "Uninstall String: $UninstallString"
        $Process = Start-Process cmd.exe -ArgumentList "/c $UninstallString" -Wait -PassThru
        if ($Process.ExitCode -eq 1603) {
            Write-Host "Uninstallation attempt failed with error code: $($Process.ExitCode). Please review manually."
            Write-Host "Hint: This exit code likely requires the system to reboot prior to installation."
        }
        elseif ($Process.ExitCode -ne 0) {
            Write-Host "Uninstallation attempt failed with error code: $($Process.ExitCode). Please review manually."
        }
        else {
            Write-Host "Uninstallation attempt completed."
        }
        exit $($Process.ExitCode)
    }
    exit 0
}

##### BEGIN SCRIPT #####

if ($Info) {
    Show-DefensXCurrentInfo
    Write-Host "Current cloud installer version: " (Get-DefensXCurrentVersion | Out-String)
    exit 0
}

if ($Uninstall) {
    Uninstall-DefensX $UninstallInfo
    exit 0
}

$KEY = Check-DefensXKey -Key $KEY

if ($Upgrade) {
    $AgentInstall=("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | % { Get-ChildItem -Path $_ | % { Get-ItemProperty $_.PSPath } | ? { $_.DisplayName -match "$Application" } }
    $AgentVersion = $AgentInstall.DisplayVersion
    if (!$AgentVersion) {
        Write-Host "DefensX is NOT currently installed. Attempting installation now."
        Install-DefensX -Key $KEY
        exit 0
    }
    $CurrentVersion = Get-DefensXCurrentVersion
    if (($AgentVersion -ne $CurrentVersion) -or $Force) {
        Write-Host "Installed Version of DefensX: " $AgentVersion
        Write-Host "Installing current version:" $CurrentVersion
        Install-DefensX -Key $KEY
    }
    else {
        Write-Host "DefensX is already up-to-date with version:" $AgentVersion
        Write-Host "Verified that current verison on server is:" $CurrentVersion
        Write-Host "Installation date: " $AgentInstall.InstallDate
        Write-Host "Not installing since already up to date, use -Force to reinstall anyway."
    }
    exit 0
}

# Deafult to install if no other option specified and the service is not already installed
If ( Get-Service $ServiceName -ErrorAction SilentlyContinue ) {
    Write-Host "The service" $ServiceName "is Already Installed...Bye." 
    exit 0
}
else {
    Install-DefensX -Key $KEY
    exit 0
}
