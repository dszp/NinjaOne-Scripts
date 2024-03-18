<# Deploy-Stairwell-Forwarder-Windows-Shareable.ps1

FOR NINJAONE DISCORD SHARING RELEASE - removed direct URL references to Stairwell.com site/downloads, though none of 
    them are behind authentication I don't have direct permission to share so you'll need to obtain yourself.
by David Szpunar, Servant 42, Inc.
No warranty or suitability for purpose implied, use at your own risk.
Various parts of this script have been collected from elsewhere and are not entirely original.

Version 1.0.3 - 2024-03-18 - Update Script Variables handling code to latest version with small adjustments
Version 1.0.2 - 2023-11-13 - Update Script Variables handling to new generalized parsing method
Version 1.0.1 - 2023-11-10 - Add Script Variables support and -Force switch option
Version 1.0.0 - 2023-08-24 - Fixes token validation from custom fields (didn't work previously). All current features 
    working and tested across multiple Windows systems.
Version 0.2.0 - 2023-08-23 - Adds working -Uninstall flag as long as downloaded version matches installed version 
    (the removal is done by downloading the installer and passing uninstallation flags)
Version 0.1.0 - 2023-08-23 - Initial deployment script for Stairwell Windows Inception Forwarder 
    Agent and, by default, performs an initial breach assessment scan.

Pass the argument -NoScan or -NoInitialScan to skip the initial full breach assessment scan and only add files as 
they are written, modified, or executed.
#>
param(
    [switch] $NoInitialScan,
    [switch] $NoScan,
    [switch] $Force,
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

###########
# EDIT ME
###########
<#
    Create two custom fields with the below two field names, and for each Organization, add values to the two fields from the 
    Stairwell portal before running this script. Script will fail if the custom fields don't have validly-formatted values.
#>

# The custom field containing the Auth Token of the Stairwell tenant
# (Stairwell knowledgebase contains directions for locating this information)
$customAuthToken = 'stairwellAuthToken'

# The custom field containing the Environment ID of the Stairwell tenant
# (Stairwell knowledgebase contains directions for locating this information)
$customEnvironmentId = 'stairwellEnvironmentId'

# Stairwell Download Path for Bundled Installer:
# See Stairwell knoweldgebase for Download link to copy (prefer Bundle with .NET)
# (URL may change for new version releases, requriing update or hosting installer elsewhere.)
$DownloadURL = ""

#Service Name (service to check to verify if the agent is already installed)
$ServiceName = "Inception Forwarder"

#Installer Name (locally saved filename for installer)
$InstallerName = "StairwellInceptionForwarderBundle.exe"

# Also go down and edit the $ArgumentList below, if necessary for this agent, which is set after the tokens are validated below.
###########
# EDIT EDIT
###########

###########
# CUSTOM FIELD CHECKS
###########

if(!$Uninstall) {
    $AuthToken = Ninja-Property-Get $customAuthToken
    # Write-Host "Auth Token from $customAuthToken Custom Field: $AuthToken"
    if ($AuthToken -Match "^[A-Z0-9]{52}$") {
        write-host "AuthToken from custom field $customAuthToken passed basic format validation, continuing to install using this value."
    } else {
        write-host "No Auth Token field defined or invalid format, set valid $customAuthToken value in custom fields."
        write-host "Format should be: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX (52 capital alphanumeric characters long)"
        exit 1
    }

    $EnvironmentId = Ninja-Property-Get $customEnvironmentId
    write-host "Environment ID from $customEnvironmentId Custom Field: $EnvironmentId"
    if ($EnvironmentId -Match "^[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{8}$") {
        write-host "Environment ID passed basic format validation, continuing to install using this value."
    } else {
        write-host "No Environment ID field defined or invalid format, set valid $customEnvironmentId value in custom fields."
        write-host "Format should be: XXXXXX-XXXXXX-XXXXXX-XXXXXXXX (6-6-6-6 capital alphanumeric characters long)"
        exit 1
    }

    # If this script is used for other installers, this likely won't be required. It's referenced in 
    # the Installer Argument List below; other items may be appropriate for other installers.
    if($NoInitialScan -or $NoScan) {
        $DoScan = 'DOSCAN=0'
    } else {
        $DoScan = ''
    }

    $LogFileName = (Join-Path $env:TEMP "$InstallerName").Replace(".exe", ".log")

# Installer Agrument List
$ArgumentList = @"
TOKEN="$AuthToken" ENVIRONMENT_ID="$EnvironmentId" $DoScan /quiet /norestart /log $LogFileName
"@
}

##############################
# DO NOT EDIT PAST THIS POINT
##############################

# Installer Location
$InstallerPath =  Join-Path $env:TEMP $InstallerName

# Enable Debug with 1
$DebugMode = 1 

# Failure message
$Failure = "$ServiceName was not installed Successfully."

function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

#Checking if the Service is Running
function Agent-Check($service)
{
    if (Get-Service $service -ErrorAction SilentlyContinue)
    {
        return $true
    }
    return $false
}

# Debug Output (if enabled)
function Debug-Print ($message)
{
    if ($DebugMode -eq 1)
    {
        Write-Host "$(Get-TimeStamp) [DEBUG] $message"
    }
}

# Download installation file
function Download-Installer {
    Debug-Print("Downloading from provided $DownloadURL...")
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Client = New-Object System.Net.Webclient
    try
    {
        $Client.DownloadFile($DownloadURL, $InstallerPath)
    }
    catch
    {
    $ErrorMsg = $_.Exception.Message
    Write-Host "$(Get-TimeStamp) $ErrorMsg"
    }
    If ( ! (Test-Path $InstallerPath) ) {
        $DownloadError = "Failed to download the $ServiceName Installation file from $DownloadURL"
        Write-Host "$(Get-TimeStamp) $DownloadError" 
        throw $Failure
    }
    Debug-Print ("Installer Downloaded to $InstallerPath...")


}

# Installation Routine
function Install-Agent {
    Debug-Print ("Verifying AV did not steal exe...")
    If (! (Test-Path $InstallerPath)) {
    {
        $AVError = "Something, or someone, deleted the file."
        Write-Host "$(Get-TimeStamp) $AVError"
        throw $Failure
    }
    }
    if($NoInitialScan -or $NoScan) {
        Debug-Print("Skipping initial scan due to -NoScan or -NoInitialScan flag.")
    } else {
        Debug-Print("Performing initial backscan assessment after installation.")
    }
    Debug-Print ("Unpacking and Installing agent...")
    Start-Process -NoNewWindow -FilePath $InstallerPath -ArgumentList $ArgumentList -Wait
}

# Uninstallation Routine
function Uninstall-Agent {
    Debug-Print ("Verifying AV did not steal exe...")
    If (! (Test-Path $InstallerPath)) {
      {
        $AVError = "Something, or someone, deleted the file."
        Write-Host "$(Get-TimeStamp) $AVError"
        throw $Failure
      }
    }

# Uninstaller Agrument List
$ArgumentList = @"
/uninstall /quiet /norestart
"@
    Debug-Print ("Unpacking and Uninstalling agent from Installation File...")
    Start-Process -NoNewWindow -FilePath $InstallerPath -ArgumentList $ArgumentList -Wait
}

# Installation Routine
function Install-Agent {
    Debug-Print ("Verifying AV did not steal exe...")
    If (! (Test-Path $InstallerPath)) {
    {
        $AVError = "Something, or someone, deleted the file."
        Write-Host "$(Get-TimeStamp) $AVError"
        throw $Failure
    }
    }
    if($NoInitialScan -or $NoScan) {
        Debug-Print("Skipping initial scan due to -NoScan or -NoInitialScan flag.")
    } else {
        Debug-Print("Performing initial backscan assessment after installation.")
    }
    Debug-Print ("Unpacking and Installing agent...")
    Start-Process -NoNewWindow -FilePath $InstallerPath -ArgumentList $ArgumentList -Wait
}

# Uninstallation Process Start
function removeAgent {
    Debug-Print("Starting...")
    Debug-Print("Checking if $ServiceName is already installed...")
    If ( !$Force -and !(Agent-Check($ServiceName)) )
    {
        $ServiceError = "$ServiceName is Not Installed, won't try to uninstall (retry with -Force flag)...Bye." 
        Write-Host "$(Get-TimeStamp) $ServiceError"
        exit 0
    } elseif ($Force) {
        $ServiceError = "$ServiceName is Not Installed, but trying to remove anyway because -Force flag was used." 
        Write-Host "$(Get-TimeStamp) $ServiceError"
    }
    Download-Installer
    Uninstall-Agent
    Debug-Print("$ServiceName Uninstall was run...cleaning up installer...")
    Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    Debug-Print("Attempted to delete installer.")
}

try
{
    if($Uninstall) {
      removeAgent
    } else {
      installAgent
    }
}
catch
{
    $ErrorMsg = $_.Exception.Message
    Write-Host "$(Get-TimeStamp) $ErrorMsg"
    exit 1
}
