<# Deploy-ImmyBot.ps1
  .SYNOPSIS
    Install, Upgrade, or Uninstall ImmyBot Agent provided a valid ImmyBot KEY and ID from the PowerShell Deployment for a given tenant.
  .DESCRIPTION
    Install, Upgrade, or Uninstall ImmyBot Agent provided a valid ImmyBot KEY and ID from the PowerShell Deployment for a given tenant.
  
    With no parameters, installation will be attempted, but only if the ImmyBot Agent servies does not exist. Version will be ignored without the -Upgrade parameter.

    The ImmyBot PowerShell Deployment Script uses NinjaRMM Custom Fields to get the ID and KEY by default (see CONFIG), but they can be passed in as parameters if desired.

    The Ninja Custom Field should be a single string with the following format, space-separated, pulled out of a PowerShell deployment for a specific tenant:

      ID=abe6c78d-1de6-91f3-dde1-eafdev729836 KEY=aj78akdjr3ikKEasdfj58vnaew89SDJKVjFei88FVDS=
    
    You can alternately leave the ADDR field in the middle of the custom field value if you don't want to remove it, like this, and it will still work:
    
      ID=abe6c78d-1de6-91f3-dde1-eafdev729836 ADDR=https://SUBDOMAIN.immy.bot/plugins/api/v1/1 KEY=aj78akdjr3ikKEasdfj58vnaew89SDJKVjFei88FVDS=

    As long as you pass in -ID and -KEY parameters, or provide ID and KEY environment variables, this script will function entirely separate from NinjaRMM.
  .PARAMETER Tenant
    The plain subdomain for the ImmyBot tenant (the part after "https://"" and before ".immy.bot").

    Not required for Info or Uninstall parameters. Always required for Install or Upgrade, though it can be defaulted in the parameters list (hardcoded).
  .PARAMETER ID
    If this parameter is passed from the ImmyBot PowerShell Deployment Script along with the -KEY parameter, they will be used instead of NinjaRMM Custom Fields.
  .PARAMETER KEY
    If this parameter is passed from the ImmyBot PowerShell Deployment Script along with the -ID parameter, they will be used instead of NinjaRMM Custom Fields.
  .PARAMETER Upgrade
    Install Reinstall/Upgrade ImmyBot if it's already installed and at an older version than the current version available online, or if it's not installed at all.

    If the current version is already installed, the agent will not be reinstalled unless you add the -Force parameter.
  .PARAMETER Force
    Add to the -Upgrade parameter to attempt to reinstall even if the same version is already installed.
  .PARAMETER Uninstall
    If ImmyBot is already installed, uninstall it, using the uninstall string from the Windows Registry.
  .PARAMETER Info
    Confirm installation status and print version info, then exit. Other parameters will be ignored.
  .EXAMPLE
    Deploy-ImmyBot.ps1 -Tenant 'yoursubdomain'
    Deploy-ImmyBot.ps1 -Tenant 'yoursubdomain' -ID 'yourID' -KEY 'yourKEY'
    Deploy-ImmyBot.ps1 -Tenant 'yoursubdomain' -ID 'yourID' -KEY 'yourKEY' -Upgrade
    Deploy-ImmyBot.ps1 -Tenant 'yoursubdomain' -ID 'yourID' -KEY 'yourKEY' -Upgrade -Force
    Deploy-ImmyBot.ps1 -Info
    Deploy-ImmyBot.ps1 -Uninstall


Version 0.5.2 - 2024-03-19 - by David Szpunar - Adjust $ID and $KEY values to fix more similar typos, and add TLS version enforcement
Version 0.5.1 - 2024-03-15 - by David Szpunar - Adjust $ID and $KEY values to fix typos that caused issues for non-custom-field parameters thanks to @HiTechPhilip
Version 0.5.0 - 2024-02-19 - by David Szpunar - Refactor, add -Tenant, -Upgrade, -Force, -Uninstall, -Info switches and cloud version check function, documentation
Version 0.0.5 - 2023-11-28 - by David Szpunar - Review and update for new ImmyBot version, minor adjustments
Version 0.0.1 - 2023-01-26 - by David Szpunar - Initial version by David Szpunar, deployment only if not already installed
#>
[CmdletBinding()]
param(
  [string] $Tenant = '',
  [string] $ID,
  [string] $KEY,
  [switch] $Upgrade,
  [switch] $Force,
  [switch] $Uninstall,
  [switch] $Info
)

##### CONFIG #####
# The page name (such as Deployments) for the custom Ninja Documentation page with the KEY and ID field in it.
# Leave BLANK/empty string if you're using Device/Role Custom Fields and NOT Documentation Custom Fields, or if you aren't using NinjaRMM custom fields at all.
$NinjaCustomDocumentationPage = 'Deployments'

# The custom field name of the Ninja Custom field that contains both the ID and KEY field/value pairs from the ImmyBot PowerShell deployment script.
# This can be a Device or Role Custom Field, or a Documenation Custom Field (if using the Documentation Page above), as long as Automation Write access is enabled.
# Leave BLANK/empty string if you're passing in the -ID and -KEY parameters to the script directly rather than using NinjaRMM custom fields.
$NinjaCustomFieldName = 'immyBotIDAndKey'
##### END CONFIG #####

#Service Name and Application Name
$ServiceName = "ImmyBot Agent"
$Application = "ImmyBot Agent"

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

function Get-ImmyCurrentVersion {
  <#
  .SYNOPSIS
      Given the result of WebResponseObject with the ImmyBot teannt name, determine the current version of ImmyBot from the file name.
  .DESCRIPTION
      Given the result of WebResponseObject with the ImmyBot teannt name, determine the current version of ImmyBot from the file name.
  .EXAMPLE
      $version = Get-ImmyCurrentVersion -Tenant 'subdomain'
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [String] $Tenant
  )

  if ([string]::IsNullOrEmpty($Tenant)) {
    Write-Host "ERROR: No Tenant specified (required for cloud version check and download URL), quitting."
    return $false
  }

  $uri = "https://$Tenant.immy.bot/plugins/api/v1/1/installer/latest-download"
  Write-Verbose "URI for latest version information: $uri"

  try {
    # Manually invoke a web request
    $Request = [System.Net.WebRequest]::Create($uri)
    $Request.AllowAutoRedirect = $false
    $Response = $Request.GetResponse()
    Write-Verbose "Response Headers returned from version check:"
    Write-Verbose ($Response.Headers | fl * | Out-String)
    Write-Verbose "Location header value: $($Response.Headers['Location'])"
  }
  catch {
    Write-Error 'Error: Web request failed.' -ErrorAction Stop
  }
  if ($Response.StatusCode.value__ -eq '307') {
    $redirectUrl = $($Response.Headers['Location'])
    Write-Verbose "Redirect URL: $RedirectUrl"
    $FileName = [System.IO.Path]::GetFileName($redirectUrl)
    Write-Verbose "FileName: $FileName"
    if (-not $FileName) { Write-Error 'Error: Failed to resolve file name from URI.' -ErrorAction Stop }
    $FileName -match '^(\d+\.\d+\.\d+)\D+(\d+)' | Out-Null
    $version = $matches[1] + '.' + $matches[2]
    Write-Verbose "Version: $version"
    return $version
  }
  return $null
}

function Show-ImmyCurrentInfo {
  $ImmyAgentInstall = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, UninstallString, Publisher, InstallDate, InstallLocation | Where-Object { $_.DisplayName -eq "$Application" }
  $AgentVersion = $ImmyAgentInstall.DisplayVersion
  
  if ($ImmyAgentInstall) {
    Write-Host "$Application is currently installed."
    Write-Host "Installed version: $AgentVersion"
  }
  else {
    Write-Host "$Application is not installed."
  }
}

function Service-Check {
  If ( Get-Service $ServiceName -ErrorAction SilentlyContinue ) {
    return $true
  }
  else {
    return $false
  }
}

function Check-ImmyBotIDandKey {
  param(
    [Parameter(Mandatory = $true,Position=0)]
    [string] $Tenant,
    [string] $ID,
    [string] $KEY
  )
  if([string]::IsNullOrWhiteSpace($ID) -or [string]::IsNullOrWhiteSpace($KEY)) {
    # Make sure this Documentation form, template, and field exist, are script readable, and have the corresponding tenant ID/KEY saved!
    if([string]::IsNullOrWhiteSpace($NinjaCustomDocumentationPage)) {
      if(![string]::IsNullOrWhiteSpace($NinjaCustomFieldName)) {
        Write-Host "Attempting to retreive ID and Key from NinjaRMM Custom Field..."
        $IDandKey = Ninja-Property-Get $NinjaCustomFieldName
      } else {
        Write-Host "Ninja Custom Field Name not provided, not attempting to retrieve ID and Key from NinjaRMM, must used -Id and -Key parameters."
      }
    } else {
      Write-Host "Attempting to retreive ID and Key from NinjaRMM Documentation Custom Field..."
      $IDandKey = Ninja-Property-Docs-Get-Single $NinjaCustomDocumentationPage $NinjaCustomFieldName
    }
  }
  if([string]::IsNullOrWhiteSpace($IDandKey)) {
    $IDandKey = "ID=$($global:ID) KEY=$($global:KEY)"
  }
  Write-Verbose "IDandKey Value: $IDandKey"

  #write-host "ImmyBot ID and Key from Documentation Field: $IDandKey"
  $regex = "ID=([a-zA-Z00-9]{8}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{12})\s.*\s*KEY=(\S{44})"
  $IDandKey -match $regex | Out-Null
  if ($Matches) {
    ($ID, $KEY) = ($Matches[1], $Matches[2])
  }
  else {
    Write-Host "Nothing found in ImmyBot ID and Key field, can't deploy for this tenant...Bye."
    exit 1
  }

  if ($ID -NotMatch "^[a-zA-Z00-9]{8}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{12}$") {
    Write-Host "The ID field is either not defined or is in an invalid format, set valid immyBotIDAndKey in documentation"
    Write-Host "Format should be: ID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX KEY=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
    Write-Host "The discovered value is" $ID
    exit 1
  }
  elseif ($KEY -NotMatch "^\S{44}$") {
    Write-Host "The KEY field is either not defined or is in an invalid format, set valid immyBotIDAndKey in documentation"
    Write-Host "Format should be: ID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX KEY=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
    Write-Host "The discovered value is" $KEY
    exit 1
  }
  else {
    #write-host "Installing with ID=" $ID
    $IDmasked = $ID.SubString(0, 10) + "****-****-" + $ID.SubString(24, 12)
    Write-Host "Installing with ID: " $IDmasked

    #write-host "Installing with KEY=" $KEY
    $KEYmasked = $KEY.SubString(0, 10) + "*************************" + $KEY.SubString(35, 9)
    Write-Host "Installing with KEY:" $KEYmasked

    Write-Host "(identifiers partially masked for log)"
  }
  if ([string]::IsNullOrEmpty($Tenant)) {
    Write-Host "ERROR: No Tenant specified (required for cloud version check and download URL), quitting."
    exit 1
  }
  return @($ID, $KEY)
}

function Install-ImmyBot {
  param(
    [Parameter(Mandatory = $true,Position=0)]
    [string] $Tenant,
    [Parameter(Mandatory = $true,Position=1)]
    [string] $Id,
    [Parameter(Mandatory = $true,Position=2)]
    [string] $Key,
    [switch] $Reinstall
  )

  $url = "https://$Tenant.immy.bot/plugins/api/v1/1/installer/latest-download"
  $ADDR = "https://$Tenant.immy.bot/plugins/api/v1/1"
  # Ensure a secure TLS version is used.
  $ProtocolsSupported = [enum]::GetValues('Net.SecurityProtocolType')
  if ( ($ProtocolsSupported -contains 'Tls13') -and ($ProtocolsSupported -contains 'Tls12') ) {
    # Use only TLS 1.3 or 1.2
    [Net.ServicePointManager]::SecurityProtocol = (
        [Enum]::ToObject([Net.SecurityProtocolType], 12288) -bOR [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    )
  } else {
    # Use only 1.2
    try {
        # In certain .NET 4.0 patch levels, SecurityProtocolType does not have a TLS 1.2 entry.
        # Rather than check for 'Tls12', we force-set TLS 1.2 and catch the error if it's truly unsupported.
        [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    } catch {
        $msg = $_.Exception.Message
        $err = "ERROR: Unable to use a secure version of TLS. Please verify Hotfix KB3140245 is installed."
        Write-Host "$err : $msg"
        Write-Error "$err : $msg"
        exit 1
    }
  }
  # The following code is the ImmyBot PowerShell deployment separated into lines for readability and with the ID and KEY variables swapped into the arguments:
  $ErrorActionPreference = "Stop"
  $InstallerFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".msi")
  (New-Object System.Net.WebClient).DownloadFile($url, $InstallerFile)
  $InstallerLogFile = [io.path]::ChangeExtension([io.path]::GetTempFileName(), ".log")
  if ($Reinstall) {
    $Arguments = " /c msiexec /i `"$InstallerFile`" /qn /norestart /l*v `"$InstallerLogFile`" REBOOT=REALLYSUPPRESS ID=$ID ADDR=$ADDR KEY=$KEY REINSTALL=ALL REINSTALLMODE=vemus"
  }
  else {
  $Arguments = " /c msiexec /i `"$InstallerFile`" /qn /norestart /l*v `"$InstallerLogFile`" REBOOT=REALLYSUPPRESS ID=$ID ADDR=$ADDR KEY=$KEY"
  }
  Write-Host "InstallerLogFile: $InstallerLogFile"
  $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
  if ($Process.ExitCode -ne 0) {
    Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 100
    Write-Host "Current cloud installer version for reference: " (Get-ImmyCurrentVersion -Tenant $Tenant | Out-String)
  }
  Write-Host "Exit Code: $($Process.ExitCode)"
  Write-Host "ComputerName: $($env:ComputerName)"

  # Return the exit code from the installation as the script exit code:
  exit $($Process.ExitCode)
}

function Uninstall-ImmyBot {
  $ImmyAgentInstall = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, UninstallString, Publisher, InstallDate, InstallLocation | Where-Object { $_.DisplayName -eq "$Application" }
  $AgentVersion = $ImmyAgentInstall.DisplayVersion
  $UninstallString = "$($ImmyAgentInstall.UninstallString) /quiet /norestart"
  Show-ImmyCurrentInfo

  if ($ImmyAgentInstall) {
    Write-Host "Uninstalling now."
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
  Show-ImmyCurrentInfo
  Write-Host "Current cloud installer version: " (Get-ImmyCurrentVersion -Tenant $Tenant | Out-String)
  exit 0
}

if ($Uninstall) {
  Uninstall-ImmyBot $UninstallInfo
  exit 0
}

($ID, $KEY) = Check-ImmyBotIDandKey -Tenant $Tenant -Id $ID -Key $KEY

if (!$Upgrade) {
  If ( Service-Check ) {
    Write-Host "The service" $ServiceName "is Already Installed...Bye." 
    exit 0
  }
  Install-ImmyBot -Tenant $Tenant -ID $Id -Key $KEY
  exit 0
}

if ($Upgrade) {
  $ImmyAgentInstall = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, UninstallString, Publisher, InstallDate, InstallLocation | Where-Object { $_.DisplayName -eq "$Application" }
  $AgentVersion = $ImmyAgentInstall.DisplayVersion
  if (!$AgentVersion) {
    Write-Host "ImmyBot is NOT currently installed. Attempting installation now."
    Install-ImmyBot -Tenant $Tenant -ID $Id -Key $KEY
    exit 0
  }
  $CurrentVersion = Get-ImmyCurrentVersion -Tenant $Tenant
  if (($AgentVersion -ne $CurrentVersion) -or $Force) {
    Write-Host "Installed Version of ImmyBot: " $AgentVersion
    Write-Host "Installing current version:" $CurrentVersion
    Install-ImmyBot -Tenant $Tenant -Id $ID -Key $KEY -Reinstall
  }
  else {
    Write-Host "ImmyBot is already up-to-date with version:" $AgentVersion
    Write-Host "Verified that current verison on server is:" $CurrentVersion
    Write-Host "Installation date: " $ImmyAgentInstall.InstallDate
    Write-Host "Not installing since already up to date, use -Force to reinstall anyway."
  }
}

