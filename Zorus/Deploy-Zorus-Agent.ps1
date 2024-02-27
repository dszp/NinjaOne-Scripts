<# Deploy-Zorus-Agent.ps1
Zorus-provided deployment script for their own agent, customized to pull token from a NinjaRMM custom field and/or allow parameters or Script Variables (-Force and -Uninstall) to install even if already installed, or to uninstall the agent.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)][switch] $Uninstall,
  [Parameter(Mandatory = $false)][switch] $Force
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

###########
# EDIT ME
###########

#Service Name (validate if already installed)
$ServiceName = "Zorus Archon"

# Deployment Token Documentation Field Name
$token_field = "zorusDeploymentToken"

##############################
# DO NOT EDIT PAST THIS POINT
##############################

$token = '' #Initialize
$Token = Ninja-Property-Docs-Get 'Deployments' 'Deployments' $token_field

if ($Token.Length -lt 51 -and !$uninstall) {
  Write-Host "Deployment code is too short or invalid, set valid $token_field field in documentation. "
  Write-Host "Format should be alphanumeric and 52 characters long"
  exit 1
}
elseif ($Token -NotMatch "^[a-zA-Z00-9]{52}$" -and !$uninstall) {
  Write-Host "No Deployment Code field defined or invalid format, set valid $token_field field in documentation. "
  Write-Host "Format should be alphanumeric and 52 characters long"
  exit 1
}
elseif (!$uninstall) {
  Write-Host "Continuing to install with the provided $token_field. "
  Write-Host "First 10 characters of Deployment Token from Documentation Field:" $Token.Substring(0, 10)
}
else {
  Write-Host "Continuing to uninstall the Zorus Archon agent. "
}

# Orig Script:
#$Token = "token here";

# Configure preferred TLS versions in order and disable progress bar to speed downloads.
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
$ProgressPreference = 'SilentlyContinue'

# If ([string]::IsNullOrEmpty($Uninstall)) {
If (!$Uninstall) {

  # Determine wether or not Archon is currently installed
  $IsInstalled = $false
  $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  foreach ($obj in $InstalledSoftware) {
    if ($obj.GetValue('DisplayName') -match "Archon") {
      $IsInstalled = $true
    }
  }


  # If it is installed
  if ($IsInstalled -and !$Force) {
    # We skip the install routine
    Write-Host "Archon already installed. Skipping"

  }
  else {
    # If it is not installed, we do the routine we had previously in place
    if ($Force) {
      Write-Host "Archon force install requested, attempting install regardless of current state."
    }
    else {
      Write-Host "Archon not installed. Installing now"
    }

    $source = "http://static.zorustech.com.s3.amazonaws.com/downloads/ZorusInstaller.exe"
    $destination = "$env:TEMP\ZorusInstaller.exe"

    Write-Host "Downloading Zorus Archon Agent..."
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($source, $destination)

    if (!(Test-Path -Path $destination)) {
      Write-Host "For some reason the download or save to $destination failed, quitting!"
      exit 10
    }

    If ([string]::IsNullOrEmpty($Password)) {
      Write-Host "Installing Zorus Archon Agent..."
        
      Start-Process -FilePath $destination -ArgumentList "/qn", "ARCHON_TOKEN=$Token" -Wait
    }
    Else {
      Write-Host "Installing Zorus Archon Agent with password..."
      Start-Process -FilePath $destination -ArgumentList "/qn", "ARCHON_TOKEN=$Token", "UNINSTALL_PASSWORD=$Password" -Wait
    }

    Write-Host "Removing Installer..."
    Remove-Item -Recurse $destination
    Write-Host "Job Complete!"
  }
    
}
Else {
  # Uninstall
  $source = "http://static.zorustech.com.s3.amazonaws.com/downloads/ZorusAgentRemovalTool.exe"
  $destination = "$env:TEMP\ZorusAgentRemovalTool.exe"

  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile($source, $destination)

  Write-Host "Downloading Zorus Agent Removal Tool..."

  If ([string]::IsNullOrEmpty($Password)) {
    Write-Host "Uninstalling Zorus Archon Agent..."
    Start-Process -FilePath $destination -ArgumentList "-s" -Wait
  }
  Else {
    Write-Host "Uninstalling Zorus Archon Agent with password..."
    Start-Process -FilePath $destination -ArgumentList "-s", "-p $Password" -Wait
  }

  Write-Host "Removing Uninstaller..."
  Remove-Item -Recurse $destination
  Write-Host "Job Complete!"
}

exit
# SOURCE: https://discord.com/channels/839605716163887146/839605717580513345/1127949602310598666
$tls = "Tls"
[System.Net.ServicePointManager]::SecurityProtocol = $tls

If ($env:Install -eq $TRUE) {
  $source = "http://static.zorustech.com.s3.amazonaws.com/downloads/ZorusInstaller.exe"
  $destination = "$env:TEMP\ZorusInstaller.exe"

  UNINSTALL = "YES"

  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile($source, $destination)

  Write-Host "Downloading Zorus Archon Agent..."

  If ([string]::IsNullOrEmpty($env:Password)) {
    Write-Host "Installing Zorus Archon Agent..."
    Start-Process -FilePath $destination -ArgumentList "/qn", "ARCHON_TOKEN=$env:Token", "HIDE_TRAY_ICON=$trayIcon", "HIDE_ADD_REMOVE=$addRemove" -Wait
  }
  Else {
    Write-Host "Installing Zorus Archon Agent with password..."
    Start-Process -FilePath $destination -ArgumentList "/qn", "ARCHON_TOKEN=$env:Token", "UNINSTALL_PASSWORD=$env:Password", "HIDE_TRAY_ICON=$trayIcon", "HIDE_ADD_REMOVE=$addRemove" -Wait
  }

  Write-Host "Removing Installer..."
  Remove-Item -Recurse $destination
  Write-Host "Job Complete!"
}
Else {
  $source = "http://static.zorustech.com.s3.amazonaws.com/downloads/ZorusAgentRemovalTool.exe"
  $destination = "$env:TEMP\ZorusAgentRemovalTool.exe"

  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile($source, $destination)

  Write-Host "Downloading Zorus Agent Removal Tool..."

  If ([string]::IsNullOrEmpty($env:Password)) {
    Write-Host "Uninstalling Zorus Archon Agent..."
    Start-Process -FilePath $destination -ArgumentList "-s" -Wait
  }
  Else {
    Write-Host "Uninstalling Zorus Archon Agent with password..."
    Start-Process -FilePath $destination -ArgumentList "-s", "-p $env:Password" -Wait
  }

  Write-Host "Removing Uninstaller..."
  Remove-Item -Recurse $destination
  Write-Host "Job Complete!"
}