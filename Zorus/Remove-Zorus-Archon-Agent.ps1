<# Remove-Zorus-Agent.ps1

.SYNOPSIS
Remove Zorus Archon Agent and related services, both via uninstallation of the agent and related apps and also via manual cleanup (optional with the -Clean parameter) if the uninstall fails.

.DESCRIPTION
Uninstalls and optionally cleans/removes the Zorus Archon Windows Agent and related services and folders. It will attempt to run uninstallers the agent entry from Add/Remove Programs unless you use the -SkipUninstall parameter.

If the -Clean parameter is specified, it will also attempt (after uninstallation) to clean up agent remnants in addition to attempting uninstallation--this includes stopping and disabling related services, removing both the Uninstall and regular application registry entries and disabling the services, attempting to delete the services, and then removing the installation folders and the related folders.

You can skip running the official removal tool (the recommended way to uninstall from the manufacturer) first with the -SkipRemovalTool parameter, but this is not recommended except for testing.

You can skip running the uninstall command against the path in Add/Remove Programs first with the -SkipUninstall parameter, optionally.

The script may leave some top-level folders under Program Files, that are empty, or may leave some subfolders that are in use and cannot be removed due to permissions, but it will attempt to remove some of these after a reboot if possible, and any remaining remnants afterwards should not allow the agent to run, even if they aren't completely cleaned up.

The script should be run with admin privileges, ideally as SYSTEM, and will quit if it is not.

Paths and services to clean up are hardcoded into the script under CONFIG AND SETUP, and will use the correct system drive for the system but the rest of the paths are hardcoded. The installation folders that any existing services refer to will be added to the cleanup list, if they are different and exist during the run (if -Clean is run as part of the initial pass).

While it can be run manually, it is recommended that the script be run via a different RMM tool, and supports but does not require NinjaRMM Script Variables with the parameter names (as checkboxes) for configuration.

.PARAMETER SkipRemovalTool
Skip uninstalling the Zorus Agent with automatic removal tool before clean (if specified). Used only if you want to run a clean without a standard removal attempt first. Generally only for troubleshooting.

.PARAMETER SkipUninstall
Skip running the uninstaller(s) located in the registry to remove the agent before running any forced cleanup of registry, services, and folders. Generally only used for troubleshooting.

.PARAMETER Clean
Clean up agent remnants in addition to attempting uninstallation.

.PARAMETER TestOnly
Test removal of agent and services without actually removing them--will output test info to console instead of making changes. Kind of like a custom -WhatIf dry run without being official.

.EXAMPLE
Remove-Zorus-Agent.ps1

.EXAMPLE
Remove-Zorus-Agent.ps1 -Clean

.NOTES
Version 0.0.1 - 2024-05-30 by David Szpunar - Initial release
#>
[CmdletBinding()]
param(
    [switch] $SkipRemovalTool,
    [switch] $SkipUninstall,
    [switch] $Clean,
    [switch] $TestOnly
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

##### CONFIG AND SETUP #####
# These itemss should generally be set via parameters or environment/script variables, but can be manually overridden for testing:
# $TestOnly = $false
# $Clean = $true
# $Verbose = $true

<# Some of this information was used for interactive troubleshooting and script design but is not a part of the final script, left for reference:

# $Application = "Archon Agent"
# # $AgentInstall = ("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match "$Application" } }
# $AgentInstall = ("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.Publisher -match "$Application" } }
# $AgentVersion = $AgentInstall.DisplayVersion
# $AgentGUID = $AgentInstall.PSChildName
# $AgentInstall | Format-List
#>

<#
PREPARE THE LIST OF APPS TO UNINSTALL AND SERVICES TO REMOVE
#>
$AppList = @('Archon Agent')
$MSIList = @('Archon Agent')

$ServiceList = @('ZorusDeploymentService')

# This gets added automatically from the registry so no need to add it manually:
$FolderPathsList = @("$($env:systemdrive)\Program Files\Zorus Inc")

<#
PREPARE THE EMPTY LIST OF FILE PATHS TO LATER REMOVE
#>
$InstallPaths = New-Object System.Collections.Generic.List[System.Object]

<#
PREPARE THE EMPTY LIST OF FILE PATHS TO LATER REMOVE
#>
$ServicePaths = New-Object System.Collections.Generic.List[System.Object]

<#
PREPARE THE EMPTY LIST OF REGISTRY PATHS TO LATER REMOVE
#>
$RegistryPaths = New-Object System.Collections.Generic.List[System.Object]

$RegistryPaths.Add('HKLM:\SOFTWARE\WOW6432Node\Zorus Inc.')
$RegistryPaths.Add('HKLM:\SOFTWARE\Zorus Inc.')

###### FUNCTIONS ######
function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function Remove-ItemOnReboot {
    # SOURCE: https://gist.github.com/rob89m/6bbea14651396f5870b23f1b2b8e4d0d
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true)][string]$Item
    )
    END {
        # Read current items from PendingFileRenameOperations in Registry
        $PendingFileRenameOperations = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations).PendingFileRenameOperations
     
        # Append new item to be deleted to variable
        $NewPendingFileRenameOperations = $PendingFileRenameOperations + "\??\$Item"
     
        # Reload PendingFileRenameOperations with existing values plus newly defined item to delete on reboot
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -Value $NewPendingFileRenameOperations
    }
}

function Uninstall-GUID ([string]$GUID) {
    # $AgentInstall = ("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match "$Application" } }
    # $AgentVersion = $AgentInstall.DisplayVersion
    # $AgentGUID = $AgentInstall.PSChildName
    # 
    # $UninstallString = "$($AgentInstall.UninstallString) /quiet /norestart"
    $UninstallString = "MsiExec.exe /x$AgentGUID /quiet /norestart"

    if ($GUID) {
        Write-Host "Uninstalling now via GUID: $GUID"
        Write-Verbose "Uninstall String: $UninstallString"
        if (!$TestOnly) {
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
            return $($Process.ExitCode)
        }
        else {
            Write-Host "TEST ONLY: No uninstallation attempt was made."
            return 0
        }
    }
    else {
        Write-Host "Pass a GUID to the function."
        return $false
    }
}

function Uninstall-App ($Agent, [string]$UninstallString) {
    if ($Agent) {
        Write-Host "Uninstalling now via Agent Uninstall String:" $Agent.DisplayName
        Write-Host "Uninstall String: $UninstallString"
        if (!$TestOnly) {
            $Process = Start-Process cmd.exe -ArgumentList "/c $UninstallString" -Wait -PassThru
            if ($Process.ExitCode -ne 0) {
                Write-Host "Uninstallation attempt failed with error code: $($Process.ExitCode). Please review manually."
            }
            else {
                Write-Host "Uninstallation attempt completed for" $Agent.DisplayName
                return 0
            }
            return $($Process.ExitCode)
        }
        else {
            Write-Host "TEST ONLY: No uninstallation attempt was made."
            return 0
        }
    }
    else {
        Write-Host "Pass an uninstall registry object to the function."
        return 1
    }
}



Function Get-ServiceStatus ([string]$Name) {
    (Get-Service -Name $Name -ErrorAction SilentlyContinue).Status
}

Function Stop-RunningService ($svc) {
    Write-Verbose "Checking if $($svc.Name) service is running to STOP"
    # If ( $(Get-ServiceStatus -Name $Name) -eq "Running" ) {
    If ( $svc.Status -eq "Running" ) {
        Write-Host "Stopping : $($svc.Name) service"
        if (!$TestOnly) {
            # Stop-Service -Name $Svc -Force
            $svc | Stop-Service -Force
        }
        else {
            Write-Host "TEST ONLY: Not stopping $Name service"
        }
    }
    else {
        Write-Verbose "The $($svc.Name) service is not running, not stopping it!"
    }
}

Function Disable-Service ($svc) {
    If ( $svc ) {
        Write-Host "Disabling : $($svc.Name) service"
        if (!$TestOnly) {
            # Set-Service $Svc -StartupType Disabled
            $svc | Set-Service -StartupType Disabled
        }
        else {
            Write-Host "TEST ONLY: Not disabling $($svc.Name) service"
        }
    }
    else {
        Write-Verbose "The $($svc.Name) service doesn't exist, not disabling it!"
    }
}

Function Remove-StoppedService ($svc) {
    If ( $svc ) {
        If ( $svc.Status -eq "Stopped" ) {
            Write-Host "Deleting : $($svc.Name) service"
            if (!$TestOnly) {
                Stop-Process -Name $($svc.Name) -Force -ErrorAction SilentlyContinue
                sc.exe delete $($svc.Name)
                Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Force -Recurse -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "TEST ONLY: Not deleting $Name service"
            }
        }
        else {
            Write-Host "The $($svc.Name) service is not stopped, not deleting it!"
        }
    }
    Else {
        Write-Verbose "Not Found to Remove: $($svc.Name) service"
    }
}

Function Remove-File-Path ([string]$Path) {
    Write-Host "Deleting folder if it exists: $Path"
    $FolderPath = Resolve-Path -Path $Path.Trim('"') -ErrorAction SilentlyContinue
    if (![string]::IsNullOrEmpty($FolderPath) -and (Test-Path $FolderPath)) {
        Write-Host "Removing folder: $FolderPath"
        if (!$TestOnly) {
            try {
                Remove-Item -Path $FolderPath -Recurse -Force -ErrorAction Stop
            }
            catch {
                Write-host "Error deleting folder '$FolderPath\', adding to delete on reboot list."
                Remove-ItemOnReboot -Item "$FolderPath\"
            }
        }
        else {
            Write-Host "TEST ONLY: Not removing $FolderPath"
        }
    }
    else {
        Write-Verbose "Not found and thus not deleting: $Path"
    }
}

Function Remove-Registry-Path ([string]$Path) {
    Write-Verbose "Deleting registry path: $Path"
    $KeyPath = Resolve-Path $Path -ErrorAction SilentlyContinue
    if (![string]::IsNullOrEmpty($KeyPath) -and (Test-Path $KeyPath)) {
        Write-Host "Removing key $KeyPath"
        if (!$TestOnly) {
            Write-Verbose "Attempting to remove registry path: $KeyPath"
            Remove-Item -Path $KeyPath -Recurse -Force
        }
        else {
            Write-Host "TEST ONLY: Not removing $KeyPath"
        }
    }
    else {
        Write-Verbose "Not found and thus not deleting: ${Path}"
    }
}

function Remove-Agent {
    foreach ($service in $ServiceList) {
        Write-Host "`nGetting Service $service"
        $ServiceObj = Get-Service $service -ErrorAction SilentlyContinue
        if (($ServiceObj)) {
            $SvcInfo = Get-WmiObject win32_service | Where-Object { $_.Name -eq "$service" } | Select-Object Name, DisplayName, State, StartMode, PathName
            Write-Host "STATE: $($SvcInfo.State) MODE: $($SvcInfo.StartMode) `tSERVICE: $($SvcInfo.DisplayName) '$($SvcInfo.Name)'"
            Write-Host "PATH: $($SvcInfo.PathName)"

            $SvcPath = Split-Path -Path $($SvcInfo.PathName).Trim('"') -Parent
            $ServicePaths.Add($SvcPath)

            if(!$TestOnly) {
                Stop-RunningService $ServiceObj
                Disable-Service $ServiceObj
                $ServiceObj = Get-Service $service -ErrorAction SilentlyContinue
                Remove-StoppedService $ServiceObj
            } else {
                Write-Host "TEST ONLY: Not stopping or disabling $service service"
            }
        }
        else {
            Write-Host "Service $service not found."
        }
    }

    Write-Verbose ""

    foreach ($Folder in $FolderPathsList) {
        Write-Verbose "Deleting folder path: $Folder"
        Remove-File-Path $Folder
    }
    Write-Verbose ""

    foreach ($Folder in $InstallPaths) {
        Write-Verbose "Deleting install folder path: $Folder"
        Remove-File-Path $Folder
    }
    Write-Verbose ""

    foreach ($Folder in $ServicePaths) {
        Write-Verbose "Deleting service folder: $Folder"
        Remove-File-Path $Folder
    }
    Write-Verbose ""

    foreach ($Key in $RegistryPaths) {
        Write-Verbose "Deleting registry path: $Key"
        Remove-Registry-Path $Key
    }
}

function Uninstall-Agent-Mfg-Tool {
    Write-Host "Uninstalling Zorus Deployment Agent using ZorusAgentRemovalTool.exe provided by Zorus, as first ideal step."
    $originalProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::'SystemDefault'

    $source = "https://static.zorustech.com/downloads/ZorusAgentRemovalTool.exe";
    $destination = "$env:TEMP\ZorusAgentRemovalTool_RemoveScript.exe";

    Write-Host "Downloading Zorus Agent Removal Tool..."
    try
    {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($source, $destination)
    }
    catch
    {
        Write-Host "Failed to download removal tool. Exiting."
        Exit
    }

    if ([string]::IsNullOrEmpty($Password))
    {
        Write-Host "Uninstalling Zorus Deployment Agent..."
        $Process = Start-Process -FilePath $destination -ArgumentList "-s" -Wait -PassThru
    }
    else
    {
        Write-Host "Uninstalling Zorus Deployment Agent with password..."
        $Process = Start-Process -FilePath $destination -ArgumentList "-s", "-p $Password" -Wait -PassThru
    }

    Write-Host "Removal Tool Process exit code: $($Process.ExitCode)"

    Write-Host "Removing temporary files..."
    Remove-Item -recurse $destination
    Write-Host "Removal complete using Zorus removal tool."

    [System.Net.ServicePointManager]::SecurityProtocol = $originalProtocol

    return $Process.ExitCode
}

##### BEGIN SCRIPT #####

# If not elevated error out. Admin priveledges are required to uninstall software
if (-not (Test-IsElevated)) {
    Write-Error -Message "Access Denied. Please run with Administrator privileges."
    exit 1
}

# Try provided removal tool first
if(!$TestOnly -and !$SkipRemovalTool) {
    $UninstallAttempt = Uninstall-Agent-Mfg-Tool
    if($UninstallAttempt -ne 0) {
        Write-Host "Failed to uninstall Zorus Agent with automatic removal tool. Proceeding to uninstall manually."
    } else {
        Write-Host "Successfully uninstalled Zorus Agent with automatic removal tool. Proceeding to clean up manually in case of any leftover remnants."
    }
} else {
    if($TestOnly) {
        Write-Host "TEST ONLY: Not uninstalling Zorus Agent with automatic removal tool first, which would normally be done here."
    }
    elseif ($SkipRemovalTool) {
        Write-Host "Skipped uninstalling Zorus Agent with automatic removal tool because of -SkipRemovalTool parameter. Proceeding to clean up manually."
    }
}

if(!$SkipUninstall) {
Write-Host "`nAttempting to uninstall via MSI GUID method if any exist..."
foreach ($app in $MSIList) {
    $AgentInstalls = $null
    $AgentInstalls = ("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match "$app" } }

    if($AgentInstalls) {
        foreach ($AgentInstall in $AgentInstalls) {
            $AgentGUID = $AgentInstall.PSChildName
            if ($AgentInstall -and $AgentInstall.PSChildName -like "*{*") {
                if ($AgentInstall.InstallLocation -ne "") {
                    $InstallPaths.Add($AgentInstall.InstallLocation)
                }
                Write-Verbose "Adding registry path to the paths to delete: $($AgentInstall.PSPath)"
                $RegistryPaths.Add($AgentInstall.PSPath)
                Write-Host "`nUninstalling app '$app' using GUID: " $AgentGUID
                if ((Uninstall-GUID $AgentInstall.PSChildName) -eq 0) {
                    Write-Host "Successfully uninstalled '$app' via MSI command using GUID $AgentGUID"
                }
            }
        }
    }
    else {
        Write-Verbose "No installation entry found to uninstall '$app' via MSI command."
    }
}

    Write-Host "`nAttempting to uninstall via app method if any exist..."
    foreach ($app in $AppList) {
        $AgentInstalls = $null
        $AgentInstalls = ("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") | ForEach-Object { Get-ChildItem -Path $_ | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match "$app" } }

        if($AgentInstalls) {
            foreach ($AgentInstall in $AgentInstalls) {
                if ($AgentInstall -and $AgentInstall.PSChildName -notlike "*{*") {
                    $AgentUninstallPath = $AgentInstall.UninstallPath
                    Write-Verbose "`nApp UNINSTALL PATH: $AgentUninstallPath"

                    if ($AgentInstall.InstallLocation -ne "") {
                        $InstallPaths.Add($AgentInstall.InstallLocation)
                    }
                    Write-Verbose "Adding registry path to the paths to delete: $($AgentInstall.PSPath)"
                    $RegistryPaths.Add($AgentInstall.PSPath)

                    $UninstallPath = $AgentInstall.UninstallString
                    $UninstallPath = Split-Path -Path $UninstallPath.Split("/")[0].Trim()
                    write-Host "`nAdding registry uninstall path to removal list:" $UninstallPath
                    $InstallPaths.Add($UninstallPath)
                    # Write-Host "`nSKIPPING standard app Uninstall method."
                    Write-Host "`nUninstalling app '$app' using standard removal."
                    if ((Uninstall-App $AgentInstall $AgentUninstallPath) -eq 0) {
                        Write-Host "Successfully uninstalled '$app' silently via standard removal."
                    }
                    else {
                        Write-Host "Unable to uninstall '$app' silently via standard removal."
                    }
                }
            }
        }
        else {
            Write-Verbose "No installation entry found to uninstall '$app' silently via standard uninstall command."
        }
    }
} else {
    Write-Host "Skipping attempt at uninstall using registry settings, proceeding directly to forced cleanup of folders, registry, and service."
}

Write-Host "Folder Paths:"
$InstallPaths
Write-Host "Registry Paths:"
$RegistryPaths


if ($Clean) {
    Write-Host "`nAttempting to clean up agent remnants..."
    Remove-Agent

    Write-Host "`nService Folder Paths Found During Agent Removal (should have been deleted):"
    $ServicePaths
}
