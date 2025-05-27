<# Manage-ScreenConnect-Windows.ps1
  .SYNOPSIS
    Review Installed ScreenConnect Clients installed on Windows, optionally report to Custom Fields, optionally Uninstall with possibility to leave some trusted instance IDs alone.
  .DESCRIPTION
    Review installed ScreenConnect Clients installed on Windows, optionally report to Custom Fields, optionally Uninstall with possibility to leave some trusted instance IDs alone.
  
    With -Safe parameter or hardcoded $Safe variable set to a comma-separated (no spaces) list of instance IDs, these will be trusted and NOT removed, but will still be reported on if found.

    If you create three NinjaRMM Custom Fields, two checkboxes with at least Automation Write permission named:
        screenconnectTrustedClientInstalled
        screenconnectUntrustedClientInstalled
    
    and one multi-line text field with Automation Read/Write permission named:
        screenconnectClientDetails
    
    this script will set the checkboxes to True or False depending on if one or more trusted or untrusted ScreenConnect insteances are found, and will output detailed logs to the multi-line text field 
    (the multi-line field will be appended with new information each run unless -ClearCustomHistory is used, and the checkboxes will be set to the current run value).

    The MinimumVersion variable can be changed to suit your needs but defaults to the earliest not-vulnerable version as reported at:
        https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
    If any instance, trusted or not, is found that is older than this version, the multi-line output will include "WARNING: VULNERABLE VERSION!" in it. This will NOT affect the checkboxes or 
    versions uninstalled or anything else other than this additional warning. The script could easily be modified to ignore/not uninstall untrusted instances that were at least upgraded to a 
    not vulnerable version (note that it's the SERVER that is vulnerable, not the client, but a client at a non-vulnerable version means the server it connects to is likely to not be vulnerable, 
    though a lower version of the Client may also be connected to a patched server, it's not possible to tell from the client side, it's just an indicator).

    What else doesn't this do?:
    - It does not find or remove emphemeral Support sessions that are not installed Access sessions!
    - It does not find or remove broken instances or ones that do not have an entry in Add/Remove programs (in the registry under the hood).

    These are avenues for future improvements, to find Support sessions that are running as standard users or that have been elevated as admin but have not been converted to Access sessions.

  .PARAMETER Safe
    With -Safe parameter or hardcoded $Safe variable set to a comma-separated (no spaces) list of instance IDs, these will be trusted and NOT removed, but will still be reported on if found.

    You can use the string "NONE" (uppercase) at runtime to force no safe instances even if $Safe is hardcoded into the script config.

    The Instance IDs are 16-character-long hexidecimal strings that are shown in parenthese after "ScreenConnect Client" in Add/Remove Programs for an installed agent, or in the installation folder path.

    There is no error-checking of trusted/safe instances, make sure you use the correct 16-character hexidecimal ID and use no spaces in the string, and no special characters other than a comma separator.
  .PARAMETER Uninstall
    If this switch is used, in addition to documenting, the script will uninstall all ScreenConnect Clients on Windows except the instance IDs defined by -Safe or $Safe.
  .PARAMETER ClearCustomHistory
    If Custom Field names are defined to output detailed logging information, this switch will clear the existing multi-line field before writing the log information.

    If this switch is not used, the script will not clear the existing multi-line field and will instead append this current run, timestamped, at the end so as to not lose previous history.
  .PARAMETER VeryVerbose
    Output to STDOUT additional debugging information using the Write-Verbose commands throughout the script.
  .PARAMETER DoNotTrustSaaS
    If this switch is used, the script will not attempt to trust any ScreenConnect SaaS instances which it does by default.
  .PARAMETER UpdateCheckboxesOnly
    If this switch is used, the script will only update the checkboxes and not update the multi-line text custom field.
  .EXAMPLE
    Manage-ScreenConnect-Windows.ps1
    Manage-ScreenConnect-Windows.ps1 -Safe abcdef0123456789,0123456789abcdef
    Manage-ScreenConnect-Windows.ps1 -Safe abcdef0123456789
    Manage-ScreenConnect-Windows.ps1 -Unninstall -Safe abcdef0123456789,0123456789abcdef
    Manage-ScreenConnect-Windows.ps1 -Uninstall
    Manage-ScreenConnect-Windows.ps1 -Uninstall -ClearCustomHistory
    Manage-ScreenConnect-Windows.ps1 -Safe abcdef0123456789,0123456789abcdef -Uninstall -ClearCustomHistory
    Manage-ScreenConnect-Windows.ps1 -Safe abcdef0123456789,0123456789abcdef -Uninstall -ClearCustomHistory -VeryVerbose

Version 0.0.2 - 2024-02-22 - by David Szpunar - Initial public version
Version 0.0.3 - 2024-02-22 - by David Szpunar - Tweaks to the local file extra info to test for files existing first. Also, fix uninstall to actually uninstall.
Version 0.0.4 - 2024-02-23 - by David Szpunar - Add first attempt at uninstall using Uninstall-Package command, and if that fails, use msiexec instead.
Version 0.0.5 - 2024-02-24 - by David Szpunar - Change all instances with ScreenConnect.com relays to be trusted due to ConnectWise protecting SaaS servers themselves.

SOURCES and CREDIT:
Based on the script I (David Szpunar, @DavidSzp) posted to https://discord.com/channels/676451788395642880/1117925926794186862 from an old script on 2023-06-12 likely in part from someone else originally.
Code for reading the config file to get the Relay Path and Instance Name is from https://discord.com/channels/801971115013963818/801989385838002196/1209685499476840529 (from TheSmokingHulk [MetaMSP] on MSPGeek)
#>
param(
    [string] $Safe = '', # Comma-separated safe/trusted instance IDs
    [switch] $Uninstall,
    [switch] $ClearCustomHistory,
    [switch] $VeryVerbose,
    [switch] $DoNotTrustSaaS,
    [switch] $UpdateCheckboxesOnly
)

### CONFIG
# Leave these blank to disable custom field saving to/from NinjaRMM.
# To use, make sure these two checkboxes and one multi-line text custom fields exist in NinjaRMM and are Automation-read/writable!
$NinjaCustom_TrustedCheckbox = 'screenconnectTrustedClientInstalled'
$NinjaCustom_UntrustedCheckbox = 'screenconnectUntrustedClientInstalled'
$NinjaCustom_ClientDetails = 'screenconnectClientDetails'

$MinimumVersion = [version]"23.9.8.8811" # Minimum version of ScreenConnect to consider not vulnerable

# Optionally override the default Safe list with a hardoded default string (comma-separated list of instance IDs, no spaces) by uncomenting below.
# Or, use the uppercase NONE to unset all trusted instances.
#$Safe = "NONE"
### END CONFIG

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

### SETUP
# Uninstall registry keys for later searching:
if ([System.Environment]::Is64BitOperatingSystem) {
    $RegistryKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
}
else {
    $RegistryKeys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
}

# Safe (keep) ConnectWise ScreenConnect Instance IDs array:
$SafeInstances = @() # Initialize
if ($Safe -ne '') {
    # Override from -Safe parameter if provided:
    $SafeInstances = $Safe.Split(',').Trim()
}
elseif ($Safe -eq 'NONE') {
    $SafeInstances = @()
}
else {
    # Safe (keep) ConnectWise ScreenConnect Instance IDs array:
    $SafeInstances = @() # Optionally set your trusted instance IDs here rather than in the $Safe string--if here, it's just a default and the -Safe parameter will override!
}
if ($SafeInstances.Count -gt 0) {
    Write-Verbose "Safe Instance Count: $($SafeInstances.Count)"
    Write-Verbose "Save Instance IDs for this script run: $($SafeInstances -join ', ')"
}

$ClientDetails = New-Object -TypeName System.Collections.ArrayList
$ClientDetails_Trusted = New-Object -TypeName System.Collections.ArrayList
$ClientDetails_Untrusted = New-Object -TypeName System.Collections.ArrayList
$OrigClientDetails = New-Object -TypeName System.Collections.ArrayList
# Prepopulate any existing custom field Client Details to a variable, and also set flag for custom fields being used:
if (![string]::IsNullOrWhiteSpace($NinjaCustom_ClientDetails)) {
    $OrigClientDetails = Ninja-Property-Get $NinjaCustom_ClientDetails
}
$ClientDetails.Add("-----SCAN OUTPUT BELOW FROM " + (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss" + ":")) | Out-Null

$TrustedInstanceCount = 0
$UntrustedInstanceCount = 0
$TerminatedProcessCount = 0

# Enable verbose output if -VeryVerbose parameter provided:
if($VeryVerbose) {
    $VerbosePreference = 'Continue'
}
### END SETUP

### FUNCTIONS
function Set-NinjaCustomCheckbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $CustomFieldCheckbox,
        [Parameter(Mandatory = $true)]
        [boolean] $value
    )
    if (![string]::IsNullOrWhiteSpace($CustomFieldCheckbox)) {
        Write-Verbose "Setting '$CustomFieldCheckbox' Ninja Custom field to '$value'."
        Ninja-Property-Set $CustomFieldCheckbox $value
    }
    return $null
}

function Log-ClientDetails {
    [CmdletBinding(PositionalBinding)]
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $false)][boolean]$Trusted = $false
    )
    # Write-Host $Status
    # $ClientDetails.Add($Status) | Out-Null
    if ($Trusted) {
        $ClientDetails_Trusted.Add($Status) | Out-Null
        Write-Verbose "Logging '$Status' to Client Details output, TRUSTED instance."
    }
    else {
        $ClientDetails_Untrusted.Add($Status) | Out-Null
        Write-Verbose "Logging '$Status' to Client Details output, UNTRUSTED instance."
    }
    Write-Verbose "Logging '$Status' to Client Details output."
    return $null
}

function Get-ScreenConnect-ConfigDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $InstanceID
    )
    $RelayRegex = '(?<=\?h=)(?<RelayServer>[^&]+)'

    $ScreenconnectInstallDetails = Get-ChildItem "${env:ProgramFiles(x86)}" -Directory |
    Where-Object { $_.Name -match "ScreenConnect Client \($InstanceID\)" } |
    ForEach-Object {
        $instanceDirectory = "${env:ProgramFiles(x86)}\$($_.Name)"
        if(Test-Path -Path "$instanceDirectory\Client.Override.en-US.resources" -PathType Leaf){
            $instanceName = ((New-Object -TypeName 'System.Resources.ResourceReader' -ArgumentList "$instanceDirectory\Client.Override.en-US.resources") | Where-Object { $_.Name -eq 'ApplicationTitle' }).Value
        } else {
            $instanceName = "UNKNOWN"
        }
        if(Test-Path -Path "$instanceDirectory\\system.config" -PathType Leaf){
            [xml]$systemxml = Get-Content -Path "$instanceDirectory\\system.config"
            $relayPath = $systemxml.configuration."ScreenConnect.ApplicationSettings".setting.value
            $relayPath -match $RelayRegex
            $instanceRelayServer = $matches.RelayServer
        } else {
            $instanceRelayServer = "UNKNOWN"
        }
        $instanceVersion = (Get-Command "$instanceDirectory\ScreenConnect.WindowsClient.exe").FileVersionInfo.FileVersion
        [PSCustomObject]@{
            'instanceID' = $instanceID
            'instanceVersion' = $instanceVersion
            'instanceName' = $instanceName
	        'installPath' = $instanceDirectory
            'relayServer' = $instanceRelayServer
        }
    }
    return $ScreenconnectInstallDetails
}

function Remove-ScreenConnect-Processes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $InstanceID
    )
    $procs = Get-Process | Where-Object { $_.ProcessName -like '*screenconnect*' } | Select-Object Id, ProcessName, Path
    foreach ($proc in $procs) {
        Write-Verbose "Found Process: $($proc.Id) $($proc.Path)"
        $proc.Path -match ".+\(([a-fA-F0-9]{16})\).+" | Out-Null
        if ($matches) {
            # Do not terminate ScreenConnect processes from trusted instances, if the provided Instance ID in the trusted instances list::
            if ([string]::IsNullOrWhiteSpace($InstanceID) -and $matches[1] -in $SafeInstances) {
                Write-Verbose "Process is from trusted instance PID: $($proc.id) $($matches[1])"
                Log-ClientDetails("Process is from trusted instance, not terminating: $($proc.id) Instance ID: $($matches[1])") $true
            }
            # Terminate all ScreenConnect processes from this ONE SPECIFIC Instance ID, if provided, without regard to the Safe Intances list:
            elseif(!([string]::IsNullOrWhiteSpace($InstanceID))-and $matches[1] -eq $InstanceID) {
                Write-Verbose "Process to terminate from $InstanceID specifically:"
                $proc | Format-List | Out-String -stream | Write-Verbose
                $TerminatedProcessCount++ | Out-Null
                Log-ClientDetails("PROCESS running from untrusted specific instance $InstanceID, terminating PID: $($proc.id) Instance ID: $($matches[1])") $false
                Get-Process | Where-Object { $_.Id -eq $proc.Id } | Stop-Process    # KILL
                Start-Sleep -Seconds 5
            }
            # Terminate all untrusted ScreenConnect processes if no Instance ID is specified and there's no trusted instance match:
            else {
                Write-Verbose "Process to terminate:"
                $proc | Format-List | Out-String -stream | Write-Verbose
                Log-ClientDetails("PROCESS running from untrusted instance, terminating PID: $($proc.id) Instance ID: $($matches[1])") $false
                $TerminatedProcessCount++ | Out-Null
                Get-Process | Where-Object { $_.Id -eq $proc.Id } | Stop-Process    # KILL
                Start-Sleep -Seconds 5
            }
        }
        else {
            Write-Verbose "No processes matched to terminate."
        }
        return $null
    }
}

function Uninstall-ScreenConnect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $InstanceID,
        [Parameter(Mandatory = $true)]
        $install
    )

    if ($install.UninstallString) {
        $AgentVersion = $install.DisplayVersion
        $UninstallString = "$($install.UninstallString) /quiet /norestart"
        Write-Verbose "Uninstalling Instance ID: $InstanceID version $AgentVersion now..."
        Write-Verbose "Uninstall string for Instance ID $($InstanceID): $UninstallString"
        Write-Verbose "DisplayVersion: $($install.DisplayVersion)"
        Write-Verbose "Publisher: $($install.Publisher)"
        Write-Verbose "InstallDate: $($install.InstallDate)"
        if ($Uninstall) {
            # First, kill any running ScreenConnect processes that are not from safe instances:
            Remove-ScreenConnect-Processes -InstanceID $InstanceID
            # Use PowerShell to uninstall the ScreenConnect Client via MSI package control:
            $Package = Get-Package -AllVersions | Where-Object -Property Name -Like 'ScreenConnect Client*($InstanceID)' | Uninstall-Package -Force
            if($Package.Status -eq "Uninstalled") {
                Log-ClientDetails("UNINSTALL ATTEMPT COMPLETED via Uninstall-Package for Instance ID $InstanceID.") $false
                $UntrustedInstanceCount-- | Out-Null
            } else {
                # Try directly with msiexec instead:
                Start-Sleep -Seconds 5
                $Process = Start-Process cmd.exe -ArgumentList "/c $UninstallString" -Wait -PassThru
                if ($Process -and $Process.ExitCode -ne 0) {
                    # Write-Host "Uninstallation attempt for Instance ID $InstanceID failed with error code: $($Process.ExitCode). Please review manually."
                    Log-ClientDetails("UNINSTALL ATTEMPT FAILED for Instance ID $InstanceID with error code: $($Process.ExitCode). Please review manually.") $false
                }
                else {
                    # Write-Host "Uninstallation attempt completed for Instance ID $InstanceID."
                    Log-ClientDetails("UNINSTALL ATTEMPT COMPLETED via MSIEXEC for Instance ID $InstanceID.") $false
                    $UntrustedInstanceCount-- | Out-Null
                }
            }

            # Wait a few seconds before moving on to the next.
            # Start-Sleep -Seconds 5
        }
        # else {
        #     Write-Verbose "Uninstallation WOULD HAVE attempted here, but -Uninstall parameter with -Verbose is enabling REPORTING ONLY for review!"
        #     Write-Verbose "Current Trusted Instance Count: $TrustedInstanceCount`t`tCurrent Untrusted Instance Count: $UntrustedInstanceCount"
        # }
    }
    else {
        Write-Host "ERROR: No uninstall string found passed in through the install parameter to uninstall function for Instance ID $InstanceID."
    }
}

### END FUNCTIONS


# $InstalledSoftware = Get-ItemProperty -ErrorAction SilentlyContinue -Path $RegistryKeys | Select-Object DisplayName, DisplayVersion, UninstallString, Publisher, InstallDate, InstallLocation | Where-Object { $_.DisplayName -like "*screenconnect*" }
$InstalledSoftware = Get-ItemProperty -ErrorAction SilentlyContinue -Path $RegistryKeys | Select-Object * | Where-Object { $_.DisplayName -like "*screenconnect*" }

foreach ($install in $InstalledSoftware) {
    # Write-Verbose "$($install.DisplayName) Full Install Details:"
    # $install | Format-List | Out-String -stream | Write-Verbose
    if ($install.DisplayName -match "[a-fA-F0-9]{16}") {
        $InstanceID = $matches[0]
        $Version = [version]$install.DisplayVersion
        $SCdetails = Get-ScreenConnect-ConfigDetails -InstanceID $InstanceID
        $IsSaaS = $SCdetails.relayServer -like "*-relay.screenconnect.com"
        if($IsSaaS) { Write-Verbose "The Instance ID $InstanceID is a ScreenConnect SaaS Instance at version $Version." }
        $InstanceLine = "`r`n -Instance ID: " + $InstanceID
        $InstanceLine += "`r`n -Instance Name: " + $SCdetails.instanceName
        $InstanceLine += "`r`n -Relay Server: " + $SCdetails.relayServer
        $InstanceLine += "`r`n -Install Path: " + $SCdetails.installPath
        $InstanceLine += "`r`n -Publisher: " + $install.Publisher
        $InstanceLine += "`r`n -Install Date: " + $install.InstallDate 
        $InstanceLine += "`r`n -Version: " + $install.DisplayVersion
        Write-Verbose "IsSaas: $IsSaas and DoNotTrustSaaS: $DoNotTrustSaaS and Version: $Version and MinimumVersion: $MinimumVersion"
        if($Version -lt $MinimumVersion -and (!($IsSaas) -or $DoNotTrustSaaS)) {
            Write-Verbose "Marking Vulnerable Version: $Version"
            $InstanceLine += "`r`n -WARNING: VULNERABLE VERSION! (Less than $MinimumVersion)"
        }
        if ($matches[0] -in $SafeInstances) {
            $TrustedInstanceCount++ | Out-Null
            $InstanceLine = "TRUSTED INSTALL by InstanceID: " + $install.DisplayName + " $InstanceLine"
            Log-ClientDetails ($InstanceLine) $true
            # Write-Host "Leaving this installation:" $install.DisplayName
        }
        elseif($IsSaaS -and !($DoNotTrustSaaS)) {
            # Trusted Because ScreenConnect.com SaaS Instance Already Protected by ConnectWise regardless of version:
            $TrustedInstanceCount++ | Out-Null
            $InstanceLine = "TRUSTED INSTALL by ConnectWise SaaS: " + $install.DisplayName + " $InstanceLine"
            Log-ClientDetails ($InstanceLine) $true
        }
        else {
            $UntrustedInstanceCount++ | Out-Null
            $InstanceLine = "UNTRUSTED INSTALL: " + $install.DisplayName + " $InstanceLine"
            Log-ClientDetails ($InstanceLine) $false
            Uninstall-ScreenConnect -InstanceID $matches[0] -install $install
        }
    }
    else {
        # Write-Host "SUMMARY: Found NO INSTANCES of ScreenConnect instances installed."
        Log-ClientDetails ("SUMMARY: Found NO INSTANCES of ScreenConnect instances installed.") $true
    }
}

# Summarize and update custom field(s):
if ($TrustedInstanceCount -gt 0) {
    # Write-Host "TRUSTED SUMMARY: Found $TrustedInstanceCount TRUSTED ScreenConnect instances installed."
    Log-ClientDetails("TRUSTED SUMMARY: Found $TrustedInstanceCount TRUSTED ScreenConnect instances installed.") $true
    Set-NinjaCustomCheckbox -CustomFieldCheckbox $NinjaCustom_TrustedCheckbox -value $true
}
else {
    # Write-Host "TRUSTED SUMMARY: Did NOT find any trusted ScreenConnect instances installed."
    Log-ClientDetails("TRUSTED SUMMARY: Did NOT find any trusted ScreenConnect instances installed.") $true
    Set-NinjaCustomCheckbox -CustomFieldCheckbox $NinjaCustom_TrustedCheckbox -value $false
}

if ($UntrustedInstanceCount -gt 0) {
    # Write-Host "UNTRUSTED SUMMARY: Found $UntrustedInstanceCount UNTRUSTED ScreenConnect instances installed."
    Log-ClientDetails("UNTRUSTED SUMMARY: Found $UntrustedInstanceCount UNTRUSTED ScreenConnect instances installed.") $false
    Set-NinjaCustomCheckbox -CustomFieldCheckbox $NinjaCustom_UntrustedCheckbox -value $true
}
else {
    # Write-Host "UNTRUSTED SUMMARY: Did NOT find any untrusted ScreenConnect instances installed."
    Log-ClientDetails("UNTRUSTED SUMMARY: Did NOT find any untrusted ScreenConnect instances installed.") $false
    Set-NinjaCustomCheckbox -CustomFieldCheckbox $NinjaCustom_UntrustedCheckbox -value $false
}

if ($TerminatedProcessCount -gt 0) {
    Log-ClientDetails("TERMINATED PROCESSS SUMMARY: Terminated $TerminatedProcessCount ScreenConnect running processes during this session.") $false
}


# Upodate Ninja Custom Field with $ClientDetails, keep the old one first if it exists:
$ClientDetails.AddRange($ClientDetails_Trusted)
$ClientDetails.AddRange($ClientDetails_Untrusted)
Write-Host ($ClientDetails -join "`r`n")
if (![string]::IsNullOrWhiteSpace($NinjaCustom_ClientDetails) -and !($UpdateCheckboxesOnly)) {
    if ($ClearCustomHistory) {
        $ClientDetails | Ninja-Property-Set-Piped $NinjaCustom_ClientDetails
    }
    else {
        ($OrigClientDetails, $ClientDetails) | Ninja-Property-Set-Piped $NinjaCustom_ClientDetails
    }
} elseif (![string]::IsNullOrWhiteSpace($NinjaCustom_ClientDetails) -and $UpdateCheckboxesOnly) {
    Write-Verbose "NOT updating custom client details field due to UpdateCheckboxesOnly flag!"
}

