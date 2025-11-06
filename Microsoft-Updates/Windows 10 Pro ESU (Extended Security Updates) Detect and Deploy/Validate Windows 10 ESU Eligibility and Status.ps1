#requires -version 5.1

<#
 .SYNOPSIS
  Validates Windows 10 ESU eligibility and current ESU activation status, and updates NinjaOne properties/tags plus an HTML report.

 .DESCRIPTION
  Performs the following checks and updates:
  - OS detection (Windows 11 vs Windows 10 22H2)
  - Robust prerequisite KB detection (KB5046613 by default) using multiple strategies
  - Windows Update network reachability tests
  - ESU installation detection (Years 1–3 via SoftwareLicensingProduct)
  - Builds an HTML summary and updates NinjaOne custom fields and tags

  Writes NinjaOne custom fields: ESUStatus, ESUEligible, ESULastCheck, ESUBinaryStatus, ESUHTMLReport, esuinstalledyears.
  Sets/clears tags based on detected ESU installation years.

 .PARAMETER None
  This script takes no parameters.

 .EXAMPLE
  pwsh -ExecutionPolicy Bypass -File ".\Validate Windows 10 ESU Eligibility and Status.ps1"

 .NOTES
  ORIGINAL SOURCE: https://discord.com/channels/676451788395642880/1426334309404639366/1427756567578542222
  ORIGINAL DATE: 2025-11-04
  ORIGINAL AUTHOR: @joeywork

  CHANGES: Updated by David Szpunar
  Added NinjaOne tags and updated documentation
  VERSION: 0.9.0 (2025-11-05)

  Microsoft source with prerequisites and instructions for Windows 10 Pro commercial ESU deployment:
  https://learn.microsoft.com/en-us/windows/whats-new/enable-extended-security-updates

 .LIMITATIONS
  - Best results when run elevated (CBS registry queries may require admin privileges)
  - Designed for Windows 10 22H2 (build 19045.*); Windows 11 is marked N/A for ESU
  - Network tests may be affected by proxies/firewalls
  - NinjaOne fields/tags are optional; the script continues if they are missing

 .NINJAONE FIELDS AND TAGS
  Custom Fields (device-level):
  - ESUStatus (Text)
  - ESUEligible (Text/Boolean)
  - ESULastCheck (Text, timestamp)
  - ESUBinaryStatus (Text)
  - ESUHTMLReport (WYSIWYG)
  - esuinstalledyears (Text)

  Tags (optional):
  - "ESU Active"
  - "ESU Not Active"
  - "ESU Active Year 1"
  - "ESU Active Year 2"
  - "ESU Active Year 3"

  NOTE: The "Not Active" tag is commented out so machines will not be tagged simply because they are not ESU active. 
  However, the "Not Active" tag is removed explicitly if no ESU years are detected, in case it was already applied.
  Uncomment the Set-NinjaTag "ESU Not Active" line if you want to tag all machines that are not ESU active.
#>

# Speed up commands that would show progress
$ProgressPreference = 'SilentlyContinue'

#region Helpers

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp][$Level] $Message"
}

function Test-KBInstalled {
    <#
        .SYNOPSIS
            Reliably determines whether a specific KB is installed.
        .DESCRIPTION
            Checks via:
              1) CBS registry package names (primary method)
              2) Get-WindowsPackage (DISM PowerShell API)
              3) Raw DISM output
              4) Get-HotFix (often incomplete for LCUs/SSUs)
              5) WMI Win32_QuickFixEngineering
        .PARAMETER KB
            The KB identifier (e.g., 'KB5046613')
        .OUTPUTS
            [bool]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('(?i)KB\d+')]
        [string]$KB
    )

    $pattern = "(?i).*${KB}.*"

    # Check if running with elevated privileges
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        Write-Log "Script not running with elevated privileges; CBS registry check may fail" 'ERROR'
    }

    # 1) Primary: CBS registry search for package names
    try {
        $cbsRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
        $cbsPackages = Get-ChildItem $cbsRoot -ErrorAction Stop
        $cbs = $cbsPackages | Where-Object { $_.PSChildName -match $pattern }
        if ($cbs) {
            Write-Log "KB found in CBS registry packages: $($cbs.PSChildName -join ', ')" 'DEBUG'
            return $true
        } else {
            Write-Log "KB not found in CBS registry. Packages checked: $($cbsPackages.PSChildName -join ', ')" 'DEBUG'
        }
    } catch {
        Write-Log "CBS registry check failed: $($_.Exception.Message)" 'ERROR'
    }

    # 2) Fallback: Get-WindowsPackage (DISM PowerShell API)
    try {
        $pkgs = Get-WindowsPackage -Online -ErrorAction Stop |
                Where-Object {
                    $_.PackageName -match $pattern -or $_.Description -match $pattern
                }
        if ($pkgs) {
            Write-Log "KB found via Get-WindowsPackage: $($pkgs | Select-Object -ExpandProperty PackageName -First 1)" 'DEBUG'
            return $true
        }
    } catch {
        Write-Log "Get-WindowsPackage failed: $($_.Exception.Message)" 'DEBUG'
    }

    # 3) Fallback: Raw DISM text output
    try {
        $dism = (dism /online /get-packages) 2>$null
        if ($null -ne $dism -and ($dism -match $pattern)) {
            Write-Log "KB found via DISM text output" 'DEBUG'
            return $true
        }
    } catch {
        Write-Log "DISM text output failed: $($_.Exception.Message)" 'DEBUG'
    }

    # 4) Fallback: Get-HotFix (often incomplete for LCUs/SSUs)
    try {
        $hf = Get-HotFix -Id $KB -ErrorAction SilentlyContinue
        if ($hf) {
            Write-Log "KB found via Get-HotFix" 'DEBUG'
            return $true
        }
    } catch {
        Write-Log "Get-HotFix threw: $($_.Exception.Message)" 'DEBUG'
    }

    # 5) Fallback: WMI Win32_QuickFixEngineering
    try {
        $wmi = Get-WmiObject -Class Win32_QuickFixEngineering -Filter "HotFixID = '$KB'" -ErrorAction Stop
        if ($wmi) {
            Write-Log "KB found via WMI Win32_QuickFixEngineering" 'DEBUG'
            return $true
        }
    } catch {
        Write-Log "WMI check failed: $($_.Exception.Message)" 'DEBUG'
    }

    Write-Log "KB $KB not detected by any method" 'ERROR'
    return $false
}

function Test-WUNetwork {
    <#
        .SYNOPSIS
            Checks reachability to Windows Update endpoints over 443.
        .DESCRIPTION
            Returns $true if at least one endpoint is reachable (TCP 443).
            Adjust endpoints as needed for your environment/proxies.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Endpoints = @(
            'download.windowsupdate.com',
            'dl.delivery.mp.microsoft.com',
            'fe2.update.microsoft.com',
            'tsfe.trafficshaping.dsp.mp.microsoft.com'
        ),
        [int]$Port = 443,
        [int]$MaxFailures = 2
    )

    $failures = 0
    foreach ($ep in $Endpoints) {
        try {
            $ok = Test-NetConnection -ComputerName $ep -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            if ($ok) {
                Write-Log "Network OK: ${ep}:${Port} reachable" 'DEBUG'
                return $true
            }
            else {
                Write-Log "Network FAIL: ${ep}:${Port} not reachable" 'DEBUG'
                $failures++
                if ($failures -gt $MaxFailures) { break }
            }
        } catch {
            Write-Log "Network check exception for ${ep}:${Port} - $($_.Exception.Message)" 'DEBUG'
            $failures++
            if ($failures -gt $MaxFailures) { break }
        }
    }
    return $false
}

function Get-ESUInstallationStatus {
    <#
        .SYNOPSIS
            Checks which ESU years are currently activated.
        .DESCRIPTION
            Queries SoftwareLicensingProduct for ESU Year 1, 2, and 3 activations.
            Returns a hashtable with years and their activation status.
        .OUTPUTS
            [hashtable] with keys Year1, Year2, Year3 (boolean values)
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Year1 = $false
        Year2 = $false
        Year3 = $false
    }

    try {
        Write-Log "Checking for installed ESU licenses..." 'DEBUG'
        
        # Get all Software Licensing Products
        $licenses = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
            Where-Object { $_.Name -like "*ESU*" -and $_.LicenseStatus -eq 1 }
        
        foreach ($license in $licenses) {
            Write-Log "Found active license: $($license.Name)" 'DEBUG'
            
            if ($license.Name -like "*ESU-Year1*") {
                $result.Year1 = $true
                Write-Log "ESU Year 1 is activated" 'INFO'
            }
            if ($license.Name -like "*ESU-Year2*") {
                $result.Year2 = $true
                Write-Log "ESU Year 2 is activated" 'INFO'
            }
            if ($license.Name -like "*ESU-Year3*") {
                $result.Year3 = $true
                Write-Log "ESU Year 3 is activated" 'INFO'
            }
        }
    } catch {
        Write-Log "Failed to check ESU installation status: $($_.Exception.Message)" 'ERROR'
    }

    return $result
}

#endregion Helpers

#region OS Detection

$osVersion = [System.Environment]::OSVersion.Version
# Windows 11 reports Major=10 with Build >= 22000
$isWindows11 = ($osVersion.Major -eq 10 -and $osVersion.Build -ge 22000)
$build = $osVersion.Build

Write-Log "Detected OS Version: $($osVersion.ToString()) (IsWindows11=$isWindows11)"

#endregion OS Detection

#region ESU Installation Detection

$esuInstalled = Get-ESUInstallationStatus
$installedYears = @()
if ($esuInstalled.Year1) { $installedYears += "Year 1" }
if ($esuInstalled.Year2) { $installedYears += "Year 2" }
if ($esuInstalled.Year3) { $installedYears += "Year 3" }

$esuInstalledText = if ($installedYears.Count -gt 0) {
    "Installed: $($installedYears -join ', ')"
} else {
    "No ESU installed"
}

Write-Log "ESU Installation Status: $esuInstalledText"

#endregion ESU Installation Detection

#region ESU Logic

# Bitmask flags:
# 0x1 = Windows 10 22H2 (build 19045.*)
# 0x2 = Required KB installed
# 0x4 = Network endpoints reachable
$CanApplyWin10ESU = 0

# The required ESU prerequisite KB for Win10 22H2
$requiredKB = 'KB5046613'

# Binary status text we will display in HTML
$binary = $null

if ($isWindows11) {
    # Windows 11 path: No ESU needed
    $esuStatus   = "Running Windows 11 - No ESU Patch needed"
    $esuEligible = "true"
    $statusColor = "green"
    $binary      = "N/A - Windows 11"
}
else {
    # Check Windows 10 22H2 (build 19045.*)
    if ($build -ge 19045 -and $build -lt 22000) {
        $CanApplyWin10ESU = $CanApplyWin10ESU -bor 0x1
        Write-Log "Windows 10 22H2 detected (build $build) -> flag 0x1 set" 'DEBUG'
    } else {
        Write-Log "Not Windows 10 22H2 (build $build)" 'DEBUG'
    }

    # Check KB presence (robustly)
    if (Test-KBInstalled -KB $requiredKB) {
        $CanApplyWin10ESU = $CanApplyWin10ESU -bor 0x2
        Write-Log "$requiredKB detected -> flag 0x2 set" 'DEBUG'
    } else {
        Write-Log "$requiredKB NOT detected" 'DEBUG'
    }

    # Check Windows Update endpoints reachability
    if (Test-WUNetwork) {
        $CanApplyWin10ESU = $CanApplyWin10ESU -bor 0x4
        Write-Log "Network endpoints reachable -> flag 0x4 set" 'DEBUG'
    } else {
        Write-Log "Network endpoints NOT reachable" 'DEBUG'
    }

    # Prepare status message
    if ($CanApplyWin10ESU -eq 0x7) {
        $esuStatus   = "Eligible for Win10 ESU (All prerequisites met)"
        $esuEligible = "true"
        $statusColor = "green"
    } else {
        $issues = @()
        if (-not ($CanApplyWin10ESU -band 0x1)) { $issues += "Not Windows 10 22H2" }
        if (-not ($CanApplyWin10ESU -band 0x2)) { $issues += "Missing $requiredKB" }
        if (-not ($CanApplyWin10ESU -band 0x4)) { $issues += "Network endpoints not reachable" }
        $esuStatus   = "Not eligible for Win10 ESU (Issues: $($issues -join ', '))"
        $esuEligible = "false"
        $statusColor = "red"
    }

    # Human-readable bitmask summary
    $binary = "Flags=0x{0:X} (Win10=0x1, KB=0x2, Network=0x4)" -f $CanApplyWin10ESU
}

#endregion ESU Logic

#region HTML Report

# Build HTML (raw HTML tags, suitable for RMM property rendering)
$esuInstallRow = if (-not $isWindows11) {
    "<tr>
        <td style='border: 1px solid #ddd; padding: 8px;'>ESU Installation Status</td>
        <td style='border: 1px solid #ddd; padding: 8px;'>$esuInstalledText</td>
    </tr>"
} else {
    ""
}

$htmlTable = @"
<table style='border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;'>
    <tr style='background-color: #f2f2f2;'>
        <th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Check Item</th>
        <th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Status</th>
    </tr>
    <tr>
        <td style='border: 1px solid #ddd; padding: 8px;'>ESU Eligibility</td>
        <td style='border: 1px solid #ddd; padding: 8px; color: $statusColor;'>$esuStatus</td>
    </tr>
    $esuInstallRow
    <tr>
        <td style='border: 1px solid #ddd; padding: 8px;'>Binary Status</td>
        <td style='border: 1px solid #ddd; padding: 8px;'>$binary</td>
    </tr>
    <tr>
        <td style='border: 1px solid #ddd; padding: 8px;'>Last Check</td>
        <td style='border: 1px solid #ddd; padding: 8px;'>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</td>
    </tr>
</table>
"@

#endregion HTML Report

#region NinjaOne Properties

try {
    Ninja-Property-Set ESUStatus $esuStatus
    Ninja-Property-Set ESUEligible $esuEligible
    Ninja-Property-Set ESULastCheck (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Ninja-Property-Set ESUBinaryStatus $binary
    Ninja-Property-Set ESUHTMLReport $htmlTable
    Ninja-Property-Set esuinstalledyears $esuInstalledText
    Write-Log "Successfully updated NinjaOne Properties with ESU status"
} catch {
    Write-Log "Failed to set NinjaOne Properties: $($_.Exception.Message)" 'ERROR'
}

try {
    if ($installedYears.Count -gt 0) {
        try {
            if ($esuInstalled.Year1) { Set-NinjaTag "ESU Active Year 1" }
            if ($esuInstalled.Year2) { Set-NinjaTag "ESU Active Year 2" }
            if ($esuInstalled.Year3) { Set-NinjaTag "ESU Active Year 3" }
            Remove-NinjaTag "ESU Not Active" 2>$null | Out-Null
            Set-NinjaTag "ESU Active" 2>$null | Out-Null
        }
        catch {
            Write-Warning "Failed to set NinjaOne Tags: $($_.Exception.Message)"
        }
    }
    else {
        try {
            Remove-NinjaTag "ESU Active" 2>$null | Out-Null
            Remove-NinjaTag "ESU Active Year 1" 2>$null | Out-Null
            Remove-NinjaTag "ESU Active Year 2" 2>$null | Out-Null
            Remove-NinjaTag "ESU Active Year 3" 2>$null | Out-Null
            # Only uncomment this if ALL computers should have the ESU Not Active tag set regardless of other status!
            # Set-NinjaTag "ESU Not Active"
        }
        catch {
            Write-Warning "Failed to set NinjaOne Tags: $($_.Exception.Message)"
        }
    }
} catch {
    Write-Log "Failed to set NinjaOne Tags: $($_.Exception.Message)" 'ERROR'
}


#endregion NinjaOne Properties

# Console output
Write-Output "Windows 10 ESU Status: $esuStatus"
if (-not $isWindows11) {
    Write-Output ("CanApplyWin10ESU Flags: 0x{0:X}" -f $CanApplyWin10ESU)
    Write-Output "ESU Installation Status: $esuInstalledText"
} else {
    Write-Output "CanApplyWin10ESU Flags: N/A (Windows 11)"
}