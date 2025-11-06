<#
.SYNOPSIS
 Deploys a Windows 10 Pro ESU product key, attempts activation, verifies ESU year status, and updates NinjaOne tags and custom fields.

.DESCRIPTION
 Installs the provided ESU product key using slmgr via cscript, attempts activation, and parses /dlv output to determine if the ESU add-on is Licensed.
 On success, the script queries WMI (SoftwareLicensingProduct) to detect which ESU years (Year 1–3) are installed.
 The script then sets NinjaOne tags to reflect ESU status and, when verification succeeds, updates the 'esuinstalledyears' device custom field.
 If verification immediately returns no installed years, the script retries the status check up to 5 times with a 15-second delay between attempts (~1.25 minutes total).
 If verification still fails after retries, the script logs a warning and does not update the custom field.
 
 ORIGINAL SOURCE: https://discord.com/channels/676451788395642880/1117936414177382530/1435378318416547983
 ORIGINAL DATE: 2025-11-04
 ORIGINAL AUTHOR: @geefpv
 
 CHANGES: Updated by David Szpunar
 Added NinjaOne tags and copied detection function and custom field from the one at https://discord.com/channels/676451788395642880/1426334309404639366/1427756567578542222 by @joeywork
 CURRENT VERSION: 0.9.0 (2025-11-05)
 
 Microsoft source with prerequisites and instructions for Windows 10 Pro commercial ESU deployment:
 https://learn.microsoft.com/en-us/windows/whats-new/enable-extended-security-updates

.PARAMETER ProductKey
 25-character ESU key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX). Can also be supplied via environment variable 'ProductKey'. Failes if not provided. 
 A Ninja Script Variable with correct name will create this variable properly.

.EXAMPLE
 pwsh -ExecutionPolicy Bypass -File ".\Deploy Windows 10 ESU Key.ps1" -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

.EXAMPLE
 $env:ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
 pwsh -ExecutionPolicy Bypass -File ".\Deploy Windows 10 ESU Key.ps1"

.NOTES
 - Requires administrative privileges.
 - Requires access to Microsoft activation endpoints.
 - Requires cscript.exe and slmgr.vbs available under %windir%\System32 or %windir%\Sysnative.
 - Designed and tested for Windows 10 22H2 (build 19045.*); other builds are not guaranteed.
 - Tag and custom field writes are attempted inside try/catch. If they don't exist, the script continues and logs warnings.

.LIMITATIONS
 - ESU status verification relies on WMI and can be delayed. The script retries for ~1.25 minutes; if still not detected, manual validation may be required.
 - When verification fails after retries, the custom field is not updated to avoid inaccurate data.

.NINJAONE FIELDS AND TAGS
 Custom Fields (device-level):
 - esuinstalledyears (Text) — Example values: "Installed: Year 1" or "Installed: Year 1, Year 2". Optional; the script will continue if missing.

 Tags (optional):
 - "ESU Active"
 - "ESU Not Active"
 - "ESU Active Year 1"
 - "ESU Active Year 2"
 - "ESU Active Year 3"
 The script continues if tags are absent; it redirects non-critical output to avoid noisy logs.

#>

param(
    [string]$ProductKey
)

# Allow product key to be provided by environment variable
if (-not $ProductKey -and $env:ProductKey) {
    $ProductKey = $env:ProductKey
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp][$Level] $Message"
}

if (-not $ProductKey) {
    Write-Log "No product key provided. Please specify -ProductKey or set the environment variable 'ProductKey'." 'ERROR'
    exit 1
}

# Basic format check (29 characters including hyphens)
if ($ProductKey -notmatch '^[A-Za-z0-9-]{29}$') {
    Write-Log "Product key format does not appear standard (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX). Quitting" 'ERROR'
    exit 1
}



function Get-ESUInstallationStatus {
    <#
        .SYNOPSIS
            Checks which ESU years are currently activated.
        .DESCRIPTION
            Queries SoftwareLicensingProduct for ESU Year 1, 2, and 3 activations.
            Returns a hashtable with years and their activation status.
            This function is from the script at https://discord.com/channels/676451788395642880/1426334309404639366/1427756567578542222 by @joeywork
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
    }
    catch {
        Write-Log "Failed to check ESU installation status: $($_.Exception.Message)" 'ERROR'
    }

    return $result
}

function Get-ExecutablePath {
    param([string[]]$Candidates)
    foreach ($c in $Candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

# Determine paths for cscript and slmgr.vbs
$windir = $env:windir
$cscriptCandidates = @(
    (Join-Path $windir 'Sysnative\cscript.exe'),
    (Join-Path $windir 'System32\cscript.exe')
)
$slmgrCandidates = @(
    (Join-Path $windir 'Sysnative\slmgr.vbs'),
    (Join-Path $windir 'System32\slmgr.vbs')
)

$cscriptPath = Get-ExecutablePath -Candidates $cscriptCandidates
$slmgrPath  = Get-ExecutablePath -Candidates $slmgrCandidates

if (-not $cscriptPath) {
    Write-Log "cscript.exe not found in expected locations under $windir." 'ERROR'
    exit 1
}
if (-not $slmgrPath) {
    Write-Log "slmgr.vbs not found in expected locations under $windir." 'ERROR'
    exit 1
}

# Commands to execute
$commands = @(
    "/ipk $ProductKey",
    "/ato",
    "/dlv"
)

$dlvOutput = ""
$failedCommands = @()

foreach ($cmd in $commands) {
    $argLine = "//nologo `"$slmgrPath`" $cmd"
    Write-Log "==> Running: $cscriptPath $argLine" 'INFO'

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $cscriptPath
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($stdout) {
        Write-Log "---- stdout ----" 'INFO'
        Write-Log $stdout 'INFO'
    }
    if ($stderr) {
        Write-Log "---- stderr ----" 'ERROR'
        Write-Log $stderr 'ERROR'
    }

    Write-Log ("Exit Code: {0}" -f $proc.ExitCode) 'DEBUG'
    if ($proc.ExitCode -ne 0) {
        Write-Log "Command '$cmd' finished with non-zero exit code $($proc.ExitCode)." 'ERROR'
        $failedCommands += $cmd
    }

    if ($cmd -eq "/dlv") {
        $dlvOutput = $stdout
    }
}

# --- ESU Activation Validation ---

$activationSuccess = $false

if ($failedCommands.Count -gt 0) {
    Write-Log "One or more slmgr commands failed: $($failedCommands -join ', ')" 'ERROR'
}

if ([string]::IsNullOrWhiteSpace($dlvOutput)) {
    Write-Log "No /dlv output captured; cannot verify activation status." 'ERROR'
} else {
    # Extract the ESU section (name contains 'Client-ESU')
    $esuSection = ($dlvOutput -split "Software licensing service version:")[1..100] -join "Software licensing service version:"
    if ($esuSection -match "Name:\s*Windows\(R\),\s*Client-ESU[^`r`n]+([\s\S]*?)(?=Name:|$)") {
        $thisESU = $matches[1]
        if ($thisESU -match "License Status:\s*Unlicensed") {
            Write-Log "Detected ESU license status: Unlicensed" 'WARN'
            $activationSuccess = $false
        } elseif ($thisESU -match "License Status:\s*Licensed") {
            Write-Log "Detected ESU license status: Licensed" 'INFO'
            $activationSuccess = $true
        } else {
            Write-Log "Unable to determine ESU license status from dlv output." 'WARN'
        }
    } else {
        Write-Log "No ESU add-on section found in slmgr /dlv output." 'WARN'
    }
}

# --- Tag & Field Updates ---
$ProgressPreference = 'SilentlyContinue' # Allow attempted tag and custom field writes to fail during try{} blocks without exiting

if ($activationSuccess -and $failedCommands.Count -eq 0) {
    Write-Log "ESU appears activated." 'INFO'
    $esuInstalled = Get-ESUInstallationStatus
    $installedYears = @()
    if ($esuInstalled.Year1) { $installedYears += "Year 1" }
    if ($esuInstalled.Year2) { $installedYears += "Year 2" }
    if ($esuInstalled.Year3) { $installedYears += "Year 3" }

    if ($installedYears.Count -lt 1) {
        $maxRetries = 5
        $retry = 0
        while ($installedYears.Count -lt 1 -and $retry -lt $maxRetries) {
            Start-Sleep -Seconds 15
            $esuInstalled = Get-ESUInstallationStatus
            $installedYears = @()
            if ($esuInstalled.Year1) { $installedYears += "Year 1" }
            if ($esuInstalled.Year2) { $installedYears += "Year 2" }
            if ($esuInstalled.Year3) { $installedYears += "Year 3" }
            $retry++
        }
    }

    $esuInstalledText = if ($installedYears.Count -gt 0) {
        "Installed: $($installedYears -join ', ')"
    } else {
        "No ESU installed"
    }
    
    try {
        if ($installedYears.Count -gt 0) {
            Ninja-Property-Set esuinstalledyears $esuInstalledText
        } else {
            Write-Log "ESU activation appears successful, but status could not be verified after retries. Please re-run a manual check. Custom fields were not updated." 'WARN'
        }
        Set-NinjaTag "ESU Active"
        if ($esuInstalled.Year1) { Set-NinjaTag "ESU Active Year 1" 2>$null | Out-Null }
        if ($esuInstalled.Year2) { Set-NinjaTag "ESU Active Year 2" 2>$null | Out-Null }
        if ($esuInstalled.Year3) { Set-NinjaTag "ESU Active Year 3" 2>$null | Out-Null }
        Remove-NinjaTag "ESU Not Active" 2>$null | Out-Null
    }
    catch {
        Write-Log "Failed to set NinjaOne Tags: $($_.Exception.Message)" 'ERROR'
    }
} else {
    Write-Log "ESU not activated successfully - check slmgr output or contact Microsoft Support." 'ERROR'
    
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
    try {
        #ninja-property-set ESUStatus $esuInstalledText
        Ninja-Property-Set esuinstalledyears $esuInstalledText
        Remove-NinjaTag "ESU Active" 2>$null | Out-Null
        Remove-NinjaTag "ESU Active Year 1" 2>$null | Out-Null
        Remove-NinjaTag "ESU Active Year 2" 2>$null | Out-Null
        Remove-NinjaTag "ESU Active Year 3" 2>$null | Out-Null
        Set-NinjaTag "ESU Not Active" 2>$null | Out-Null
    }
    catch {
        Write-Log "Failed to set NinjaOne Property: $($_.Exception.Message)" 'ERROR'
    }
}
