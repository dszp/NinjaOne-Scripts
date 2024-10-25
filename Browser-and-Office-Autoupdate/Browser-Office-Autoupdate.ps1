<# Browser-Office-Autoupdate.ps1
NOTE: Only covers Local Machine policy, not per-user registry keys that may override these settings on a per-user basis.

Version 0.0.1 - 2024-01-15 - Initial version by David Szpunar
Version 0.0.2 - 2024-01-16 - Added Office Click-To-Run Autoupdate Blocker Removal at request of @teamitpd
Version 0.0.3 - 2024-01-16 - Adjusted Office Click-To-Run to check for UpdatesEnabled to equal "False" and update to True (rather than deleting if exists)
Version 0.0.4 - 2024-02-10 - Adjusted Firefox check to accept forced update settings (but report) so as to not fail when autoupdate is configured.
Version 0.0.5 - 2024-02-20 - Added some Write-Verbose statements to show changes NOT being made, if called with -Verbose parameter.
Version 0.0.6 - 2024-10-24 - Resolved bug in Chrome update with typo in registry key name reported by GitHub user @lyttek

LICENSE: Provided without warranty or guarantee of fitness for any purposes. Code freely available for use or reuse.

USAGE:
With no arguments, this script will report on whether any browser updates are disabled at the system level.

With the -AllowAllUpdates switch, it will remove any browser autoupdate blocker registry keys for Chrome, Edge, and Firefox.

With the -AllowChromeUpdate switch, it will enable the Chrome autoupdate policy registry keys only, if they are disabled.
With the -AllowEdgeUpdate switch, it will enable the Edge autoupdate policy registry key, if they are disabled.
With the -AllowFirefoxUpdate switch, it will enable the Firefox autoupdate policy registry key, if they are disabled.
With the -AllowOfficeUpdate switch, it will remove the Click-To-Run Office Apps for Business/Enterprise update configuration key, if it exists.

Script Variables with the argument names may also bet set as checkboxes for NinjaRMM in the GUI.

Links provided in comments to specific documentation for most registry keys at https://admx.help/ for review.

Initial Chrome SOURCE: https://discord.com/channels/676451788395642880/1072879047329202258/1156585935962640446
Original basic Chrome script from Steven at NinjaOne:
I've additionally added DisableAutoUpdateChecksCheckboxValue as one of the registry keys in this process - it also has an impact on automatic updates, with the dword being set to 1 it will never apply the updates automatically.

Evaluation script (you can uncomment the #Set-ItemProperty lines to automatically flip the values of the keys without the secondary script being needed):
Set Result Code to any, With Output to "Some Browser Updates Disabled", then hit apply.
#>
[CmdletBinding()]
param(
    [switch] $AllowAllUpdates,
    [switch] $AllowChromeUpdate,
    [switch] $AllowEdgeUpdate,
    [switch] $AllowFirefoxUpdate,
    [switch] $AllowOfficeUpdate
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

# Set Error Action to Silently Continue for the remainder of the script
$ORIG_ErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Initialize exit code variable, set to initial 0 for success (autoupdate is NOT disabled)
$AreUpdatesDisabled = 0

if ($AllowAllUpdates) {
    Write-Host "Will adjust any automatic updates to enabled (if disabled)."
}
if ($AllowChromeUpdate) {
    Write-Host "Will adjust Chrome updates to enabled (if disabled)."
}
if ($AllowEdgeUpdate) {
    Write-Host "Will adjust Edge updates to enabled (if disabled)."
}
if ($AllowFirefoxUpdate) {
    Write-Host "Will adjust Firefox updates to enabled (if disabled)."
}
if ($AllowOfficeUpdate) {
    Write-Host "Will adjust Microsoft Office CTR updates to enabled (if disabled)."
}
if (!$AllowAllUpdates -and !$AllowChromeUpdate -and !$AllowEdgeUpdate -and !$AllowFirefoxUpdate -and !$AllowOfficeUpdate) {
    Write-Host "Report-only mode, will not adjust any registry values."
}

<#
CHROME: https://admx.help/?Category=ChromeEnterprise
#>
Write-Verbose "Checking registry path HKLM:\SOFTWARE\Policies\Google\Update for disabled updates..."
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}") -eq '0') {
    Write-Host "Chrome Updates Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowChromeUpdate) {
        Write-Host "Setting Chrome Update registry key Update{8A69D345-D564-463C-AFF1-A69D9E530F96} to enabled."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Update" "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}" 1
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Chrome updates are not disabled, not changing Update{8A69D345-D564-463C-AFF1-A69D9E530F96} key."
}

if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "Update{4DC8B4CA-1BDA-483E-B5FA-D3C12E15B62D}") -eq '0') {
    Write-Host "Chrome Updates Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowChromeUpdate) {
        Write-Host "Setting Chrome Update registry key Update{4DC8B4CA-1BDA-483E-B5FA-D3C12E15B62D} to enabled."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Update" "Update{4DC8B4CA-1BDA-483E-B5FA-D3C12E15B62D}" 1
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Chrome updates are not disabled, not changing Update{4DC8B4CA-1BDA-483E-B5FA-D3C12E15B62D} key."
}

# Chrome General Autoupdate Allowed https://admx.help/?Category=GoogleUpdate&Policy=Google.Policies.Update::Pol_DefaultUpdatePolicy
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "UpdateDefault") -eq '0') {
    Write-Host "Chrome Update Override Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowChromeUpdate) {
        Write-Host "Setting Chrome Update Override registry key UpdateDefault to always allow."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Update" "UpdateDefault" 1
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Chrome update override is not disabled, not changing UpdateDefault key."
}

if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "DisableAutoUpdateChecksCheckboxValue") -eq '1') {
    Write-Host "Chrome Updates Disabled by Checkbox"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowChromeUpdate) {
        Write-Host "Removing Chrome Update registry key DisableAutoUpdateChecksCheckboxValue to allow for automatic updates."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "DisableAutoUpdateChecksCheckboxValue"
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Chrome updates are not disabled by checkbox, not removing DisableAutoUpdateChecksCheckboxValue key."
}

<#
EDGE: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies
#>
Write-Verbose "Checking registry path HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate for disabled updates..."
# Edge Updates Default https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Update::Pol_DefaultUpdatePolicy
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "UpdateDefault") -eq '0') {
    Write-Host "Edge Default Updates Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowEdgeUpdate) {
        Write-Host "Setting Edge Default Update registry key UpdateDefault to enabled."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" "UpdateDefault" 1
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Edge updates are not disabled, not changing UpdateDefault key."
}

# Edge Stable Updates https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Update::Pol_UpdatePolicyMicrosoftEdge
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}") -eq '0') {
    Write-Host "Edge Stable Updates Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowEdgeUpdate) {
        Write-Host "Setting Edge Update registry key Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} to enabled."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" 1
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Edge Stable updates are not disabled, not changing Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} key."
}

# Edge WebView Updates https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Update::Pol_UpdatePolicyMicrosoftEdgeWebView
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}") -eq '0') {
    Write-Host "Edge WebView Updates Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowEdgeUpdate) {
        Write-Host "Setting Edge WebView Update registry key Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} to enabled."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" 1
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Edge WebViewupdate override is not disabled, not changing Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} key."
}

# Remove Edge Target Version Override: https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Update::Pol_TargetVersionPrefixMicrosoftEdge
if (![string]::IsNullOrEmpty((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "TargetVersionPrefix{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"))) {
    Write-Host "Edge Targeted Release Version Configured"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowEdgeUpdate) {
        Write-Host "Removing Edge Targeted Version Override registry key TargetVersionPrefix{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "TargetVersionPrefix{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Edge Targetd Version Override is not disabled, not removing TargetVersionPrefix{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} key."
}

<#
Firefox: https://admx.help/?Category=Firefox&Policy=Mozilla.Policies.Firefox::DisableAppUpdate
#>
# Firefox Updates Block https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Update::Pol_DefaultUpdatePolicy
Write-Verbose "Checking Firefox Autoupdate Blocker..."
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableAppUpdate") -eq '1') {
    Write-Host "Firefox Updates Disabled"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowFirefoxUpdate) {
        Write-Host "Setting Edge Default Update registry key UpdateDefault to enabled."
        Set-ItemProperty "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" "DisableAppUpdate" 0
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Firefox updates are not disabled, not changing DisableAppUpdate key."
}

# Firefox Autoupdate Block: https://admx.help/?Category=Firefox&Policy=Mozilla.Policies.Firefox::AppAutoUpdate
# if (![string]::IsNullOrEmpty((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate"))) {
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate") -eq '0') {
    Write-Host "Firefox Autoupdate is configured to download but not automatically install updates (user can choose when)."
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowFirefoxUpdate) {
        Write-Host "Removing Firefox Auto Update configuration registry key AppAutoUpdate to allow user autoupdate config to take effect."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate"
        $AreUpdatesDisabled--
    }
} elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate") -eq '1') {
    Write-Host "Firefox Autoupdate is already configured to download and force-install updates (not changing)."
} elseif (![string]::IsNullOrEmpty((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate"))) {
    Write-Host "Firefox Autoupdate is configured but not to a known value."
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowFirefoxUpdate) {
        Write-Host "Removing Firefox Auto Update configuration registry key AppAutoUpdate to allow user autoupdate config to take effect."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate"
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Firefox autoupdate is not disabled, not removing the AppAutoUpdate key."
}

<#
Microsoft Office Click-To-Run
Microsoft Office 2016 option, NOT supported here but could be: https://admx.help/?Category=Office2016&Policy=office16.Office.Microsoft.Policies.Windows::L_EnableAutomaticUpdates
For Intune controls, review: https://learn.microsoft.com/en-us/mem/intune/configuration/administrative-templates-update-office
#>
Write-Verbose "Checking Microsoft Office Click-To-Run Autoupdate Blocker..."
if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "UpdatesEnabled") -eq 'False') {
    Write-Host "Microsoft Office Click-To-Run Autoupdate Blocker is set to False"
    $AreUpdatesDisabled++
    if ($AllowAllUpdates -or $AllowOfficeUpdate) {
        Write-Host "Updating Microsoft Office Click-To-Run Autoupdate ClickToRun\Configuration\UpdatesEnabled registry key to True from False"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "UpdatesEnabled"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "UpdatesEnabled" -Type String -Value 'True'
        $AreUpdatesDisabled--
    }
}
else {
    Write-Verbose "Microsoft Office Click-To-Run update blocker is not configured, not changing UpdatesEnabled key."
}

# Restore original ErrorActionPreference
$ErrorActionPreference = $ORIG_ErrorActionPreference

# Exit with result, 0 only if there are no updates disabled (regardless of any updates/changes):
if ($AreUpdatesDisabled -eq 0) {
    Write-Host "No browser updates were found to be disabled in checks AND/OR the ones found were removed."
}
else {
    Write-Host "SUMMARY: Some Browser Updates Disabled"
}
if ($AreUpdatesDisabled -le 0) {
    # Exit with 0 if all updates were disabled (including changes implemented) (success)
    exit 0
}
else {
    # Exit with the number of updates that were found to be disabled if any updates were disabled (failure)
    exit $AreUpdatesDisabled
}

