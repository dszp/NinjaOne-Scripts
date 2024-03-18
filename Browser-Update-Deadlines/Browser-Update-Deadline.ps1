<# Browser-Update-Deadline.ps1
NOTE: Only covers Local Machine policy, not per-user registry keys. Run as SYSTEM or Administrator. Chrome, Edge Chromium, Brave, and Firefox only.

Version 0.0.1 - 2024-01-18 - Initial version by David Szpunar, testing only, feedback and testing requested.
Version 0.0.2 - 2024-01-28 - Modified by Sebastian Schmidt, Added Brave & Firefox fixed RelaunchNotificationPeriod not being applied.
Version 0.0.3 - 2024-01-29 - Modified by David Szpunar, updated docs, tweaked a variable typo under Brave settings, added RelaunchWindow for all but Firefox, fixed a registry Type mismatch.

LICENSE: Provided without warranty or guarantee of fitness for any purposes. Code freely available for use or reuse.

USAGE:
With no arguments, this script will report on whether any browser browser update deadlines are in place for Chrome or Edge and what they are.

With the -NotifyRecommended switch, Chrome, Edge, Brave, and Firefox will have their registry keys updated to notify the user that a restart is recommended.
With the -NotifyRequired switch, Chrome, Edge, Brave, and Firefox will have their registry keys updated to notify the user that a restart is required.
With the -NotifyDays or -NotifyMS switches, the notification timeframe will be set to the specified number of days or milliseconds (1-23 days). 7 days is the default. Firefox is not affected by this.
With the -RelaunchWindow switch, the RelaunchWindow for Chrome, Edge, and Brave will be set to update for 120 minutes after 2:00am, unless you configure a different time. Firefox is not affected by this.
With the -ForceUpdate switch, Chrome, Edge, Brave, and Firefox registry keys will be created even if the application's HKLM:\SOFTWARE\Policies\ key doesn't exist yet.

Use -Duration, -Hour, and -Minute parameters to configure the RelaunchWindow for Chrome, Edge, and Brave if you use the -NotifyRequired and -RelaunchWindow switches and want to specify a different time than the default.
    (The default is 2:00am for a period of 120 minutes, and the browsers otherwise will not update automatically before this time even if the deadline is reached.)

Alternately, use the following switches to unset the deadlines:
With the -NoDeadlines switch, it will remove any browser autoupdate deadline registry keys for Chrome, Edge, Brave, and Firefox.
With the -NoChromeDeadline switch, it will remove any Chrome autoupdate deadline registry keys.
With the -NoEdgeDeadline switch, it will remove any Edge autoupdate deadline registry keys.
With the -NoBraveDeadline switch, it will remove any Brave autoupdate deadline registry keys.
With the -NoFirefoxDeadline switch, it will remove any Firefox autoupdate deadline registry keys.

CHROME REFERENCE:
    RelaunchNotification:
        https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::RelaunchNotification
        https://chromeenterprise.google/policies/#RelaunchNotification
    RelaunchNotificationPeriod:
        https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::RelaunchNotificationPeriod
        https://chromeenterprise.google/policies/#RelaunchNotificationPeriod
    RelaunchWindow:
        https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::RelaunchWindow
        https://chromeenterprise.google/policies/?policy=RelaunchWindow
    FAQ about Managing Chrome Updates from Google: https://support.google.com/chrome/a/answer/6350036?sjid=14781490175146289422-NC
    Timing note about frequenty of update notifications during the RelaunchNotificationPeriod: https://chromeenterprise.google/policies/#RelaunchNotificationPeriod
        "Allows you to set the time period, in milliseconds, over which users are notified that Google Chrome must be relaunched or that a 
        Google ChromeOS device must be restarted to apply a pending update.
        Over this time period, the user will be repeatedly informed of the need for an update. For Google ChromeOS devices, a 
        restart notification appears in the system tray according to the RelaunchHeadsUpPeriod policy. For Google Chrome browsers, 
        the app menu changes to indicate that a relaunch is needed *once one third of the notification period passes.* This notification 
        changes color once *two thirds of the notification period passes,* and again once the full notification period has passed. 
        The additional notifications enabled by the RelaunchNotification policy follow this same schedule.
        If not set, the default period of 604800000 milliseconds (one week) is used."

EDGE REFERENCE:
    RelaunchNotification:
        https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::RelaunchNotification
        https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#relaunchnotification
    RelaunchNotificationPeriod:
        https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::RelaunchNotificationPeriod
        https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#relaunchnotificationperiod
    RelaunchWindow:
        https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#relaunchwindow
        
BRAVE REFERENCE:
    https://support.brave.com/hc/en-us/articles/360039248271-Group-Policy

FIREFOX REFERENCE:
    https://admx.help/?Category=Firefox
    https://github.com/mozilla/policy-templates/releases

Script Variables with the argument names may also bet set as checkboxes for NinjaRMM in the GUI.

Links provided in comments to specific documentation for most registry keys at https://admx.help/ for review.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][Int16] $NotifyDays = 7, #RelaunchNotificationPeriod in days, convert to milliseconds between 3600000 and 2000000000, default 604800000 (7 days)
    [Parameter(Mandatory = $false)][Int64] $NotifyMS, #RelaunchNotificationPeriod in milliseconds between 3600000 and 2000000000, default 604800000 (7 days), overrides Days if exists
    [switch] $NotifyRecommended,
    [switch] $NotifyRequired,
    [switch] $NoDeadlines,
    [switch] $NoChromeDeadline,
    [switch] $NoEdgeDeadline,
    [switch] $NoBraveDeadline,
    [switch] $NoFirefoxDeadline,
    [switch] $ForceUpdate,
    [switch] $RelaunchWindow,
    [ValidateRange(1,1440)]
    [int] $Duration = 120,
    [ValidateRange(0,23)]
    [int] $Hour = 2,
    [ValidateRange(0,59)]
    [int] $Minute = 0
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

if ($NotifyDays -lt 1 -or $NotifyDays -gt 23) {
    Write-Host "ERROR: NotifyDays must be between 1 and 23 if set (default is 7)."
    exit 1
}
if (!$NotifyMS -or ($NotifyMS -le 3600000 -and $NotifyMS -ge 2000000000)) {
    $NotifyMS = $NotifyDays * 86400000
}
if ($NotifyMS -lt 3600000 -or $NotifyMS -gt 2000000000) {
    Write-Host "ERROR: NotifyMS must be between 3600000 and 2000000000 if set (default is 604800000 or 7 days)."
    exit 1
}

# Set Error Action to Silently Continue for the remainder of the script
$ORIG_ErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

if ($NoDeadlines) {
    Write-Host "Will update Chrome, Edge, Brave and Firefox relaunch notifications to default by removing registry keys, if they exist.`n"
}
if ($NoChromeDeadline) {
    Write-Host "Will update Chrome relaunch notifications to default by removing registry keys, if they exist.`n"
}
if ($NoEdgeDeadline) {
    Write-Host "Will update Edge relaunch notifications to default by removing registry keys, if they exist.`n"
}
if ($NoBraveDeadline) {
    Write-Host "Will update Brave relaunch notifications to default by removing registry keys, if they exist.`n"
}
if ($NoFirefoxDeadline) {
    Write-Host "Will update Firefox auto update to default by removing registry keys, if they exist.`n"
}
if (!$NoDeadlines -and !$NoChromeDeadline -and !$NoEdgeDeadline -and !$NoBraveDeadline -and !$NoFirefoxDeadline -and !$NotifyRecommended -and !$NotifyRequired) {
    Write-Host "Report-only mode, will not adjust any registry values.`n"
}
if ($NotifyRecommended) {
    Write-Host "Update Chrome, Edge, Brave and Firefox relaunch notification to RECOMMENDED for $NotifyDays days ($NotifyMS milliseconds).`n"
}
elseif ($NotifyRequired) {
    Write-Host "Update Chrome, Edge, Brave and Firefox relaunch notification to REQUIRED for $NotifyDays days ($NotifyMS milliseconds).`n"
}

$RelaunchWindowJSON = @"
{"entries": [{"duration_mins": $Duration,"start": {"hour": $Hour,"minute": $Minute}}]}
"@

Write-Host "----------HELP NOTES----------"
Write-Host "KEY: RelaunchNotification not set (the default) will indicate to the user that a relaunch is required via suble changes to the browser menu."
Write-Host "RelaunchNotification set to 1 prompts a user that a restart is recommended or required, 2 shows a prompt to the user indiacating a relaunch is required."
Write-Host "The user can dismiss these warnings unless the RelaunchNotification is set to 2 and RelaunchNotificationPeriod milliseconds value has expired."
Write-Host "RelaunchNotificationPeriod value is set in milliseconds between 3600000 (1 day) and 2000000000 (~23 days), default 604800000 (7 days)."
Write-Host "Firefox just has one setting 'Application Autoupdate' If this policy is enabled, Firefox is automatically updated without user approval. If this policy is disabled, Firefox updates are downloaded but the user can choose when to install the update."
Write-Host "----------END HELP----------"

<#
CHROME: https://admx.help/?Category=ChromeEnterprise
https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::RelaunchNotification
https://chromeenterprise.google/policies/#RelaunchNotification
https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::RelaunchNotificationPeriod
https://chromeenterprise.google/policies/#RelaunchNotificationPeriod
https://admx.help/?Category=Chrome&Policy=Google.Policies.Chrome::RelaunchWindow
https://chromeenterprise.google/policies/?policy=RelaunchWindow
#>
Write-Host "`nCHROME:"
$ChromeRelaunchNotification = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotification")
$ChromeRelaunchNotificationPeriod = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotificationPeriod")
$ChromeRelaunchWindow = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchWindow")
if ($ChromeRelaunchNotification -eq 1 -or $ChromeRelaunchNotification -eq 2 -or $ForceUpdate) {
    Write-Host "Chrome Relaunch Notification is set to $ChromeRelaunchNotification (and $ChromeRelaunchNotificationPeriod milliseconds is the Notification Period)."
    Write-Host "The Chrome Relaunch Window is set to '$ChromeRelaunchWindow'."
    $IsRelaunchNotNull++
    if ($NoDeadlines -or $NoChromeDeadline) {
        Write-Host "Removing Chrome registry keys RelaunchNotification, RelaunchNotificationPeriod, and RelaunchWindow to return to defaults (SUBTLE RESTART RECOMMENDATION)."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotification"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotificationPeriod"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchWindow"
        $IsRelaunchNotNull
    }
}

$ChromeRelaunchNotification = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotification")
$ChromeRelaunchNotificationPeriod = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotificationPeriod")
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome") -and $ForceUpdate) {
    Write-Host "Creating Google Policies key as it doesn't exist yet."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
}
if ($NotifyRecommended -and ((Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome") -or $ForceUpdate)) {
    Write-Host "Intially, Chrome Relaunch Notification is set to $ChromeRelaunchNotification (and $ChromeRelaunchNotificationPeriod milliseconds is the current Notification Period)."
    if (!$NoChromeDeadline) {
        Write-Host "Setting Chrome registry keys RelaunchNotification to 1 (RECOMMEND RELAUNCH) and RelaunchNotificationPeriod to $NotifyMS ($NotifyDays days)."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotification" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotificationPeriod" -Value $NotifyMS -Type DWord -Force
    }
}
if ($NotifyRequired -and ((Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome") -or $ForceUpdate)) {
    Write-Host "Intially, Chrome Relaunch Notification is set to $ChromeRelaunchNotification (and $ChromeRelaunchNotificationPeriod milliseconds is the current Notification Period)."
    if (!$NoChromeDeadline) {
        Write-Host "Setting Chrome registry keys RelaunchNotification to 2 (REQUIRE RELAUNCH) and RelaunchNotificationPeriod to $NotifyMS ($NotifyDays days)."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotification" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchNotificationPeriod" -Value $NotifyMS -Type DWord -Force
        if($RelaunchWindow) {
            Write-Host "Setting Chrome Notification Window to: $RelaunchWindowJSON"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "RelaunchWindow" -Value "$RelaunchWindowJSON" -Type String -Force
        }
    }
}

<#
EDGE: https://admx.help/?Category=EdgeChromium
https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::RelaunchNotification
https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#relaunchnotification
https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::RelaunchNotificationPeriod
https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#relaunchnotificationperiod
https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#relaunchwindow
edge://policy/
#>
Write-Host "`nEDGE:"
$EdgeRelaunchNotification = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotification")
$EdgeRelaunchNotificationPeriod = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotificationPeriod")
$EdgeRelaunchWindow = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchWindow")
if ($EdgeRelaunchNotification -eq 1 -or $EdgeRelaunchNotification -eq 2 -or $ForceUpdate) {
    Write-Host "Edge Relaunch Notification is set to $EdgeRelaunchNotification (and $EdgeRelaunchNotificationPeriod milliseconds is the Notification Period)."
    Write-Host "The Edge Relaunch Window is set to '$EdgeRelaunchWindow'."
    if ($NoDeadlines -or $NoEdgeDeadline) {
        Write-Host "Removing Edge registry keys RelaunchNotification, RelaunchNotificationPeriod, and RelaunchWindow to return to defaults (SUBTLE RESTART RECOMMENDATION)."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotification"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotificationPeriod"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchWindow"
    }
}

$EdgeRelaunchNotification = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotification")
$EdgeRelaunchNotificationPeriod = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotificationPeriod")
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge") -and $ForceUpdate) {
    Write-Host "Creating Edge Policies key as it doesn't exist yet."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
}
if ($NotifyRecommended -and ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge") -or $ForceUpdate)) {
    Write-Host "Intially, Edge Relaunch Notification is set to $EdgeRelaunchNotification (and $EdgeRelaunchNotificationPeriod milliseconds is the current Notification Period)."
    if (!$NoEdgeDeadline) {
        Write-Host "Setting Edge registry keys RelaunchNotification to 1 (RECOMMEND RELAUNCH) and RelaunchNotificationPeriod to $NotifyMS ($NotifyDays days)."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotification" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotificationPeriod" -Value $NotifyMS -Type DWord -Force
    }
}
if ($NotifyRequired -and ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) -or $ForceUpdate) {
    Write-Host "Intially, Edge Relaunch Notification is set to $EdgeRelaunchNotification (and $EdgeRelaunchNotificationPeriod milliseconds is the current Notification Period)."
    if (!$NoEdgeDeadline) {
        Write-Host "Setting Edge registry keys RelaunchNotification to 2 (REQUIRE RELAUNCH) and RelaunchNotificationPeriod to $NotifyMS ($NotifyDays days)."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotification" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchNotificationPeriod" -Value $NotifyMS -Type DWord -Force
        if($RelaunchWindow) {
            Write-Host "Setting Edge Notification Window to: $RelaunchWindowJSON"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "RelaunchWindow" -Value "$RelaunchWindowJSON" -Type String -Force
        }
    }
}

<#
BRAVE:
https://support.brave.com/hc/en-us/articles/360039248271-Group-Policy
#>
Write-Host "`nBRAVE:"
$BraveRelaunchNotification = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotification")
$BraveRelaunchNotificationPeriod = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotificationPeriod")
$BraveRelaunchWindow = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchWindow")
if ($BraveRelaunchNotification -eq 1 -or $BraveRelaunchNotification -eq 2 -or $ForceUpdate) {
    Write-Host "Brave Relaunch Notification is set to $BraveRelaunchNotification (and $BraveRelaunchNotificationPeriod milliseconds is the Notification Period)."
    Write-Host "The Brave Relaunch Window is set to '$BraveRelaunchWindow'."
    $IsRelaunchNotNull++
    if ($NoDeadlines -or $NoBraveDeadline) {
        Write-Host "Removing Brave registry keys RelaunchNotification, RelaunchNotificationPeriod, and RelaunchWindow to return to defaults (SUBTLE RESTART RECOMMENDATION)."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotification"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotificationPeriod"
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchWindow"
        $IsRelaunchNotNull
    }
}

$BraveRelaunchNotification = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotification")
$BraveRelaunchNotificationPeriod = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotificationPeriod")
if (!(Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave") -and $ForceUpdate) {
    Write-Host "Creating Brave Policies key as it doesn't exist yet."
    New-Item -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Force | Out-Null
}
if ($NotifyRecommended -and ((Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave") -or $ForceUpdate)) {
    Write-Host "Intially, Brave Relaunch Notification is set to $BraveRelaunchNotification (and $BraveRelaunchNotificationPeriod milliseconds is the current Notification Period)."
    if (!$NoChromeDeadline) {
        Write-Host "Setting Brave registry keys RelaunchNotification to 1 (RECOMMEND RELAUNCH) and RelaunchNotificationPeriod to $NotifyMS ($NotifyDays days)."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotification" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotificationPeriod" -Value $NotifyMS -Type DWord -Force
    }
}
if ($NotifyRequired -and ((Test-Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave") -or $ForceUpdate)) {
    Write-Host "Intially, Brave Relaunch Notification is set to $BraveRelaunchNotification (and $BraveRelaunchNotificationPeriod milliseconds is the current Notification Period)."
    if (!$NoBraveDeadline) {
        Write-Host "Setting Brave registry keys RelaunchNotification to 2 (REQUIRE RELAUNCH) and RelaunchNotificationPeriod to $NotifyMS ($NotifyDays days)."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotification" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchNotificationPeriod" -Value $NotifyMS -Type DWord -Force
        if($RelaunchWindow) {
            Write-Host "Setting Brave Notification Window to: $RelaunchWindowJSON"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" -Name "RelaunchWindow" -Value "$RelaunchWindowJSON" -Type String -Force
        }
    }
}

<#
FIREFOX: https://admx.help/?Category=Firefox
https://github.com/mozilla/policy-templates/releases
about:policies
#>
Write-Host "`nFIREFOX:"
$FirefoxAppAutoUpdate = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate")
if ($FirefoxAppAutoUpdate -eq 1 -or $FirefoxAppAutoUpdate -eq 0 -or $ForceUpdate) {
    Write-Host "Firefox Notification is initially set to $FirefoxAppAutoUpdate"
    $IsRelaunchNotNull++
    if ($NoDeadlines -or $NoFirefoxDeadline) {
        Write-Host "Removing Firefox registry keys RelaunchNotification and RelaunchNotificationPeriod to return to defaults (SUBTLE RESTART RECOMMENDATION)."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate"
        $IsRelaunchNotNull
    }
}

$FirefoxAppAutoUpdate = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate")
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox") -and $ForceUpdate) {
    Write-Host "Creating Firefox Policies key as it doesn't exist yet."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Force | Out-Null
}
if ($NotifyRecommended -and ((Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox") -or $ForceUpdate)) {
    Write-Host "Firefox AppAutoUpdate is set to $FirefoxAppAutoUpdate"
    if (!$NoFirefoxDeadline) {
        Write-Host "Setting Firefox registry keys AppAutoUpdate to 0 (RECOMMEND RELAUNCH)"
        # If this policy is disabled, Firefox updates are downloaded but the user can choose when to install the update.
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate" -Value 0 -Type DWord -Force
    }
}
if ($NotifyRequired -and ((Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox") -or $ForceUpdate)) {
    Write-Host "Firefox AppAutoUpdate is set to $FirefoxAppAutoUpdate"
    if (!$NoFirefoxDeadline) {
       # If this policy is enabled, Firefox is automatically updated without user approval.
        Write-Host "Setting Firefox registry keys AppAutoUpdate to 1 (FORCE RELAUNCH)"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "AppAutoUpdate" -Value 1 -Type DWord -Force
    }
}

# Restore original ErrorActionPreference
$ErrorActionPreference = $ORIG_ErrorActionPreference

exit 0