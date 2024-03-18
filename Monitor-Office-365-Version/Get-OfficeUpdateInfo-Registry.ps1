<# Get-OfficeUpdateInfo-Registry.ps1
2023-08-22 - 1.0.0 - Gather registry information for internal data collection in reference to ticket 303725 re: Office Updates
2023-08-23 - 1.0.1 - Update to output to a custom multi-line field only if the field name is defined; default to script output only.

How Office update branches are selected: https://techcommunity.microsoft.com/t5/microsoft-365-blog/how-to-manage-office-365-proplus-channels-for-it-pros/ba-p/795813
Issues setting Office update channel: https://learn.microsoft.com/en-us/answers/questions/938793/can-not-set-o365-update-channel
Office update channel change details: https://learn.microsoft.com/en-us/deployoffice/updates/change-update-channels
Config that forces reset on clients: https://config.office.com/officeSettings/serviceprofile
#>

##### CONFIG
# Custom mulit-line field name to write output to. Must have script write access.
# Comment out to NOT write to custom field at all!

# $customScratch = 'scratchSpaceDs'
##### END CONFIG
if($null -ne $customScratch) {
    $customCurrentValue = Ninja-Property-Get $customScratch -ErrorAction SilentlyContinue    
}
$customOutput = ''

# Scratch info:
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\16.0\Common
# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun
#       \LastScenario = UPDATE
#       \LastScenarioResult - Failure
#       \WorkstationLockState = Locked
#
#HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies

function OutputCustomFields {
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if($null -ne $customScratch -and $customScratch -ne '') {   # only write to custom field if it's defined
        if($null -ne $customOutput) {
            Ninja-Property-Set $customScratch "OUTPUT $($now):`n$customOutput"
        } else {
            Ninja-Property-Set $customScratch "NOTHING NEW $($now):`n$customCurrentValue"
        }
    }

    Write-Host "Output at $($now):`n$customOutput"
}

function Get-RegistryAndProperty ([string]$key, [string]$property) {
    try {
        $value = Get-ItemPropertyValue -Path $key -Name $property -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        $customOutput += "Key $key not found.`n"
    } catch [System.Management.Automation.PSArgumentException] {
        $customOutput += "Found key $key but property $property not found.`n"
    }
    return $value
}

$RegConfig = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

$Channel = Get-RegistryAndProperty $RegConfig "CDNBaseUrl"
$UpdateChannel = Get-RegistryAndProperty $RegConfig "UpdateChannel"
$UpdateChannelChanged = Get-RegistryAndProperty $RegConfig "UpdateChannelChanged"
$VersionToReport = Get-RegistryAndProperty $RegConfig "VersionToReport"
$ReportedVersion = Get-RegistryAndProperty $RegConfig "ClientXnoneVersion"
$UpdatesEnabled = Get-RegistryAndProperty $RegConfig "UpdatesEnabled"

$RegPoliciesOfficeUpdate = "HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate"
$SoftwarePolicies_OfficeUpdate_UpdateBranch = Get-RegistryAndProperty $RegPoliciesOfficeUpdate "UpdateBranch"

try {
    $CloudVersionInfo = Invoke-RestMethod 'https://clients.config.office.net/releases/v1.0/OfficeReleases' -ErrorAction Stop
} catch [System.Net.WebException] {
    $customOutput += "Unable to make web request to clients.config.office.net.`n"
    OutputCustomFields
    exit 1
}

$UsedChannel = $cloudVersioninfo | Where-Object { $_.OfficeVersions.cdnBaseURL -eq $channel }
$UsedChannelUpdateKey = $cloudVersioninfo | Where-Object { $_.OfficeVersions.cdnBaseURL -eq $UpdateChannel }

# Write the selected channel to the provided custom field:
$customOutput += "Keys from $($RegConfig):`n"
$customOutput += "   CDNBaseUrl URL: $Channel`n"
$customOutput += "UpdateChannel URL: $UpdateChannel`n"
$customOutput += "   Channel from CDNBaseUrl: $($UsedChannel.Channel)`n"
$customOutput += "Channel from UpdateChannel: $($UsedChannelUpdateKey.Channel)`n"
$customOutput += "Version from Install: $($ReportedVersion)`n"
$customOutput += "   Version from CDNBaseUrl Key: $($UsedChannel.latestVersion)`n"
$customOutput += "Version from UpdateChannel Key: $($UsedChannelUpdateKey.latestVersion)`n"
$customOutput += "   End of Support Date from CDNBaseUrl Key: $($UsedChannel.endOfSupportDate)`n"
$customOutput += "End of Support Date from UpdateChannel Key: $($UsedChannelUpdateKey.endOfSupportDate)`n"
$customOutput += "Update Channel Changed: $($UpdateChannelChanged)`n"
$customOutput += "Version to Report: $($VersionToReport)`n"
$customOutput += "Updates Enabled: $($UpdatesEnabled)`n"

$customOutput += "`n`nKeys from $($RegPoliciesOfficeUpdate):`n"
$customOutput += "UpdateBranch: $($SoftwarePolicies_OfficeUpdate_UpdateBranch)`n"

OutputCustomFields
