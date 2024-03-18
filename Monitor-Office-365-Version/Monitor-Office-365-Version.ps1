<# Monitor-Office-365-Version.ps1
2023-08-14 - Updated by David Szpunar to use variable for custom field name and catch registry key not found where Office not installed. 
    Also adds output of current channel to a second custom field.
2023-11-15 - Updated by David Szpunar to add the Reported Platform (x86 or x64) for the ClickToRun installation to the end of the version output.
    Also updated to check the ClientVersionToReport key instead of the ClientXnoneVersion if the latter doesn't exist.
2023-11-16 - Updated by David Szpunar to fix a logic bug in previous release.

Output: The defined $customField_office365Version custom field (can be global or role-specific, if configured for the role in use) 
is set to the string "latest" if the latest version of Office is currently installed, or the version number otherwise. It's left 
blank if Office Click2Run is not installed based on detected registry key.

The custom field in $customField_office365Channel is also updated with the current Office update channel configured on the system.

Description of Microsoft Office update channels: https://learn.microsoft.com/en-us/deployoffice/updates/overview-update-channels
List of CDNBaseUrls for Office 365 used for mapping to channel names: https://clients.config.office.net/releases/v1.0/OfficeReleases
Webpage list of latest Office versions: https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
(This URL must be accessible from this script for this script to work properly)

SOURCE: https://discord.com/channels/676451788395642880/1072879047329202258/1140650471695061042
ORIGINAL SOURCE: https://www.cyberdrain.com/automating-with-powershell-monitoring-office-releases/
Saved search in Ninja example: https://discord.com/channels/676451788395642880/1072879047329202258/1140651444714868798
#>

##### CONFIG
# Custom field name to write output to. Must have script write access.
$customField_office365Version = 'office365Version'

# Custom field name to write currently selected channel to. Must have script write access.
$customField_office365Channel = 'office365Channel'
##### END CONFIG

try {
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\ClientXnoneVersion") {
        $ReportedVersion = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "ClientXnoneVersion" -ErrorAction Stop
    } else {
        $ReportedVersion = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "ClientVersionToReport" -ErrorAction Stop
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    Write-Host "No registry key found, Office Click2Run likely not installed."
    Ninja-Property-Set $customField_office365Version $null
    exit 0
} catch [System.Management.Automation.PSArgumentException] {
    Write-Host "Registry path found but property key ClientXnoneVersion was not found, Office may be installed but not the Click2Run version."
    Ninja-Property-Set $customField_office365Version $null
}
try {
    $Channel = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "CDNBaseUrl" -ErrorAction Stop | Select-Object -Last 1
} catch [System.Management.Automation.ItemNotFoundException] {
    Write-Host "ClientXnoneVersion key found but CDNBaseUrl key not found. Something is wrong or misconfigured."
    Ninja-Property-Set $customField_office365Version 'error'
    exit 1
}
# Gather Office Bitness
$ReportedPlatform = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -Name "Platform" -ErrorAction Continue

try {
    $CloudVersionInfo = Invoke-RestMethod 'https://clients.config.office.net/releases/v1.0/OfficeReleases' -ErrorAction Stop
} catch [System.Net.WebException] {
    Write-Host "Unable to make web request to clients.config.office.net. Setting custom fields blank (not saving) and quitting. Installed version of Office is reported as: $($ReportedVersion)"
    Ninja-Property-Set $customField_office365Version $null
    Ninja-Property-Set $customField_office365Channel $null
    exit 1
}

$UsedChannel = $cloudVersioninfo | Where-Object { $_.OfficeVersions.cdnBaseURL -eq $channel }

# Write the selected channel to the provided custom field:
Ninja-Property-Set $customField_office365Channel "$($UsedChannel.Channel)"

if ($UsedChannel.latestversion -eq $ReportedVersion) {
    Write-Host "Currently using the latest version of Office in the $($UsedChannel.Channel) Channel: $($ReportedVersion) on the $ReportedPlatform platform."
    Ninja-Property-Set $customField_office365Version latest
    exit 0
}
else {
    Write-Host "Not using the latest version in the $($UsedChannel.Channel) Channel. Check if version is still supported"
    $OurVersion = $CloudVersionInfo.OfficeVersions | Where-Object -Property legacyVersion -EQ $ReportedVersion
    if ($OurVersion.endOfSupportDate -eq "0001-01-01T00:00:00Z") {
        Write-Host "This version does not yet have an end-of-support date. You are running a current version on the $ReportedPlatform platform, but not the latest. Your version is $($ReportedVersion) and the latest version is $($UsedChannel.latestVersion)"
        Ninja-Property-Set $customField_office365Version "$ReportedVersion $ReportedPlatform"
        exit 0
    }
    if ($OurVersion.endOfSupportDate) {
        Write-Host "This version will not be supported at $($OurVersion.endOfSupportDate). Your version is $($ReportedVersion) on the $ReportedPlatform platform and the latest version is $($UsedChannel.latestVersion)"
        Ninja-Property-Set $customField_office365Version "$ReportedVersion $ReportedPlatform"
        exit 1
    }
    else {
        Write-Host "Could not find version in the supported versions list. This version is most likely no longer supported. Your version is $($ReportedVersion) on the $ReportedPlatform platform and the latest version is $($UsedChannel.latestVersion)."
        Ninja-Property-Set $customField_office365Version "$ReportedVersion $ReportedPlatform"
        exit 1
    }
}
