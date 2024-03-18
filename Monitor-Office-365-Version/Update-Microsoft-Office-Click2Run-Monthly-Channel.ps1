<# Update-Microsoft-Office-Click2Run-Current-Channel.ps1

Update the Microsoft Office Click2Run release version to remove any channel version targets and customized update settings, 
clearing out related registry keys so it returns to defaults, forces the CDNBaseUrl value to the default Microsoft Office 
update value, and starts a gentle background update (waits for user to close Office to complete update).

Version 0.2.0 - 2023-08-14 - Updated by David Szpunar to clean up error reporting and loop through property removals.
Version 0.1.1 - 2023-07-31 - Updated by David Szpunar to soft update call at the end, $CDNBaseUrl config section, and add this comment to original source.
Version 0.1.0 - 2023-03-30 - Initial version from Discord user Anthony P (@anthonyp0129).

The $CDNBaseUrl can be adjusted to the URL for whichever release cycle you want. List of CDNBaseUrl options to channels mapping is at:
https://techcommunity.microsoft.com/t5/microsoft-365-blog/how-to-manage-office-365-proplus-channels-for-it-pros/ba-p/795813

SOURCE: https://discord.com/channels/676451788395642880/1072879047329202258/1135121736480854066
#>

[CmdletBinding()]
param ()

##### CONFIG
# Set this URL to the one for the Office release channel you wish to configure. Defaults to Current Channel.
# Map of channel versions to URLs:
# https://techcommunity.microsoft.com/t5/microsoft-365-blog/how-to-manage-office-365-proplus-channels-for-it-pros/ba-p/795813
$CDNBaseUrl = "http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60"
##### END CONFIG

Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}

if ([System.Environment]::Is64BitOperatingSystem) {
    $C2RPaths = @(
        (Join-Path -Path $ENV:SystemDrive -ChildPath 'Program Files (x86)\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'),
        (Join-Path -Path $ENV:SystemDrive -ChildPath 'Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe')
    )
} else {
    $C2RPaths = (Join-Path -Path $ENV:SystemDrive -ChildPath 'Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe')
}

Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration -Name CDNBaseUrl -Value "$CDNBaseUrl"
Write-Host "Updated HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun\Configuration property CDNBaseUrl to $CDNBaseUrl"

Write-Host ""
Write-Host "Attempting to remove Click2Run related update registry keys. Failures indicate keys that already didn't exist:"

$UpdateConfigPath = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
$UpdatePropertyNames = @(
    'UpdateUrl',
    'UpdateToVersion',
    'UnmanagedUpdateUrl',
    'UpdateChannel',
    'UpdateToVersion'
)

# Loop trough each property and attempt to remove properties if they exist, showing where they already do not:
foreach ($PropertyName in $UpdatePropertyNames) {
    Write-Host "" # Add newline space before output for this item.
    $PropertyValue = Test-RegistryValue -Path "$UpdateConfigPath" -Name $PropertyName -PassThru
    if($PropertyValue) {
        Write-Host "Attempting to remove existing value '$($PropertyValue.$PropertyName)' for property $($PropertyName):"
    }
    try {
        Remove-ItemProperty -Path $UpdateConfigPath -Name $PropertyName -Force -Verbose -ErrorAction Stop
    } catch [System.Management.Automation.PSArgumentException] {
        Write-Host 'Nothing to remove since this path already doesn''t exist for "Item:'
        Write-Host "$($UpdateConfigPath): $($PropertyName)""."
    } catch {
        Write-Host "Unexpected error encountered: " $PSItem.Exception.Message
    }
    finally {
        $Error.Clear()
    }
}

try {
    Write-Host ""
    Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate' -Force -Verbose -ErrorAction Stop
} catch [System.Management.Automation.ItemNotFoundException] {
    Write-Host 'Nothing to remove since this path already doesn''t exist for "Item:'
    Write-Host "Path HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate""."
} catch {
    Write-Host "Unexpected error encountered: " $PSItem.Exception.Message
}
finally {
    $Error.Clear()
}



$C2RPaths | ForEach-Object {
    if (Test-Path -Path $_) {
        $C2RPath = $_
    }
}
if ($C2RPath) {
    Write-Verbose "C2RPath: $C2RPath"
    # Force an update immediately, closing Office if it's open:
    # Start-Process -FilePath $C2RPath -ArgumentList '/update user displaylevel=false forceappshutdown=true updatepromptuser=false' -Wait
    # Kicks off Office scheduled update task to update itself, if auto-updates are enabled, but don't prompt user, wait for natural restart to update:
    Start-Process -FilePath $C2RPath -ArgumentList '/frequentupdate SCHEDULEDTASK displaylevel=false updatepromptuser=false forceappshutdown=false' -Wait
    Write-Host ""
    Write-Host "Background update to Office initiated."
} else {
    Write-Error 'No Click-to-Run Office installation detected. This script only works with Click-to-Run Office installations.'
    Exit 1
}
