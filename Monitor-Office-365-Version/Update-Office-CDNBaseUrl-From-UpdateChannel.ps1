<# Update-Office-CDNBaseUrl-From-UpdateChannel.ps1
2023-08-23 - 1.0.0 - Initial script by David Szpunar to force the CDNBaseUrl registry property to match the UpdateChannel

Per https://techcommunity.microsoft.com/t5/microsoft-365-blog/how-to-manage-office-365-proplus-channels-for-it-pros/ba-p/795813
And in reference to ticket 303725 from Ninja, this script detects if the registry property 
HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\UpdateChannel exists and is not empty, and if so, takes that value and 
copies it to the property HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration\CDNBaseUrl so they match.
#>

# Define Configuration registry key location
$RegConfig = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"

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

function Set-RegistryPropertyValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$key,

        [Parameter(Mandatory=$true)]
        [string]$property,

        [Parameter(Mandatory=$true)]
        $Value
    )

    # Check if the key exists
    if (!(Test-Path $key)) {
        Write-Host "Registry key does not exist: $key (quitting, no changes made)."
        exit 1
    }

    # Check if the property already exists
    $propertyExists = $null -ne (Get-ItemProperty -Path $key -Name $property -ErrorAction SilentlyContinue)

    # Create the property if it doesn't exist
    if (!$propertyExists) {
        New-ItemProperty -Path $key -Name $property -Value $Value
        Write-Host "Created property $property in registry key $key"
    } else {
        # Set the value of the property
        Set-ItemProperty -Path $key -Name $property -Value $Value
        Write-Host "Set value of property $property in registry key $key to $Value"
    }
}

function Show-Registry-Key-Values {
    $global:UpdateChannel = Get-RegistryAndProperty $RegConfig "UpdateChannel"
    $global:CDNBaseUrl = Get-RegistryAndProperty $RegConfig "CDNBaseUrl"
    
    Write-Host "Keys from $($RegConfig):"
    Write-Host "   CDNBaseUrl URL: $global:CDNBaseUrl"
    Write-Host "UpdateChannel URL: $global:UpdateChannel"
}

# Output current registry parameter values
Show-Registry-Key-Values

if($null -ne $UpdateChannel -and $UpdateChannel -ne "") {
    if($UpdateChannel -ne $CDNBaseUrl) {
        Write-Host "`nUpdating CDNBaseUrl value to match UpdateChannel value:"
        Set-RegistryPropertyValue $RegConfig "CDNBaseUrl" $UpdateChannel
        Write-Host ""
        # Output current registry parameter values again after changes
        Show-Registry-Key-Values
    } else {
        Write-Host "`nNo changes made, keys already match."
    }
} else {
    Write-Host "`nNo changes made, UpdateChannel value is empty or doesn't exist."
}
