<# Harden-Security-Windows-Registry.ps1
This script configures several common registry settings that lock down Windows client (and sometimes server) security.
Usually this means disabling old protocols or requiring SMB signing, etc., and on modern networks most of these already 
should not be used, but also in theory it could break things, so only run this on systems where you know it won't have 
a negative effect, or are prepared to diagnose issues/test things after adjusting.

There is currently no automatic undo for these settings, but given that these are all basic registry settings, 
usually deleting the key or changing the value will reverse the change. Many times, rebooting is required before 
a change will take effect. These settings may be overridden by local or group policy settings, or Intune, if 
those are configured.

Version 0.0.1 - 2023-12-27 - Initial release by David Szpunar
Version 0.0.2 - 2024-03-12 - Updated to properly set (or fix) the registry value type to DWord when needed, rather than always using REG_SZ (string).
Version 0.0.3 - 2024-03-12 - Updated to disable NetBIOS over TCP/IP (NBT-NS) for physical network adapters.
#>

# SOURCE: https://discord.com/channels/676451788395642880/1063257007324414004/1187116607500197908 by Mikey O'Toole.
# Utility Function: Registry.ShouldBe - modified to skip Wow6432Node registry paths on 32-bit Windows.
## This function is used to ensure that a registry value exists and is set to a specific value.
function Registry.ShouldBe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Value,
        [Parameter(Mandatory)]
        [ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')]
        [string]$Type
    )
    begin {
        # Return if the OS is not 64-bit if the registry path includes Wow6432Node (these are only valid on 64-bit Windows).
        if(![System.Environment]::Is64BitOperatingSystem -and ($Path -like "*\Wow6432Node\*")) {
            Write-Warning ("Skipping Wow6432Node registry path on 32-bit Windows: $Path")
            return
        }
        # Make sure the registry path exists.
        if (!(Test-Path $Path)) {
            Write-Warning ("Registry path '$Path' does not exist. Creating.")
            New-Item -Path $Path -Force | Out-Null
        }
        # Make sure it's actually a registry path.
        if (!(Get-Item $Path).PSProvider.Name -eq 'Registry' -and !(Get-Item $Path).PSIsContainer) {
            throw "Path '$Path' is not a registry path."
        }
    }
    process {
        do {
            # Do nothing if the -64bit switch is set and the OS is not 64-bit.
            if(![System.Environment]::Is64BitOperatingSystem -and $64BitOnly) {
                return 0
            }
            # Do nothing if the -32bit switch is set and the OS is not 32-bit.
            if(![System.Environment]::Is64BitOperatingSystem -and $32BitOnly) {
                return 0
            }
            # Make sure the registry value exists.
            if (!(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
                Write-Warning ("Registry value '$Name' in path '$Path' does not exist. Setting to '$Value' with type '$Type'.")
                New-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force | Out-Null
            }
            # Make sure the registry value is correct.
            if ((Get-ItemProperty -Path $Path -Name $Name).$Name -ne $Value) {
                Write-Warning ("Registry value '$Name' in path '$Path' is not correct. Setting to '$Value' with type '$Type'.")
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
            }
            # Make sure the registry value type is correct.
            if ((Get-Item -Path $Path).GetValueKind($Name) -ne $Type) {
                Write-Warning ("Registry value type for key '$Name' in path '$Path' is not correct. Setting to '$Type' with value '$Value'.")
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
            }
        } while ((Get-ItemProperty -Path $Path -Name $Name).$Name -ne $Value)
    }
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsWorkstation {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    return $OS.ProductType -eq 1
}

if(!(Test-IsElevated)) {
    Write-Host "This script needs to be run with elevated permissions. Exiting..."
    exit 1
}

# Disable LLMNR: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast Registry key is not present, Hence presumed as Enabled(1), Expected value: 0
Write-Host "Disabling LLMNR Multicast Name Resolution..."
Registry.ShouldBe -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value '0' -Type 'DWord'

# SOURCE: https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102
Write-Host "Requiring SMB Signing on Client and Server..."
Registry.ShouldBe -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Value '1' -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Value '1' -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Rdr\Parameters' -Name 'EnableSecuritySignature' -Value '1' -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Rdr\Parameters' -Name 'RequireSecuritySignature' -Value '1' -Type 'DWord'

# SOURCE: https://techcommunity.microsoft.com/t5/itops-talk-blog/how-to-defend-users-from-interception-attacks-via-smb-client/ba-p/1494995
Write-host "Disallowing Insecure Guest Auth for SMB - Windows 10+ and Server 2016+..."
Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth' -Value '0' -Type 'DWord'

# SOURCE (Service): https://www.stigviewer.com/stig/microsoft_windows_10/2023-09-29/finding/V-220865
# SOURCE (Client): https://www.stigviewer.com/stig/microsoft_windows_10/2023-09-29/finding/V-220862
Write-Host "Disabling 'Allow Basic authentication' for WinRM Service and Client..."
Registry.ShouldBe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Value '0' -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Value '0' -Type 'DWord'

# SOURCE: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900
Write-Host "Enabling 'CertPaddingCheck' registry key to resolve WinVerifyTrust security issues per CVE-2013-3900..."
Registry.ShouldBe -Path 'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -Value '1' -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -Value '1' -Type 'DWord'

# SOURCE: https://ss64.com/nt/syntax-ntlm.html
Write-Host "Setting the LM and NTLMv1 authentication responses to 5 via LmCompatibilityLevel ('Send NTLMv2 response only. Refuse LM & NTLM.')..."
Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Lsa' -Name 'LmCompatibilityLevel' -Value '5' -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LmCompatibilityLevel' -Value '5' -Type 'DWord'

# SOURCE: https://www.tenforums.com/tutorials/101962-enable-disable-autoplay-all-drives-windows.html
Write-Host "Disabling Autorun(Autoplay) on all drives..."
Registry.ShouldBe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoDriveTypeAutorun' -Value 255 -Type 'DWord'
Registry.ShouldBe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoAutorun' -Value 0x01 -Type 'DWord'

##### NBT-NS Disable ####
<# Disable NetBIOS over TCP/IP (NBT-NS) via PowerShell
ORIGINAL SOURCE: https://www.reddit.com/r/sysadmin/comments/sjra2q/disable_llmnr_and_nbtns/
CURRENT SOURCE: https://www.reddit.com/r/PowerShell/comments/buh3ln/comment/epi7fg4/?utm_source=share&utm_medium=web2x&context=3
    CREDIT: https://www.reddit.com/user/PinchesTheCrab/
Information on disabling via DHCP for dynamic IPs using Windows DHCP Server:
     https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-netbios-tcp-ip-using-dhcp
Information on disabling NetBIOS over TCP/IP (NBT-NS) via DHCP when using a Fortinet FortiGate firewall for DHCP: 
    https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-disable-NetBIOS-over-TCP-IP-using-DHCP/ta-p/195730
#>

Write-Host "Disabling NetBIOS over TCP/IP (NBT-NS) and LMHOST lookup on physical network adapters..."
$filter = @'
(Description LIKE '%Intel%'
    OR Description LIKE '%Realtek%' 
    OR Description LIKE '%Broadcom%' 
    OR Description LIKE '%Surface%' 
    OR Description LIKE '%Marvell%' 
    OR Description LIKE '%Wireless%'
)
    AND TcpipNetbiosOptions <> 2
'@

# Get-CimInstance Win32_NetworkAdapterConfiguration -Filter $filter |
#     Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 }

Get-CimInstance Win32_NetworkAdapterConfiguration -Filter $filter | 
    ForEach-Object {
        $regParam = @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{0}' -f $PSItem.SettingID
            Name = 'NetbiosOptions'
            Value = 2
            Type = 'DWord'
        }
        Registry.ShouldBe @regParam
    }
##### END NBT-NS Disable #####

# Windows Desktop Only Settings
Write-Host ""
Write-Host "Checking Windows Version...."
if (Test-IsWorkstation) {
    Write-Host "Windows Desktop/Workstation Detected! Running some additional client-side-only hardening..."

    # SOURCE: https://www.stigviewer.com/stig/windows_xp/2014-01-06/finding/V-15669
    Write-Host "Prohibiting use of Internet Connection Sharing on your DNS domain network..."
    Registry.ShouldBe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value '0' -Type 'DWord'

    # SOURCE: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
    Write-Host "Enabling 'Local Security Authority (LSA) protection'..."
    Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value '1' -Type 'DWord'

    # SOURCE: https://www.stigviewer.com/stig/microsoft_windows_10/2023-09-29/finding/V-220930
    Write-Host "Do not allow anonymous enumeration of SAM accounts and shares..."
    Registry.ShouldBe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value '1' -Type 'DWord'
}
