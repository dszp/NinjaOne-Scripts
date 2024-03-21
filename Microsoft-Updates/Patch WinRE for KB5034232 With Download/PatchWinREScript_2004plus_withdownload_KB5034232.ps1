<# PatchWinREScript_2004plus_withdownload.ps1
SOURCE: https://support.microsoft.com/en-us/topic/kb5034957-updating-the-winre-partition-on-deployed-devices-to-address-security-vulnerabilities-in-cve-2024-20666-0190331b-1ca3-42d8-8a55-7fc406910c10
Discord Original Link: https://discord.com/channels/676451788395642880/1072879047329202258/1197244573605445642
Discord link for start of download addition: https://discord.com/channels/676451788395642880/1195093276118765650/1195118075062788248

About this script: This script is for Windows 10, version 2004 and later versions, including Windows 11. We recommend that you use this version of the script, because it is more robust but uses features available only on Windows 10, version 2004 and later versions.

ADDITIONS v0.0.1 by David Szpunar on 2024-02-10: This is the Microsoft script, with the following changes:
- Added download of the Safe OS Dynamic Update package from Microsoft to $env:temp, for Windows 10 22H2 only. Detects x86 or x64.
- Added flag -Only1022H2 to exit immediately if the OS doesn't match Windows 10 22H2 exactly.
- If it's not Windows 10 22H2 and you don't use -Only1022H2, you still MUST use the -packagePath parameter and provide a path to the patch.
- Made the packagePath parameter optional in order to allow for the download of the package for Windows 10 22H2.
- Outputs all dism logs to dism_script_kb5034232_YYYY-MM-DD-HH-MM.log in the $env:temp folder.
- If it's been run before, exit code is 0 instead of 1 to indicate "succcss" even though nothing was changed.

I created Script Variables for Only1022H2 (checkbox) and packagePath (text) to make running the script easier.
Each of them will be used in place of script parameters if they exist and are not empty.

USAGE:
Parameter: workDir
    <Optional> Specifies the scratch space used to patch WinRE. If not specified, the script will use the default temp folder for the device.
Parameter: packagePath
    <Required except for Win 10 22H2> Specifies the path and name of the OS-version-specific and processor architecture-specific Safe OS Dynamic update package to be used to update the WinRE image.
    Note This can be a local path or a remote UNC path but the Safe OS Dynamic Update must be downloaded and available for the script to use.
    (Download location for Safe OS Update: https://www.catalog.update.microsoft.com/Search.aspx?q=Safe%20OS )
    Example: 
    .\PatchWinREScript_2004plus.ps1 -packagePath "\\server\share\windows10.0-kb5021043-x64_efa19d2d431c5e782a59daaf2d.cab
#>
################################################################################################
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
################################################################################################
Param (
    [Parameter(HelpMessage = "Work Directory for patch WinRE")][string]$workDir = "",
    [Parameter(Mandatory = $false, HelpMessage = "Path of target package")][string]$packagePath,
    [Parameter(Mandatory = $false, HelpMessage = "Only try to apply KB5034232 for Windows 10 22H2, otherwise quit.")][switch]$Only1022H2
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

$DISMLog = Join-Path $env:TEMP ("dism_script_kb5034232_" + (Get-Date -Format "yyyy-MM-dd-HH-mm") + ".log")

$CurrentWindows = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Select-Object -Property ProductName,DisplayVersion)
# ------------------------------------
# Help functions
# ------------------------------------
# Log message
function LogMessage([string]$message) {
    $message = "$([DateTime]::Now) - $message"
    Write-Host $message
}
function IsTPMBasedProtector {
    $DriveLetter = $env:SystemDrive
    LogMessage("Checking BitLocker status")
    $BitLocker = Get-WmiObject -Namespace "Root\cimv2\Security\MicrosoftVolumeEncryption" -Class "Win32_EncryptableVolume" -Filter "DriveLetter = '$DriveLetter'"
    if (-not $BitLocker) {
        LogMessage("No BitLocker object")
        return $False
    }
    $protectionEnabled = $False
    switch ($BitLocker.GetProtectionStatus().protectionStatus) {
("0") {
            LogMessage("Unprotected")
            break
        }
("1") {
            LogMessage("Protected")
            $protectionEnabled = $True
            break
        }
("2") {
            LogMessage("Uknown")
            break
        }
        default {
            LogMessage("NoReturn")
            break
        }
    }
    if (!$protectionEnabled) {
        LogMessage("Bitlocker isn’t enabled on the OS")
        return $False
    }
    $ProtectorIds = $BitLocker.GetKeyProtectors("0").volumekeyprotectorID
    $return = $False
    foreach ($ProtectorID in $ProtectorIds) {
        $KeyProtectorType = $BitLocker.GetKeyProtectorType($ProtectorID).KeyProtectorType
        switch ($KeyProtectorType) {
            "1" {
                LogMessage("Trusted Platform Module (TPM)")
                $return = $True
                break
            }
            "4" {
                LogMessage("TPM And PIN")
                $return = $True
                break
            }
            "5" {
                LogMessage("TPM And Startup Key")
                $return = $True
                break
            }
            "6" {
                LogMessage("TPM And PIN And Startup Key")
                $return = $True
                break
            }
            default { break }
        }#endSwitch
    }#EndForeach
    if ($return) {
        LogMessage("Has TPM-based protector")
    }
    else {
        LogMessage("Doesn't have TPM-based protector")
    }
    return $return
}
function SetRegistrykeyForSuccess {
    reg add HKLM\SOFTWARE\Microsoft\PushButtonReset /v WinREPathScriptSucceed /d 1 /f
}
function TargetfileVersionExam([string]$mountDir) {
    # Exam target binary
    $targetBinary = $mountDir + "\Windows\System32\bootmenuux.dll"
    LogMessage("TargetFile: " + $targetBinary)
    $realNTVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($targetBinary).ProductVersion
    $versionString = "$($realNTVersion.Split('.')[0]).$($realNTVersion.Split('.')[1])"
    $fileVersion = $($realNTVersion.Split('.')[2])
    $fileRevision = $($realNTVersion.Split('.')[3])
    LogMessage("Target file version: " + $realNTVersion)
    if (!($versionString -eq "10.0")) {
        LogMessage("Not Windows 10 or later")
        return $False
    }
    $hasUpdated = $False
    #Windows 10, version 1507 10240.19567
    #Windows 10, version 1607 14393.5499
    #Windows 10, version 1809 17763.3646
    #Windows 10, version 2004 1904X.2247
    #Windows 11, version 21H2 22000.1215
    #Windows 11, version 22H2 22621.815
    switch ($fileVersion) {
        "10240" {
            LogMessage("Windows 10, version 1507")
            if ($fileRevision -ge 19567) {
                LogMessage("Windows 10, version 1507 with revision " + $fileRevision + " >= 19567, updates have been applied")
                $hasUpdated = $True
            }
            break
        }
        "14393" {
            LogMessage("Windows 10, version 1607")
            if ($fileRevision -ge 5499) {
                LogMessage("Windows 10, version 1607 with revision " + $fileRevision + " >= 5499, updates have been applied")
                $hasUpdated = $True
            }
            break
        }
        "17763" {
            LogMessage("Windows 10, version 1809")
            if ($fileRevision -ge 3646) {
                LogMessage("Windows 10, version 1809 with revision " + $fileRevision + " >= 3646, updates have been applied")
                $hasUpdated = $True
            }
            break
        }
        "19041" {
            LogMessage("Windows 10, version 2004")
            if ($fileRevision -ge 2247) {
                LogMessage("Windows 10, version 2004 with revision " + $fileRevision + " >= 2247, updates have been applied")
                $hasUpdated = $True
            }
            break
        }
        "22000" {
            LogMessage("Windows 11, version 21H2")
            if ($fileRevision -ge 1215) {
                LogMessage("Windows 11, version 21H2 with revision " + $fileRevision + " >= 1215, updates have been applied")
                $hasUpdated = $True
            }
            break
        }
        "22621" {
            LogMessage("Windows 11, version 22H2")
            if ($fileRevision -ge 815) {
                LogMessage("Windows 11, version 22H2 with revision " + $fileRevision + " >= 815, updates have been applied")
                $hasUpdated = $True
            }
            break
        }
        default {
            LogMessage("Warning: unsupported OS version")
        }
    }
    return $hasUpdated
}
function DownloadPatch([string]$packagePath) {
    $CurrentWindows = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion") | Select-Object -Property ProductName,DisplayVersion)
    LogMessage("Windows Product Name: `t" + $CurrentWindows.ProductName)
    LogMessage("Windows Product Version: `t" + $CurrentWindows.DisplayVersion)
    LogMessage("packagePath: `t`t" + $packagePath)
    if([string]::IsNullOrEmpty($packagePath) -and $CurrentWindows.ProductName -like "*10*" -and $CurrentWindows.DisplayVersion -eq "22H2") {
        LogMessage("packagePath not specified but this is Windows 10 22H2, trying to download patch.")
        
        if([Environment]::Is64BitOperatingSystem) {
            LogMessage("64-bit OS detected, trying to download 64-bit patch")
            $packageUrl = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/crup/2024/01/windows10.0-kb5034232-x64_ff4651e9e031bad04f7fa645dc3dee1fe1435f38.cab"
        } else {
            LogMessage("32-bit OS detected, trying to download 32-bit patch")
            $packageUrl = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/crup/2024/01/windows10.0-kb5034232-x86_3f9ddcafa903e4dd499193a851ecacbe79d842b3.cab"
        }
        
        $packagePath = "$env:temp\windows10.0-kb5034232-x64ff4651e9e031bad04f7fa645dc3dee1fe1435f38.cab"
        write-host "Start Safe OS Dynamic Update download ...."
            try {
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile($packageUrl, $packagePath)
                LogMessage("Safe OS Dynamic Update download complete, saved to $packagePath")
            }
            catch {
                LogMessage("Failed to download patch from $($URL)")
                exit 1
            } finally 
            {
                $wc.Dispose();
            }
    } else {
        LogMessage("Either packagePath not specified or this is not Windows 10 22H2 and automatic download is not supported. Quitting.")
        exit 1
    }
}
function PatchPackage([string]$mountDir, [string]$packagePath) {
    # Exam target binary
    $hasUpdated = TargetfileVersionExam($mountDir)
    if ($hasUpdated) {
        LogMessage("The update has already been added to WinRE")
        SetRegistrykeyForSuccess
        return $False
    }
    # Add package
    DownloadPatch $packagePath
    LogMessage("Apply package:" + $packagePath)
    Dism /Add-Package /Image:$mountDir /PackagePath:$packagePath /LogLevel:4 >>"$DISMLog"
    if ($LASTEXITCODE -eq 0) {
        LogMessage("Successfully applied the package")
    }
    else {
        LogMessage("Applying the package failed with exit code: " + $LASTEXITCODE)
        return $False
    }
    # Cleanup recovery image
    LogMessage("Cleanup image")
    Dism /image:$mountDir /cleanup-image /StartComponentCleanup /ResetBase /LogLevel:4 >>"$DISMLog"
    if ($LASTEXITCODE -eq 0) {
        LogMessage("Cleanup image succeed")
    }
    else {
        LogMessage("Cleanup image failed: " + $LASTEXITCODE)
        return $False
    }
    return $True
}
# ------------------------------------
# Execution starts
# ------------------------------------
LogMessage("DISM Log File: $DISMLog")
LogMessage("Windows Product Name: `t`t" + $CurrentWindows.ProductName)
LogMessage("Windows Product Version: `t" + $CurrentWindows.DisplayVersion)
LogMessage("packagePath: `t`t`t`t" + $packagePath)
if($Only1022H2 -and !($CurrentWindows.ProductName -like "*10*" -and $CurrentWindows.DisplayVersion -eq "22H2")) {
    LogMessage("The 'only try to apply KB5034232 for Windows 10 22H2' flag was set, and this system DOES NOT match, quitting!")
    exit 0
} elseif($Only1022H2) {
    LogMessage("The 'only try to apply KB5034232 for Windows 10 22H2' flag was set, and this system DOES match, continuing!")
}
# Check breadcrumb
if (Test-Path HKLM:\Software\Microsoft\PushButtonReset) {
    $values = Get-ItemProperty -Path HKLM:\Software\Microsoft\PushButtonReset
    if (!(-not $values)) {
        if (Get-Member -InputObject $values -Name WinREPathScriptSucceed) {
            $value = Get-ItemProperty -Path HKLM:\Software\Microsoft\PushButtonReset -Name WinREPathScriptSucceed
            if ($value.WinREPathScriptSucceed -eq 1) {
                LogMessage("This script was previously run successfully")
                # exit 1
                exit 0
            }
        }
    }
}
if ([string]::IsNullorEmpty($workDir)) {
    LogMessage("No input for mount directory")
    LogMessage("Use default path from temporary directory")
    $workDir = [System.IO.Path]::GetTempPath()
}
LogMessage("Working Dir: " + $workDir)
$name = "CA551926-299B-27A55276EC22_Mount"
$mountDir = Join-Path $workDir $name
LogMessage("MountDir: " + $mountdir)
# Delete existing mount directory
if (Test-Path $mountDir) {
    LogMessage("Mount directory: " + $mountDir + " already exists")
    LogMessage("Try to unmount it")
    Dism /unmount-image /mountDir:$mountDir /discard /LogLevel:4 >>"$DISMLog"
    if (!($LASTEXITCODE -eq 0)) {
        LogMessage("Warning: unmount failed: " + $LASTEXITCODE)
    }
    LogMessage("Delete existing mount directory " + $mountDir)
    Remove-Item $mountDir -Recurse
}
# Create mount directory
LogMessage("Create mount directory " + $mountDir)
New-Item -Path $mountDir -ItemType Directory
# Set ACL for mount directory
LogMessage("Set ACL for mount directory")
icacls $mountDir /inheritance:r
icacls $mountDir /grant:r SYSTEM:"(OI)(CI)(F)"
icacls $mountDir /grant:r *S-1-5-32-544:"(OI)(CI)(F)"
# Mount WinRE
LogMessage("Mount WinRE:")
reagentc /mountre /path $mountdir
if ($LASTEXITCODE -eq 0) {
    # Patch WinRE
    if (PatchPackage -mountDir $mountDir -packagePath $packagePath) {
        $hasUpdated = TargetfileVersionExam($mountDir)
        if ($hasUpdated) {
            LogMessage("After patch, find expected version for target file")
        }
        else {
            LogMessage("Warning: After applying the patch, unexpected version found for the target file")
        }
        LogMessage("Patch succeed, unmount to commit change")
        Dism /unmount-image /mountDir:$mountDir /commit /LogLevel:4 >>"$DISMLog"
        if (!($LASTEXITCODE -eq 0)) {
            LogMessage("Unmount failed: " + $LASTEXITCODE)
            exit 1
        }
        else {
            if ($hasUpdated) {
                if (IsTPMBasedProtector) {
                    # Disable WinRE and re-enable it to let new WinRE be trusted by BitLocker
                    LogMessage("Disable WinRE")
                    reagentc /disable
                    LogMessage("Re-enable WinRE")
                    reagentc /enable
                    reagentc /info
                }
                # Leave a breadcrumb indicates the script has succeed
                SetRegistrykeyForSuccess
            }
        }
    }
    else {
        LogMessage("Patch failed or is not applicable, discard unmount")
        Dism /unmount-image /mountDir:$mountDir /discard /LogLevel:4 >>"$DISMLog"
        if (!($LASTEXITCODE -eq 0)) {
            LogMessage("Unmount failed: " + $LASTEXITCODE)
            exit 1
        }
    }
}
else {
    LogMessage("Mount failed: " + $LASTEXITCODE)
}
# Cleanup Mount directory in the end
LogMessage("Delete mount direcotry")
Remove-Item $mountDir -Recurse
