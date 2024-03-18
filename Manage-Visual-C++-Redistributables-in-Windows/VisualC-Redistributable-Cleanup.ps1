<# VisualC-Redistributable-Cleanup.ps1
SOURCE: https://vcredist.com/uninstall-vcredist/
SOURCE: https://www.powershellgallery.com/packages/VcRedist/

Version: 0.0.1 - 2023-11-30 by David Szpunar - Initial Version

DESCRIPTION: Uninstalls or installs Visual C++ Redistributables in various ways. Uses the VcRedist PowerShell module from the NuGet, and 
installs the module and an updated Package Manager (to use NuGet at all) if required first.

Call with NO arguments/parameters to output a list of the currently installed VC++ Redistributables on the system, but do nothing.
Call with -Unsupported to uninstall all unsupported versions of the Redistributable (2012 and older).
Call with -ToUninstall and one or more years, separated by comma (no spaces), to uninstall specific versions of the Redistributable.
Call with -UninstallAll to uninstall all versions of the Redistributable (all versions installed on the whole system, of any type!).
Call with -Install to install all SUPPORTED versions of the Redistributable (2013 and newer).

Can mix and match -Install and the other options together; supported versions will be installed after the uninstallations are completed.

EXAMPLES:
script.ps1 -ToUninstall "2005,2010"
    Remove all versions of Visual C++ Redistributable 2005 and 2010.

script.ps1 -UninstallAll -Install
    Uninstall all versions of Visual C++ Redistributable, then install all supported versions. This can be quite handy to make sure only 
    the latest patch version is installed, as the specific minor version is often outdated or multiple are installed, and this will 
    ensure only the latest version of only the supported VC++ Redistributable releases are installed.

NOTE: Some software my stop working properly if VC++ Redistributables are not installed that match their needed version! If you run into 
issues with apps after cleaning up, you may need to reinstall the app (which often reinstalls the VC++ Redistributable it came with), or 
install the VC++ Redistributable version manually if it's unsupported. This script can be modified to install other versions, either all 
versions including unsupported by changing this line: 
    $Redists = Get-VcList | Save-VcRedist -Path $Path | Install-VcRedist -Silent

to be like this with added -ExportAll parameter:
    $Redists = Get-VcList -Export All | Save-VcRedist -Path $Path | Install-VcRedist -Silent

Or, you can filter the output using Where-Object per the Examples at https://vcredist.com/get-vclist/#examples in order to 
install only specific versions or architectures. This may be added to this script in a later release, to control which versions 
to install besides none or "all supported" as it started just removing old versions and the install-supported was added after the fact.

NINJAONE: This script works with parameters, or via Script Variables with these types and names, none of which are required:
[Checkbox] Unsupported
[String/Text] ToUninstall
[Checkbox] UninstallAll
[Checkbox] Install

The script does NOT output anything to custom variables in NinjaOne, but it easily could be modified to do so.
#>
param (
    [string]$ToUninstall,
    [switch]$Install,
    [switch]$UninstallAll,
    [switch]$Unsupported
)

### PROCESS NINJRAMM SCRIPT VARIABLES AND ASSIGN TO NAMED SWITCH PARAMETERS
# Get all named parameters and overwrite with any matching Script Variables with value of 'true' from environment variables
# Otherwise, if not a checkbox ('true' string), assign any other Script Variables provided to matching named parameters
$switchParameters = if($MyInvocation.InvocationName) { (Get-Command -Name $MyInvocation.InvocationName).Parameters } else { $null }
foreach ($param in $switchParameters.keys) {
    $var = Get-Variable -Name $param -ErrorAction SilentlyContinue;
    if($var) {
        $envVarName = $var.Name.ToLower()
        $envVarValue = [System.Environment]::GetEnvironmentVariable("$envVarName")
        if (![string]::IsNullOrWhiteSpace($envVarValue) -and $envVarValue.ToLower() -eq 'true') {    # Checkbox variables
            $PSBoundParameters[$envVarName] = $true
            Set-Variable -Name "$envVarName" -Value $true -Scope Script
        } elseif (![string]::IsNullOrWhiteSpace($envVarValue) -and $envVarValue -ne 'false') {       # non-Checkbox string variables
            $PSBoundParameters[$envVarName] = $envVarValue
            Set-Variable -Name "$envVarName" -Value $envVarValue -Scope Script
        }
    }
}
### END PROCESS SCRIPT VARIABLES

# Path to store installation files if installing:
$Path = "$env:Temp\VcRedist"

function Load-Module ($m) {

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        write-host "Module $m is already imported."
        return $true
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            Import-Module $m
            return $true
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            # if (Find-Module -Name $m | Where-Object {$_.Name -eq $m}) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Get-PackageProvider -Name "NuGet" -Force | Out-Null
                Install-Module -Name $m -Force
                Import-Module $m
                return $true
            # }
            else {

                # If the module is not imported, not available and not in the online gallery then abort
                write-host "Module $m not imported, not available and not in an online gallery, exiting."
                return $false
            }
        }
    }
}

if (Load-Module "VcRedist") {
    # Write-Host "VCRedist module is already installed, continuing."
} 
else {
    Write-Host "Can't find or install VcRedist module, quititng."
    exit 1
    # Install-Module -Name VcRedist -Force
}
Write-Host "Currently installed VC Redistributables:"
Get-InstalledVcRedist | Select Name | Format-Table

[array]$ToUninstallArray = @()

if ($Unsupported -and $false -eq $UninstallAll) {
    $ToUninstallArray = @('2005','2008', '2010', '2012')
    Write-Host "Uninstalling all unsupported Visual C+ Redistributables, meaning up through 2012."
} elseif ($ToUninstall.Length -gt 0 -and $false -eq $UninstallAll) {
    $ToUninstallArray = $ToUninstall.Trim() -split ','
    
    if ($ToUninstallArray.Count -eq 0) {
        Write-Host "No VC Redistributables provided to uninstall."
        exit 0
    } else {
        Write-Host "Uninstalling the following Visual C+ Redistributables:"
        Write-Host ""
    }
} elseif ($false -eq $UninstallAll) {
    Write-Host "No VC Redistributables provided to uninstall."
    exit 0
} 

if(!$UninstallAll) {
    Write-Host "Count of versions to try and uninstall:" $ToUninstallArray.Count "(" ($ToUninstallArray -join ", ") "):"
    Write-Host ""
    
    foreach($Version in $ToUninstallArray) {
        foreach ($foundVersion in (Get-InstalledVcRedist | where-object Name -like "*$Version*")) {
            Write-Host "Triggering uninstall of VC Redistributable $($Version):" $foundVersion.Name
            # Get-InstalledVcRedist | where-object Name -like "*$Version*" | Uninstall-VcRedist -Confirm:$false
            $foundVersion | Uninstall-VcRedist -Confirm:$false
        }
        Write-Host ""
    }
} elseif ($UninstallAll) {
    Write-Host "Uninstalling ALL VC Redistributables."
    foreach ($foundVersion in Get-InstalledVcRedist) {
        Write-Host "Triggering uninstall of VC Redistributable:" $foundVersion.Name
        # Get-InstalledVcRedist | where-object Name -like "*$Version*" | Uninstall-VcRedist -Confirm:$false
        $foundVersion | Uninstall-VcRedist -Confirm:$false
    }
    Write-Host ""
}


if($Install) {
    Write-Host "Installing VC Redistributables:"
    #region tasks/install apps
    Write-Host "Saving VcRedists to path: $Path."
    New-Item -Path $Path -ItemType "Directory" -Force -ErrorAction "SilentlyContinue" > $null

    Write-Host "Downloading and installing supported Microsoft Visual C++ Redistributables."
    $Redists = Get-VcList | Save-VcRedist -Path $Path | Install-VcRedist -Silent

    Write-Host "Installed Visual C++ Redistributables:"
    $Redists | Select-Object -Property "Name", "Release", "Architecture", "Version" -Unique
    #endregion
}

Write-Host "Installed VC Redistributables after changes:"
Get-InstalledVcRedist | Select Name | Format-Table
