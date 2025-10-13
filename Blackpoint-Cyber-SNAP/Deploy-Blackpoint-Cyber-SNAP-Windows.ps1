#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
#.______    __          ___       ______  __  ___ .______     ______    __  .__   __. .___________.##  
#|   _  \  |  |        /   \     /      ||  |/  / |   _  \   /  __  \  |  | |  \ |  | |           |## 
#|  |_)  | |  |       /  ^  \   |  ,----'|  '  /  |  |_)  | |  |  |  | |  | |   \|  | `---|  |----`##  
#|   _  <  |  |      /  /_\  \  |  |     |    <   |   ___/  |  |  |  | |  | |  . `  |     |  |####### 
#|  |_)  | |  `----./  _____  \ |  `----.|  .  \  |  |      |  `--'  | |  | |  |\   |     |  |#######         
#|______/  |_______/__/     \__\ \______||__|\__\ | _|       \______/  |__| |__| \__|     |__|#######         
#####################################################################################################                                                                                                
####################################╔═╗╔╗╔╔═╗╔═╗///╔╦╗╔═╗╔═╗╔═╗╔╗╔╔═╗╔═╗#############################
####################################╚═╗║║║╠═╣╠═╝/// ║║║╣ ╠╣ ║╣ ║║║╚═╗║╣ ###### Ver 2.2 04/09/2021 ###
####################################╚═╝╝╚╝╩ ╩╩/////═╩╝╚═╝╚  ╚═╝╝╚╝╚═╝╚═╝#############################

<#
Version 1.2.2 - 2023-11-10 - Add -Force switch parameter/Script Variable to reinstall even if service already exists
Version 1.2.1 - 2023-08-24 - Fixes custom field input validation routines to use -Match rather than -NotMatch
Version 1.2.0 - 2023-08-09 - Modified by David Szpunar separate documentation template/instance and custom field names into separate variables
Version 1.1.0 - Modified by David Szpunar to add NinjaRMM code to pull from custom documentation field and validate the UID and EXE name
Version 1.0.0 - Original script form Blackpoint Cyber docs at https://support.blackpointcyber.com/article/89-ninjaone-snap-installation
   (note 2023-08-09: directions no longer include script and recommend creating a new deployment for each client, but they still publish 
   a PowerShell version at https://support.blackpointcyber.com/article/41-configuring-the-powershell-script that this adds custom fields 
   integration to)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][switch] $Force
)
if($env:force -eq 'true') {
    $Force = $true
}

###########
# EDIT ME
###########
# The name of your NinjaRMM Documentation document that contains the custom fields below, assumes that there is both a template 
# and a single instance of the document with the same name (otherwise change to Ninja-Property-Docs-Get calls below with separate 
# template and instance names):
$CustomNinjaDocumentation = 'Deployments'

# The UID of the customer from the download URL to the .exe file, from Blackpoint Cyber Portal, without slashes:
$CustomerUIDCustomField = 'blackpointCyberSnapCustomerUid'

# The name of the Custom NinjaRMM Documentation Field .exe file (without path, with extension) from the Blackpoint Cyber portal:
$CustomerEXECustomField = 'blackpointCyberSnapExecutableName'

# Create a Documentation template with the above two field names, and for each Organization, add values to the two fields from the 
# Blackpoint Cyber portal before running this script.
###########
# EDIT EDIT
###########

###########
# CUSTOM FIELD CHECKS
###########

#Customer UID found in URL From Blackpoint Portal
#Example CustomerUID format: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
$CustomerUID = Ninja-Property-Docs-Get-Single $CustomNinjaDocumentation $CustomerUIDCustomField
write-host "CustomerUID from $CustomNinjaDocumentation Documentation Field: $CustomerUID"
if ($CustomerUID -Match "^[a-zA-Z00-9]{8}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{4}-[a-zA-Z00-9]{12}$") {
    write-host "Customer UID passed basic format validation, continuing to install using this value."
} else {
    write-host "No CustomerUID field defined or invalid format, set valid blackpointCyberSnapCustomerUid in documentation"
    write-host "Format should be: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX (36 characters long)"
    exit 1  
}

#Snap Installer name
#Example CompanyEXE format: "COMPANYNAME_installer.exe"
$CompanyEXE = Ninja-Property-Docs-Get-Single $CustomNinjaDocumentation $CustomerEXECustomField
write-host "CompanyEXE from $CustomNinjaDocumentation Documentation field: $CompanyEXE"
if ($CompanyEXE -Like '*_installer.exe') {
    write-host "Filename passed basic format validation, continuing to install using this value."
} else {
    write-host "No CompanyEXE field defined ending in _installer.exe, set valid blackpointCyberSnapExecutableName in documentation"
    exit 2
}

##############################
# DO NOT EDIT PAST THIS POINT
##############################

#Installer Name
$InstallerName = "snap_installer.exe"

#InstallsLocation
$InstallerPath =  Join-Path $env:TEMP $InstallerName

#Snap URL
$DownloadURL = "https://portal.blackpointcyber.com/installer/$CustomerUID/$CompanyEXE"

#Service Name
$SnapServiceName = "Snap"

#Enable Debug with 1
$DebugMode = 1 

#Failure message
$Failure = "Snap was not installed Successfully. Contact support@blackpointcyber.com if you need more help."

function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}


#Checking if the Service is Running
function Snap-Check($service)
{
    if (Get-Service $service -ErrorAction SilentlyContinue)
    {
        return $true
    }
    return $false
}

#Debug 
function Debug-Print ($message)
{
    if ($DebugMode -eq 1)
    {
        Write-Host "$(Get-TimeStamp) [DEBUG] $message"
    }
}

#Checking .NET Ver 4.6.1
function Net-Check {
    #Left in to help with troubleshooting
    #$$cimreturn = (Get-CimInstance Win32_Operatingsystem | Select-Object -expand Caption -ErrorAction SilentlyContinue) 
    #$windowsfull =  $cimreturn
    #$WindowsSmall = $windowsfull.Split(" ")
    #[string]$WindowsSmall[0..($WindowsSmall.Count-2)]
    #If ($WindowsSmall -eq $Windows10) {  
    
    Debug-Print("Checking for .NET 4.6.1+...") 
    #Calls Net Ver 
        If (! (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -gt 394254){
                   

        $NetError = "SNAP needs 4.6.1+ of .NET...EXITING" 
        Write-Host "$(Get-TimeStamp) $NetError"
        exit 0
        }
        
        {
        Debug-Print ("4.6.1+ Installed...")
        }
           
}

      

#Downloads file
function Download-Installer {
    Debug-Print("Downloading from provided $DownloadURL...")
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Client = New-Object System.Net.Webclient
    try
    {
        $Client.DownloadFile($DownloadURL, $InstallerPath)
    }
    catch
    {
    $ErrorMsg = $_.Exception.Message
    Write-Host "$(Get-TimeStamp) $ErrorMsg"
    }
    If ( ! (Test-Path $InstallerPath) ) {
        $DownloadError = "Failed to download the SNAP Installation file from $DownloadURL"
        Write-Host "$(Get-TimeStamp) $DownloadError" 
        throw $Failure
    }
    Debug-Print ("Installer Downloaded to $InstallerPath...")


}

#Installation 
function Install-Snap {
    Debug-Print ("Verifying AV did not steal exe...")
    If (! (Test-Path $InstallerPath)) {
    {
        $AVError = "Something, or someone, deleted the file."
        Write-Host "$(Get-TimeStamp) $AVError"
        throw $Failure
    }
    }
    Debug-Print ("Unpacking and Installing agent...")
    Start-Process -NoNewWindow -FilePath $InstallerPath -ArgumentList "-y"    
    
}


function runMe {
    Debug-Print("Starting...")
    Debug-Print("Checking if SNAP is already installed...")
    If ( !$Force -and (Snap-Check($SnapServiceName)) )
    {
        $ServiceError = "SNAP is Already Installed...Bye." 
        Write-Host "$(Get-TimeStamp) $ServiceError"
        exit 0
    }
    Net-Check
    Download-Installer
    Install-Snap
  # Error-Test
    Write-Host "$(Get-TimeStamp) Snap Installed..."
}

try
{
    runMe
}
catch
{
    $ErrorMsg = $_.Exception.Message
    Write-Host "$(Get-TimeStamp) $ErrorMsg"
    exit 1
}
