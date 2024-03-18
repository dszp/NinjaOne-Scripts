#Requires -Version 5.0
<#
    .SYNOPSIS
        Set Microsoft Attack Surface Reduction (ASR) Rule to a specified mode and report on existing ASR rule settings.
    .DESCRIPTION
        Report on currently configured ASR rules in the registry using -ReportOnly; otherwise also request updating of a particular rule by GUID to an available mode.

    .PARAMETER ASRID
        The GUID of the Attack Surface Reduction (ASR) rule to be set to a specified mode.

    .PARAMETER ReportOnly
        Report on currently configured ASR rules in the registry but don't make any changes.

    .PARAMETER Mode
        The mode to set the ASR rule to. Default to 'Enable' (Block). Options are 'Enable', 'Disabled', 'AuditMode', or 'Warn'.

    .PARAMETER Verbose
        When updating the configuration, prints all currently configured ASR rule and settings to the console in addition to making the requested update, and not just the status of the rule being adjusted.

    .NOTES
        2023-11-27: Initial release

    .LINK
        Not currently linked externally.
    
    .EXAMPLE
        Set-MicrosoftASR-Rule.ps1

        This sets the default rule, which is "Block abuse of exploited vulnerable signed drivers" to "Enable" (Block) because of the script defaults.

    .EXAMPLE
        Set-MicrosoftASR-Rule.ps1 -ReportOnly

        This sets the default rule, which is "Block abuse of exploited vulnerable signed drivers" to "Enable" (Block) and reports all currently configured ASR rule and settings.

    .EXAMPLE
        Set-MicrosoftASR-Rule.ps1 -ASRID '56a863a9-875e-4185-98a7-b882c64b5ce5'

        This sets the default rule, which is "Block abuse of exploited vulnerable signed drivers" to "Enable" (Block) by passing the ASR rule GUID.
    
    .EXAMPLE
        Set-MicrosoftASR-Rule.ps1 -ASRID '56a863a9-875e-4185-98a7-b882c64b5ce5' -Verbose

        This sets the default rule with the passed GUID to "Enable" (Block) and reports all currently configured ASR rule and settings.
    
    .EXAMPLE
        Set-MicrosoftASR-Rule.ps1 -ASRID '56a863a9-875e-4185-98a7-b882c64b5ce5' -Mode 'Disabled' -Verbose

        This sets the default rule, which is "Block abuse of exploited vulnerable signed drivers" to "Disabled" (Allow) by passing the ASR rule GUID and reports all currently configured ASR rule and settings.
#>
<#
Useful links and references:
All Attack Surface Reduction rules in Defender with IDs: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide
GUID Matrix: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#asr-rule-to-guid-matrix
PowerShell reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/enable-attack-surface-reduction?view=o365-worldwide#powershell
(Get-MpPreference).AttackSurfaceReductionRules_Ids
(Get-MpPreference).AttackSurfaceReductionRules_Ids -eq "56a863a9-875e-4185-98a7-b882c64b5ce5"
(Get-MpPreference).AttackSurfaceReductionRules_Actions


GUID: 56a863a9-875e-4185-98a7-b882c64b5ce5
Name: Unsigned Drivers: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-abuse-of-exploited-vulnerable-signed-drivers
#>
param (
    [string]$ASRID = '56a863a9-875e-4185-98a7-b882c64b5ce5',
    [switch]$Verbose,
    [Switch]$ReportOnly,
    [ValidateSet('Enable','Disabled','AuditMode','Warn')]
    [string]$Mode = 'Enable'
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

$MapValueToDesc = @{
    "0" = "Disabled"
    "1" = "Block"
    "2" = "Audit"
    "6" = "Warn"
}
$MapDescToValue = @{
    "Disabled" = "0"
    "Block" = "1"
    "Audit" = "2"
    "Warn" = "6"
}

$MpStatus = Get-MpComputerStatus
Write-Host "Defender Computer ID: $($MpStatus.ComputerID)"
Write-Host "AntiMalware Service Enabled: $($MpStatus.AMServiceEnabled)"
Write-Host "Antispyware Enabled: $($MpStatus.AntispywareEnabled) (signaures updated $($MpStatus.AntispywareSignatureLastUpdated))"
Write-Host "Antivirus Enabled: $($MpStatus.AntivirusEnabled) (signatures updated $($MpStatus.AntivirusSignatureLastUpdated))"
Write-Host "NOTE: Rules that are configured to 'Enable' will be displayed as being set to 'Block'"
Write-Host ""

if($MpStatus.AMRunningMode -eq "Passive") {
    Write-Host "Defender is in Passive mode and not Normal or EDR Block Mode. Quitting."
    exit 1
}

$MpPrefs = Get-MpPreference
$ASR_Qty = ($MpPrefs.AttackSurfaceReductionRules_Ids.Length) - 1

if($ASR_Qty -ge 0) {
    Write-Host "Existing ASR Rule Value(s):"
    for ($i = 0; $i -le $ASR_Qty; $i++) {
        $myId = ($MpPrefs.AttackSurfaceReductionRules_Ids)[$i]
        $myAction = ($MpPrefs.AttackSurfaceReductionRules_Actions)[$i]
        $myActionDesc = $MapValueToDesc["$myAction"]
        if($ASRID -eq $MyID) {
            Write-Host "Rule $i GUID: $(($MpPrefs.AttackSurfaceReductionRules_Ids)[$i]) is set to value $myActionDesc (RULE IN QUESTION)"
        } elseif($Verbose -or $ReportOnly) {
            Write-Host "Rule $i GUID: $(($MpPrefs.AttackSurfaceReductionRules_Ids)[$i]) is set to value $myActionDesc"
            
        }
    }
    Write-Host ""
}

if((Get-MpPreference).AttackSurfaceReductionRules_Ids -eq "$ASRID") {
    # Write-Host "Rule $ASRID is currently in the list of configured rules on this system."
} else {
    Write-Host "Rule $ASRID is not currently in the list of configured rules on this system."
}

if($ReportOnly) {
    Write-Host "Report-only mode requested, quitting with no changes made."
    exit 0
}
# Attempt to set the rule provided to the mode specified:
Write-Host "Attempting to set rule $ASRID to $Mode"
Set-MpPreference -AttackSurfaceReductionRules_Ids $ASRID -AttackSurfaceReductionRules_Actions $Mode

# Report outcome:
if((Get-MpPreference).AttackSurfaceReductionRules_Ids -eq "$ASRID") {
    # Write-Host "Rule $ASRID IS in the list of configured rules."
} else {
    Write-Host "Rule $ASRID is NOT in the list of configured rules."
}
Write-Host ""

$MpPrefs = Get-MpPreference
$ASR_Qty = ($MpPrefs.AttackSurfaceReductionRules_Ids.Length) - 1
for ($i = 0; $i -le $ASR_Qty; $i++) {
    $myId = ($MpPrefs.AttackSurfaceReductionRules_Ids)[$i]
    $myAction = ($MpPrefs.AttackSurfaceReductionRules_Actions)[$i]
    $myActionDesc = $MapValueToDesc["$myAction"]
    if($ASRID -eq $myId) {
        Write-Host "Rule $i GUID: $(($MpPrefs.AttackSurfaceReductionRules_Ids)[$i]) is now set to value $myActionDesc"
    }
}
