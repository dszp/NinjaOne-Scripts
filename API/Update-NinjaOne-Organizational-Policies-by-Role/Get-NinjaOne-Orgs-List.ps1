<# Get-NinjaOne-Orgs-List.ps1

Created by David Szpunar of Servant 42.
No warranties expressed or implied. MIT license, free to use or modify.

REQUIRES: Config module for secrets from https://discord.com/channels/676451788395642880/1126703581609865296
config.ps1 file in same folder (see comments below) with the following three variables defined:
  $ClientID = 'op://vault/item/clientid'
  $ClientSecret = 'op://vault/item/credential'
  $RefreshToken = 'op://vault/item/refreshtoken'
Alternately, define those variables directly in this script in lieu of loading from secrets manager, but 
keep in mind that lowers the security and this script becomes very poweful on its own.

HOW TO USE: Get a refresh token, put in your secrets vault referenced from config, run script from a folder 
where you want to end up with the three files defined in the CONFIG section for review. To update policies 
with accompanying script, edit the fileOrgsAndPolicies file and set new policy numbers in the NEW_policy_id 
column for only those organizations you want to update and use the update script against that file.

Version 0.1.0 - Released 2023-10-07 - initial release
#>

# Docs for NinjaOne API: https://app.ninjarmm.com/apidocs/
# Docs for NinjaOne PowerShell module: https://github.com/homotechsual/NinjaOne

##### CONFIG
$fileOrgsAndPolicies = './OrgsAndPolicies.csv'
$fileOrgs = './Orgs.csv'
$filePolicies = './Policies.csv'

######################### DEFS
# $POLICY_TYPES = @('1','201','202','22','205','206','11','12','31')
$POLICY_TYPES = @('1','201','202')
# $POLICY_NODES = @('MAC','CLOUD_MONITOR_TARGET','HYPERV_VMM_HOST','HYPERV_VMM_GUEST','WINDOWS_WORKSTATION','WINDOWS_SERVER')
$POLICY_NODES = @('WINDOWS_WORKSTATION','WINDOWS_SERVER')
######################### END DEFS

# Require the load-config file from https://discord.com/channels/676451788395642880/1126703581609865296 and load config.ps1
. "./load-config.ps1" 'config.ps1'

##### END CONFIG

# Splat the parameters - easier to read!
$ReconnectionParameters = @{
  Instance = 'us'
  ClientID = $ClientID
  ClientSecret = $ClientSecret
  RefreshToken = $RefreshToken
  UseTokenAuth = $True
}

Import-Module NinjaOne
Connect-NinjaOne @ReconnectionParameters

# To test with a single item, uncomment the rest of the lines temporarily.
$Organisations = Get-NinjaOneOrganisations -detailed #| select-object -First 1
$Roles = Get-NinjaOneRoles # | select-object -First 1
$Policies = Get-NinjaOnePolicies # | select-object -First 1

if (($Organisations | Measure-Object).Count -lt 1) {
    Write-Host "No items found in Organizations, something went wrong. Quitting."
    exit 1
}


$Organisations | select-object -Property id,name,description,nodeApprovalMode | Export-Csv -Path "$fileOrgs" -NoTypeInformation


$output = @()
ForEach ($org in $Organisations) {
    $org_entry = @{
        'org_id' = $org.id
        'org_name' = $org.name
        'org_description' = $org.description
        'org_nodeApprovalMode' = $org.nodeapprovalmode
    }
    Write-Host "$($org.id),$($org.name)"

foreach ($orgpolicy in ($org.policies | Where-Object -Property 'noderoleid' -In $POLICY_TYPES)) {
    $policy = $Policies | Where-Object -Property 'id' -eq $orgpolicy.policyid
    $role = $Roles | Where-Object -Property 'id' -eq $orgpolicy.noderoleid

    if ($role.chassisType -eq 'UNKNOWN') { 
        $role_type = $role.nodeClass
    } else {
        $role_type = $role.nodeClass + ' ' + $role.chassisType
    }

    #  Write-Host "Policy: " $policy.name " Node Role and Type: " $role.nodeClass " " $role.chassisType " (" $role.id ")"
     $lineitem = $org_entry
     $lineitem += @{
        'role_id' = $role.id
        'role_type' = $role_type
        'role_nodeClass' = $role.nodeClass
        'policy_id' = $policy.id
        'NEW_policy_id' = ''
        'policy_name' = $policy.name
        'policy_description' = $policy.description
     }
     $output += $lineitem
}
# Write-Host "Entry: " $lineitem
}

$Organisations
    | select-object -Property id,name,description,nodeApprovalMode 
    | Export-Csv -Path "$fileOrgs" -NoTypeInformation

#Write-host $output
$output 
    # | Select-Object -Property org_id,org_name,org_nodeApprovalMode,org_description,role_id,role_type,role_nodeClass,policy_id,NEW_policy_id,policy_name,policy_description 
    | Select-Object -Property role_type,role_nodeClass,org_name,policy_id,NEW_policy_id,policy_name,org_id,role_id,policy_description 
    | Sort-Object -Property role_nodeClass,org_id,role_type
    | Export-Csv -Path "$fileOrgsAndPolicies" -NoTypeInformation

$Policies
    | select-object -Property id,nodeClass,name,description 
    | Where-Object -Property 'nodeClass' -In $POLICY_NODES
    | Sort-Object -Property nodeClass,name
    | Export-Csv -Path "$filePolicies" -NoTypeInformation


