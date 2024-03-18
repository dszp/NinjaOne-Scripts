<# Update-NinjaOne-Org-Policies.ps1

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
where the fileOrgsAndPolicies CSV file exists with at least the columns from the $required_headers array exist 
and set new policy numbers in the NEW_policy_id column for only those organizations you want to update and 
run this script either the predefined default file name or pass the file name you're using as the 
only (-fileOrgsAndPolicies) parameter.

You can use the accompanying Get-NinjaOne-Orgs-List.ps1 script to 
obtain a list of policies, orgs, and combined orgs and policies mapping with an empty NEW_policy_id column 
you can use to define your updates for use here.

NOTE: You MUST pass the -ReallyChange flag to update the policy mappings! You'll get only a display of potential 
actions without it, for safety to ensure you intend the changes.

Version 0.1.0 - Released 2023-10-07 - initial release
#>
param (
  [string]$fileOrgsAndPolicies = './OrgsAndPolicies.csv',
  [switch]$ReallyChange
)

# Define the CSV headers required at a minimum to make this work; the rest are optional for display/human sorting.
$required_headers = @('org_id', 'NEW_policy_id', 'role_id');

##### CONFIG
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

# Import the CSV file with changes and verify required column names all exist.
if(Test-Path -Path $fileOrgsAndPolicies -PathType leaf) {
  $Updates = Import-Csv -Path $fileOrgsAndPolicies
} else {
  Write-Host "File '$fileOrgsAndPolicies' does not exist, quitting."
  exit
}

$headers = ($Updates | Get-Member -MemberType NoteProperty).Name
Write-Host $headers
foreach ($header in $required_headers) {
  if($header -notin $headers) {
    write-Host "Required column '$header' not found, quitting. Required columns:"
    write-host $required_headers
    exit
  }
}

# Read in organizations so we can pull name or other information as needed for display.
$Organisations = Get-NinjaOneOrganisations
if (($Organisations | Measure-Object).Count -lt 1) {
  Write-Host "No items found in Organizations, something went wrong. Quitting."
  exit 1
}

$countChanged = 0
$countTotal = 0
foreach ($update in $Updates) {
    $countTotal++
    $org = $Organisations | Where-Object -Property 'id' -Like $update.org_id
    if(!$org) {
      Write-Host "No organization found with ID $($update.org_id), skipping line $countTotal."
      continue
    }
    if($update.NEW_policy_id -gt 0 -and $update.NEW_policy_id -ne $update.policy_id) {  # Only update if new is non-blank and different from existing policy.
        Write-Host "For org '$($org.name)' (ID $($update.org_id)) change policy $($update.policy_id) to $($update.NEW_policy_id) for Role ID $($update.role_id)."
        if($ReallyChange) {
          Update-NinjaOneNodeRolePolicyAssignment -organisationId $update.org_id -nodeRoleId $update.role_id -policyId $update.NEW_policy_id
        }
        $countChanged++
    }
}

if($ReallyChange) {
  Write-Host "`nUpdated $countChanged record(s) of $countTotal."
} else {
  Write-Host "`nAdd parameter `$ReallyChange to actually make changes, just testing. NO change(s) made."
  Write-Host "Would have updated $countChanged record(s) of $countTotal."
}
