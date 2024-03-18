<# A SNIPPET to Convert Script Variables To Parameters

NOTE: This script is a snippet designed to be inserted into your own projects, and is NOT designed to be run on its own! See directions below.

I prefer to write scripts that are usable from the command line and from NinjaRMM Automations, but support both parameters as well as Script Variables. The [switch] parameter type allows for a checkbox-like "true if exists" function when used with manually-entered parameters (via NinjaRMM or CLI), but Ninja's new Script Variables feature instead turns checkboxes into environment variables where the string value "true" is set if the checkbox is checked at runtime.

While a simple if statement takes these into account, it requires a second definition of each switch parameter, adding room for typos and extra manual effort. This snippet (after the example parameter binding; use your own) automatically overwrites any named parameters to $true if there's a correspondingly-named lowercase (NinjaRMM converts all Script Variables to lowercase environment variables) environment variable with a string value of true, for easy re-use

After the snippet runs, access the contents of your paramters as usual via variable name; if Script Variables with the same name were set, they will have overwritten the parameter variables with the Script Variable values from NinjaRMM.

If a Script Variable is set to the strings 'true' or 'false', the corresponding parameter will be a boolean $true or $false value.

If you do not define a parameter in the param() block with the same name as a Script Variable, it will be ignored by this snippet (you can still access it via the usual $env: method).

It also resolves these issues from the original version I wrote:
 - The oddities of environment variable names and cases (being case-sensitive unlike most variables)
 - Ninja lower-casing all Script Variables names (good but need to know)
 - Needing to loop through the list of all possible arguments defined by the param group and (especially!) not just the ones passed in
 - Knowing that Script Variables use a lowercase string "true" for checkboxes rather than a $true value, to convert the value to boolean correctly
 - The fact that updating the parameter list value does NOT change the assigned variable name ($PSBoundParameters['SwitchName'] = $true does NOT also set $SwitchName to $true if it was false at script inception) which does make sense but is another bit of minutiae to consider

 This version I've used in multiple scripts since it's initial release and I haven't had to change any of it in quite some time. I haven't tested it with every type of Script Variable beyond checkboxes and text fields.

Note: Script Variables are documented by NinjaOne in the following locations (must be logged in to access Dojo articles):
https://ninjarmm.zendesk.com/hc/en-us/articles/17783013460621-Automation-Library-Using-Variables-in-Scripts
https://ninjarmm.zendesk.com/hc/en-us/articles/17765447097357-Script-Variable-Types

Version 1.0.0 - 2023-11-22 - Initially published version supporting at least Checkboxes and String/Text fields.
#>

# Example parameters; use your own:
param (
    [switch]$SwitchParam1,
    [switch]$SwitchParam2,
    [string]$NonSwitchParam
)

# TO DEPLOY, ADD THE FOLLOWING TO YOUR SCRIPT, just below your param() block and before the rest of your script:




### PROCESS NINJRAMM SCRIPT VARIABLES AND ASSIGN TO NAMED SWITCH PARAMETERS
# Get all named parameters and overwrite with any matching Script Variables with value of 'true' from environment variables
# Otherwise, if not a checkbox ('true' string), assign any other Script Variables provided to matching named parameters
$switchParameters = (Get-Command -Name $MyInvocation.InvocationName).Parameters;
foreach ($param in $switchParameters.keys) {
    $var = Get-Variable -Name $param -ErrorAction SilentlyContinue;
    if($var) {
        $envVarName = $var.Name.ToLower()
        $envVarValue = [System.Environment]::GetEnvironmentVariable("$envVarName")
        if (![string]::IsNullOrWhiteSpace($envVarValue) -and ![string]::IsNullOrEmpty($envVarValue) -and $envVarValue.ToLower() -eq 'true') {    # Checkbox variables
            $PSBoundParameters[$envVarName] = $true
            Set-Variable -Name "$envVarName" -Value $true -Scope Script
        } elseif (![string]::IsNullOrWhiteSpace($envVarValue) -and ![string]::IsNullOrEmpty($envVarValue) -and $envVarValue -ne 'false') {       # non-Checkbox string variables
            $PSBoundParameters[$envVarName] = $envVarValue
            Set-Variable -Name "$envVarName" -Value $envVarValue -Scope Script
        }
    }
}
### END PROCESS SCRIPT VARIABLES
