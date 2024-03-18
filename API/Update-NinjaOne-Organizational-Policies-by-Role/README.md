# API: Update NinjaOne Organizational Policies by Role (& Retrieve Orgs and Policies for Edit First)
This set of scripts lets you retrieve the organizations and policies (and the mappings between them) from your NinjaOne instance via the API. Written and tested in PowerShell 7 on macOS but should work on any system and probably backwards compatible. Requires NinjaOne API creds and refresh token that's active.

Uses the secrets config loader (to be documented soon) but you can hardcode credentials yourself if you want to.

Documentation for each script is at the top, one to get and one to update after you edit the CSV with the mappings you want to change.

This is a relatively quick edit/document of older quick 'n dirty scripts I wrote a while back, so double check things yourself but it worked for my purpose when we onboarded to Ninja and needed to globally update many organizations to new policies we hadn't even created in some cases when we'd created organizations. Editing these by hand across multiple organizations in the UI is time-consuming as you can only edit one at a time, so this script speeds it up in bulk.

The config at the top of the get script limits which policy types and device node types you want to retrieve; the commented out lines are all possible values in case you want to modify them, but they default to only Windows workstations, laptops, and servers, and the policies that apply to them--changing these around is left as an exercise for you. 
