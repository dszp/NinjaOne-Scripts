#!bin/sh
# Deployment script for Blackpoint Cyber SNAP agent for macOS for NinjaRMM

# v0.1 - 2023-09-05 - Logic by David Szpunar, based on and calls Blackpoint Cyber-provided script for installation.

#SOURCE instructions: https://support.blackpointcyber.com/article/107-mac-agent-ninjaone-installation

# Locate the Auth Token from the Blackpoint Cyber Portal->Customer->Install & Deploy with the Download macOS Setup Script button.
# Save the .sh file, open it, and find the line starting with "export AUTH_TOKEN=" and copy the auth token from inside the quotes 
# and place it below as the value for AUTH_TOKEN. The blackpointCyberSnapCustomerUid Custom Documentation field under the 
# Deployments template Deployments instance should be script-readable and set to the CUSTOMER_ID value from the same script, 
# which is the same one required for Windows deployment. Otherwise this script just verifies those values are long enough 
# and then downloads and runs the deployment script provided by Blackpoint Cyber on the final line of the script you 
# downloaded in the above instructions. If snap-agent executable is located on system, script quits without installing.

# Make sure Custom Documentation Field blackpointCyberSnapCustomerUid exists, or make your own and change it, or switch 
# to using Global or Role Custom fields with slight change to ninjarmm-cli call, left as an exercise for the reader.

#########################
# EDIT AUTH_TOKEN BELOW #
#########################

# Hardcode Auth Token as it's global for all tenants under a single MSP, but optionally pull from Documentation Custom Field if desired:
export AUTH_TOKEN="PLACE_AUTH_TOKEN_HERE"
#export AUTH_TOKEN=$(/Applications/NinjaRMMAgent/programdata/ninjarmm-cli get 'Deployments' 'Deployments' blackpointCyberSnapAuthToken)

# Uncomment for debug output:
#echo "Blackpoint Cyber AUTH_TOKEN: $AUTH_TOKEN"

export CUSTOMER_ID=$(/Applications/NinjaRMMAgent/programdata/ninjarmm-cli get 'Deployments' 'Deployments' blackpointCyberSnapCustomerUid)
# Uncomment for debug output:
#echo "Blackpoint Cyber CUSTOMER_ID: $CUSTOMER_ID"

export DOWNLOAD_BASE_URL="https://agent-sega-production-snap.bpcyber.net"

if [ ${#AUTH_TOKEN} != 281 ]
then
    echo "Blackpoint Cyber Auth Token value not found or not the right length, quitting."
    exit
else
    echo "Auth Token located, continuing."
fi

if [ ${#CUSTOMER_ID} != 36 ]
then
    echo "Blackpoint Cyber Customer ID value not found or too short, quitting."
    exit
else
    echo "Customer ID located, continuing."
fi

if [ -f /usr/local/bin/snap-agent ]
then
    echo "snap-agent is already installed, quitting."
    exit
else
    echo "snap-agent NOT found, continuing to install."
fi

echo ""
echo "Running installation script..."
curl -s https://bpc-deploy-scripts.s3.amazonaws.com/macos/download-install.sh | sh
echo "Installation script run complete."
