#!/bin/bash
#
# DEPRECATED: use loadmaster-sample-scripts/run_license.sh instead.
#
echo ""
echo "Reading parameters file .params if it exists"
echo ""
. ./license.params
# Default for a new (unlicensed) applaince is bal
if [[ -z "$Api_User" ]]; then
 read -p "Enter admin account for api access: " Api_User
fi
# Prompt for the initial appliance password when it is not configured locally.
if [[ -z "$Api_Pass" ]]; then
 read -s -p "Enter password for $Api_User for api access: " Api_Pass
 echo
fi
# For security reasons, we will not echo the password input. If the parameter is not set, prompt for it.
if [[ -z "$New_Api_Pass" ]]; then
 read -s -p "Enter NEW password for $Api_User for api access: " New_Api_Pass
 echo
fi
# This is the IP address for the management interface on the appliance 
if [[ -z "$Api_Ip" ]]; then
 read -p "Enter IP address for api access: " Api_Ip
fi
# This is the TCP port for the management interface on the appliance, default is 443
if [[ -z "$Api_Port" ]]; then
 read -p "Enter TCP Port for $Api_Ip for api access (i.e. 443): " Api_Port
fi
# 
if [[ -z "$Progress_User" ]]; then
 read -p "Enter Progress User ID for licensing: " Progress_User
fi
# 
if [[ -z "$Progress_Pass" ]]; then
 read -s -p "Enter PASSWORD for $Progress_User for licensing: " Progress_Pass
 echo
fi
# This is the order ID for the license to be installed. If left blank, a trial license will be applied.
if [[ -z "$Order_Id" ]]; then
 read -p "Enter Progress Order ID or leave blank for trial license: " Order_Id
fi
# Combine IP and Port for API access
ipport="${Api_Ip}:${Api_Port}"
encoded_Pass=$(printf '%s' "$Progress_Pass" | jq -sRr @uri)

# Check to see if appliance is already licensed 
uri="https://${ipport}/access/listapi"
res=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri")
if echo "$res" | grep -q "<cmd>get</cmd>"; then
   do_eula="no"
else
   do_eula="yes"
fi

# Check to see if EULA has been acepted
uri="https://${ipport}/access/readeula"
out=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri" )
magic=$(xmllint --xpath 'string(//Magic)' - 2>/dev/null <<<"$out")
code=$(xmllint --xpath 'string(/Response/@code)' - <<<"$out")
if [[ -n "$magic" ]]; then
   do_eula="yes"
else
   do_eula="no"
fi

# Display the parameters that will be used in the script. For security reasons, we will not display the actual password values.
echo ""
echo "Parameters to be used in this script"
echo ""
echo "Api_User = $Api_User"
echo "Api_Pass = $Api_Pass"
echo "Api_Ip = $Api_Ip"
echo "Api_Port = $Api_Port"
echo "Progress_User = $Progress_User"
echo "Progress_Pass = XXXXXXXXXXXXXX"
echo "Order_Id = $Order_Id"
echo ""

# PROCESS EULA (Based on successful retrieval of FIRST MAGIC TOKEN)
if [[ "$do_eula" = "yes" ]]; then
    echo "MAGIC # 1 = $magic "
#   We retrieved the first MAGIC token earlier  
#   RETRIEVE SECOND MAGIC TOKEN
    uri="https://${ipport}/access/accepteula?magic=${magic}&type=${License_Type}"
    out=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri" )
    magic2=$(xmllint --xpath 'string(//Magic)' - 2>/dev/null <<<"$out")
    code=$(xmllint --xpath 'string(/Response/@code)' - <<<"$out")
    if [[ -z "$magic2" ]]; then
      echo "ERROR: Failed to extract second Magic value"
      exit 1
    else
      echo "Processing EULA Step 2 - Results = $code"
    fi
#   ACCEPT EULA
    uri="https://${ipport}/access/accepteula2?magic=${magic2}&accept=yes"
    out=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri" )
    code=$(xmllint --xpath 'string(/Response/@code)' - <<<"$out")
    echo "Processing EULA Step 3 - Results = $code" 
fi

# DETERMINE LICENSE TYPES AVAILABLE AND SELECT LICENSE
echo ""
echo "Determining available license types"
uri="https://${ipport}/access/alsilicensetypes?kempid=${Progress_User}&password=${encoded_Pass}"
if [[ -n "$Order_Id" ]]; then
  uri="${uri}&orderid=${Order_Id}"
fi
out=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri" )
json=$(xmllint --xpath 'string(//Success)' - 2>/dev/null <<<"$out")
mapfile -t choices < <(echo "$json" | jq -r '.categories[].licenseTypes[] | "\(.id)|\(.description)"')
PS3="Select license type: "
select item in "${choices[@]}"; do
  [[ -n "$item" ]] || { echo "Invalid selection"; continue; }
  lic_id=${item%%|*}
  lic_desc=${item#*|}
  echo "Selected ID:   $lic_id"
  echo "Description:  $lic_desc"
  break
done
echo ""
uri="https://${ipport}/access/alsilicense?kempid=${Progress_User}&password=${encoded_Pass}&lic_type_id=${lic_id}"
out=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri")
code=$(xmllint --xpath 'string(/Response/@code)' - <<<"$out")
echo "Installing License - Results = $code"

# RESET BAL PASSWORD
uri="https://${ipport}/access/set_initial_passwd?passwd=${New_Api_Pass}"
out=$(curl -s -k -u "${Api_User}:${Api_Pass}" "$uri")
code=$(xmllint --xpath 'string(/Response/@code)' - <<<"$out")
echo "Resetting bal password - Results = $code"
