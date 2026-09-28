API_USER="bal"
API_PASS=""
API_IPPORT="10.0.0.15:443"
API_CRED="$API_USER:$API_PASS"

VS_IP="10.0.0.220"
VS_PORT="443"
VS_PROTO="tcp"
VS_NAME="test1234"
VS_TYPE="http"
SSL_A=0
SSL_R=0
SSL_CERT=""


############################################################
# PROMPT for missing credentials
############################################################
# Check and prompt for API_USER if empty
if [ -z "$API_USER" ]; then
    read -p "API_USER is not set. Enter value: " API_USER
else
    API_USER="bal"
fi
# Check and prompt for API_PASS if empty
if [ -z "$API_PASS" ]; then
    read -s -p "API_PASS is not set. Enter value: " API_PASS
    echo "" # Add newline after hidden input
else
    API_PASS="$API_PASS"
fi

############################################################
# Helper: POST to /accessv2
############################################################
api_post() {
  local json="$1"
  curl -sk -X POST \
    "https://${API_IPPORT}/accessv2" \
    -H "Content-Type: application/json" \
    -d "$json"
}

############################################################
# Enable API interface (safe to call repeatedly)
############################################################
enable_api() {
local r
url="https://${API_IPPORT}/accessv2"
body=$(cat <<EOF
{
  "apiuser": "$API_USER",
  "apipass": "$API_PASS",
  "cmd": "set",
  "param": "enableapi",
  "value": "yes"
}
EOF
)
r=$(curl -s -X POST "$url" -d "$body" -k | jq -r ".code")
if [ "$r" = 200 ] ; then echo "Enabled API interface." ; else echo "Could not enable API interface. Please do this manually"; fi
}

############################################################
# Get API key 
############################################################ 
get_apikey() {
  local r 
  r=$(curl -sk -u "$API_CRED" "https://${API_IPPORT}/access/listapikeys" | grep -oP '(?<=<key>).*?(?=</key>)')
  if [ -z "$r" ] ; then 
  r=$(curl -sk -u "$API_CRED" "https://${API_IPPORT}/access/addapikey" | grep -oP '(?<=<key>).*?(?=</key>)' | head -n 1) ; echo $r
  else 
  r=$(curl -sk -u "$API_CRED" "https://${API_IPPORT}/access/listapikeys" | grep -oP '(?<=<key>).*?(?=</key>)' | head -n 1) ; echo $r
  fi 
}

############################################################
# Create Virtual Service
############################################################
create_vs_decrypt() {
  api_post "{
    \"apikey\":\"$APIKEY\",
    \"cmd\":\"addvs\",
    \"vs\":\"$VS_IP\",
    \"port\":\"$VS_PORT\",
    \"prot\":\"$VS_PROTO\",
    \"nickname\":\"$VS_NAME\",
    \"VStype\":\"$VS_TYPE\",
    \"SSLAcceleration\":\"$SSL_A\",
    \"SSLReencrypt\":\"$SSL_R\",
    \"CertFile\":\"$VS_CERT\"
  }"
}

############################################################
# Create Virtual Service
############################################################
create_vs_reecrypt() {
  api_post "{
    \"apikey\":\"$APIKEY\",
    \"cmd\":\"addvs\",
    \"vs\":\"$VS_IP\",
    \"port\":\"$VS_PORT\",
    \"prot\":\"$VS_PROTO\",
    \"nickname\":\"$VS_NAME\",
    \"VStype\":\"$VS_TYPE\",
    \"SSLAcceleration\":\"$SSL_A\",
    \"SSLReencrypt\":\"$SSL_R\",
    \"CertFile\":\"$VS_CERT\"
  }"
}

############################################################
# Create Virtual Service
############################################################
create_vs_passthru() {
  api_post "{
    \"apikey\":\"$APIKEY\",
    \"cmd\":\"addvs\",
    \"vs\":\"$VS_IP\",
    \"port\":\"$VS_PORT\",
    \"prot\":\"$VS_PROTO\",
    \"nickname\":\"$VS_NAME\",
    \"VStype\":\"$VS_TYPE\"
  }"
}

############################################################
# List Virtual Service
############################################################
show_vs() {
  api_post "{
    \"apikey\":\"$APIKEY\",
    \"cmd\":\"showvs\",
    \"vs\":\"$VS_IP\",
    \"port\":\"$VS_PORT\",
    \"prot\":\"$VS_PROTO\"
  }" | jq -r ".code"
}
echo ""
enable_api
echo ""
echo "Obtained API Key" ; APIKEY=$(get_apikey)
echo ""
CODE=$(show_vs)
if [[ "$CODE" = 200 ]]; 
then echo "Virtual Service already exists"; echo ""
else echo "Created Virtual Service"; echo ""
create_vs_passthru
fi

