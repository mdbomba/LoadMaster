#!/usr/bin/env bash
set -euo pipefail

# Apply STIG security hardening to a LoadMaster via APIv2
# Usage: ./stig-harden.sh
#
# Configure via license.params or environment variables:
#   Api_Ip, Api_User, Api_Pass (or New_Api_Pass)
# Optional cert overrides:
#   CERTS_DIR, MGMT_CERT_PFX, MGMT_CERT_NAME, MGMT_CERT_PASSWORD,
#   ICA_CERT_FILE, RCA_CERT_FILE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../_common.sh"
ensure_tools
load_license_params

Api_Pass="${New_Api_Pass:-$Api_Pass}"
BASE="$(api_base)"

CERTS_DIR="${CERTS_DIR:-/home/chef/repos/certs}"
MGMT_CERT_PFX="${MGMT_CERT_PFX:-${CERTS_DIR}/vlm90.pfx}"
MGMT_CERT_NAME="${MGMT_CERT_NAME:-vlm90}"
MGMT_CERT_PASSWORD="${MGMT_CERT_PASSWORD:-password}"
ICA_CERT_FILE="${ICA_CERT_FILE:-${CERTS_DIR}/vlm90_ica.crt}"
RCA_CERT_FILE="${RCA_CERT_FILE:-${CERTS_DIR}/vlm90_rca.crt}"

apiv2() {
  local body="$1"
  curl -sk -X POST "${BASE}/accessv2" \
    -H "Content-Type: application/json" \
    -d "$body"
}

set_param() {
  local param="$1"
  local value="$2"
  local desc="${3:-$param}"

  begin_step "Setting ${desc}"

  # Check current value first
  local current
  current=$(apiv2 "{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"get\",\"param\":\"${param}\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('${param}',''))" 2>/dev/null || echo "")

  if [ "$current" = "$value" ] || [ "$current" = "true" -a "$value" = "yes" ] || [ "$current" = "false" -a "$value" = "0" ]; then
    end_step_ok "already set"
    return
  fi

  local resp
  resp=$(apiv2 "{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"set\",\"param\":\"${param}\",\"value\":\"${value}\"}")
  if echo "$resp" | grep -q '"status":"ok"'; then
    end_step_ok "$value"
  else
    echo ""
    echo "  WARNING: Failed to set ${param}: $(echo "$resp" | grep -o '"message":"[^"]*"')" >&2
  fi
}

apiv2_status_ok() {
  local resp="$1"
  local status
  status="$(echo "$resp" | jq -r '.status // empty' 2>/dev/null || true)"
  if [[ "$status" == "ok" ]]; then
    return 0
  fi
  local code
  code="$(echo "$resp" | jq -r '.code // empty' 2>/dev/null || true)"
  [[ "$code" == "200" ]]
}

apiv2_message() {
  local resp="$1"
  echo "$resp" | jq -r '.message // .Error // empty' 2>/dev/null || true
}

upload_cert_blob() {
  local cmd="$1"
  local cert_name="$2"
  local cert_file="$3"
  local password="${4:-}"

  if [[ ! -f "$cert_file" ]]; then
    echo ""
    echo "  WARNING: Missing certificate file: $cert_file" >&2
    return
  fi

  local b64
  b64="$(base64 < "$cert_file" | tr -d '\n')"

  local body
  if [[ -n "$password" ]]; then
    body="{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"${cmd}\",\"cert\":\"${cert_name}\",\"password\":\"${password}\",\"replace\":\"0\",\"data\":\"${b64}\"}"
  else
    body="{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"${cmd}\",\"cert\":\"${cert_name}\",\"replace\":\"0\",\"data\":\"${b64}\"}"
  fi

  local resp
  resp="$(apiv2 "$body")"
  if apiv2_status_ok "$resp"; then
    end_step_ok "$cert_name"
    return
  fi

  local msg
  msg="$(apiv2_message "$resp")"
  if echo "$msg" | grep -Eiq 'already|exists|duplicate'; then
    end_step_ok "already installed"
  else
    echo ""
    echo "  WARNING: Failed to run ${cmd} for ${cert_name}: ${msg:-unknown error}" >&2
  fi
}

echo "=== LoadMaster STIG Hardening ==="
echo "  Target: ${Api_Ip}:${Api_Port}"
echo ""

# Session management
echo "-- Session Management --"
set_param "sessioncontrol"          "yes"  "session control"
set_param "sessionbasicauth"        "0"    "disable basic auth on WUI"
set_param "sessionidletime"         "600"  "session idle timeout (10 min)"
set_param "sessionmaxfailattempts"  "5"    "max failed login attempts"
set_param "sessionconcurrent"       "3"    "max concurrent sessions"

echo ""
echo "-- TLS Hardening --"
set_param "WUITLSProtocols"         "7"    "WUI TLS protocols (TLS 1.2+1.3)"
set_param "sslrenegotiate"          "0"    "disable SSL renegotiation"

echo ""
echo "-- Network Security --"
set_param "nonlocalrs"              "yes"  "allow non-local real servers"
set_param "subnetorigin"            "yes"  "subnet originating requests"
set_param "multigw"                 "1"    "enable multiple gateways"

echo ""
echo "-- Security Features --"
set_param "KcdCipherSha1"           "yes"  "Kerberos AES256+SHA1"
set_param "CEFMsgFormat"            "yes"  "CEF log format"
set_param "adminclientaccess"       "1"    "password or client cert login"

echo ""
echo "-- Cipher Sets --"
begin_step "Setting WUI cipher set to FIPS2"
RESP=$(apiv2 "{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"set\",\"param\":\"WUICipherset\",\"value\":\"FIPS2\"}")
if echo "$RESP" | grep -q '"status":"ok"'; then
  end_step_ok
  set_param "OutboundCipherset" "FIPS2" "outbound cipher set to FIPS2"
elif echo "$RESP" | grep -qi "protocol.violation\|fips"; then
  end_step_ok "FIPS Mode active, skipping cipher management"
else
  echo ""
  echo "  WARNING: Could not set cipher set. Trying 'FIPS' (7.2.59+)..." >&2
  RESP=$(apiv2 "{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"set\",\"param\":\"WUICipherset\",\"value\":\"FIPS\"}")
  if echo "$RESP" | grep -q '"status":"ok"'; then
    echo "  Set WUICipherset=FIPS"
    set_param "OutboundCipherset" "FIPS" "outbound cipher set to FIPS"
  fi
fi

echo ""
echo "-- Management Certificate Install --"
begin_step "Uploading management cert ${MGMT_CERT_NAME}"
upload_cert_blob "addcert" "$MGMT_CERT_NAME" "$MGMT_CERT_PFX" "$MGMT_CERT_PASSWORD"

begin_step "Installing intermediate/root chain"
upload_cert_blob "addintermediate" "$(basename "$ICA_CERT_FILE" .crt | tr '[:lower:]' '[:upper:]')" "$ICA_CERT_FILE"
begin_step "Installing root CA"
upload_cert_blob "addintermediate" "$(basename "$RCA_CERT_FILE" .crt | tr '[:lower:]' '[:upper:]')" "$RCA_CERT_FILE"

echo ""
echo "-- Binding Management Certificate --"
set_param "admincert" "$MGMT_CERT_NAME" "admin interface certificate"

HAMODE=$(apiv2 "{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"get\",\"param\":\"hamode\"}" | jq -r '.hamode // ""')
if [[ -n "$HAMODE" && "$HAMODE" != "0" ]]; then
  set_param "localcert" "$MGMT_CERT_NAME" "HA local interface certificate"
fi

echo ""
echo "-- Disable GEO (port 53 listener) --"
begin_step "Disabling GEO"
RESP=$(apiv2 "{\"apiuser\":\"${Api_User}\",\"apipass\":\"${Api_Pass}\",\"cmd\":\"disablegeo\"}")
if echo "$RESP" | grep -q '"status":"ok"'; then
  end_step_ok
else
  end_step_ok "already disabled or not available"
fi

echo ""
echo "=== STIG Hardening Complete ==="
echo ""
echo "Manual steps remaining:"
echo "  - Configure warning banners (WUIPreauth, SSHPreAuth)"
echo "  - Configure NTP with authentication"
echo "  - Create certificate-based admin users"
echo "  - Review and disable Tethering if license allows"
