#!/usr/bin/env bash
set -euo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${COMMON_DIR}/.." && pwd)"

CAPTURE_ROOT_DEFAULT="${PROJECT_ROOT}/captures"
CAPTURE_ROOT="${CAPTURE_ROOT:-$CAPTURE_ROOT_DEFAULT}"
LICENSE_PARAMS_NAME_DEFAULT="license.params"
LICENSE_PARAMS_NAME="${LICENSE_PARAMS_NAME:-$LICENSE_PARAMS_NAME_DEFAULT}"

LAST_ENDPOINT=""
LAST_SCENARIO=""
LAST_URL=""
LAST_RAW_FILE=""
LAST_CODE=""
LAST_ERROR=""
LAST_MAGIC=""

# ── display helpers ────────────────────────────────────────────────────────────

_STEP_LABEL=""

begin_step() {
  _STEP_LABEL="$1"
  printf '  %-45s' "${_STEP_LABEL} ..."
}

end_step_ok() {
  local detail="${1:-}"
  if [[ -n "$detail" ]]; then
    printf ' ✓  %s\n' "$detail"
  else
    printf ' ✓\n'
  fi
}

end_step_fail() {
  local reason="${1:-unknown error}"
  printf ' ✗  %s\n' "$reason" >&2
  exit 1
}

prompt_if_empty() {
  local var="$1"
  local prompt_text="$2"
  local secret="${3:-no}"
  if [[ -z "${!var:-}" ]]; then
    if [[ "$secret" == "yes" ]]; then
      read -r -s -p "  ${prompt_text}: " "${var}"; echo
    else
      read -r -p "  ${prompt_text}: " "${var}"
    fi
  fi
}

# ── tools / params ─────────────────────────────────────────────────────────────

ensure_tools() {
  local missing=0
  for cmd in curl xmllint date sed jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Missing required command: $cmd" >&2
      missing=1
    fi
  done
  if [[ "$missing" -eq 1 ]]; then
    exit 1
  fi
}

load_license_params() {
  local params_default="${COMMON_DIR}/${LICENSE_PARAMS_NAME}"
  if [[ ! -f "$params_default" ]]; then
    params_default="${PROJECT_ROOT}/${LICENSE_PARAMS_NAME}"
  fi
  local params_file="${LICENSE_PARAMS_FILE:-$params_default}"
  if [[ -f "$params_file" ]]; then
    # shellcheck disable=SC1090
    source "$params_file"
  fi

  Api_User="${Api_User:-bal}"
  Api_Pass="${Api_Pass:-1fourall}"
  Api_Ip="${Api_Ip:-}"
  Api_Port="${Api_Port:-443}"
  Vm_Name="${Vm_Name:-}"
  Progress_User="${Progress_User:-}"
  Progress_Pass="${Progress_Pass:-}"
  Order_Id="${Order_Id:-}"
  Non_Free_License_Choice="${Non_Free_License_Choice:-}"
  New_Api_Pass="${New_Api_Pass:-}"
  License_Type="${License_Type:-}"
  ntphost="${ntphost:-}"
  hostname="${hostname:-}"
  nameserver="${nameserver:-}"

  if [[ -z "${Api_Ip}" ]]; then
    echo "Api_Ip is required. Set it in license.params or export Api_Ip." >&2
    exit 1
  fi
}

api_base() {
  printf 'https://%s:%s' "$Api_Ip" "$Api_Port"
}

utc_ts() {
  date -u +%Y%m%dT%H%M%SZ
}

safe_endpoint_slug() {
  local endpoint="$1"
  echo "$endpoint" | tr '/' '-'
}

ensure_capture_dir() {
  local scope="$1"
  mkdir -p "${CAPTURE_ROOT}/${scope}"
}

urlencode() {
  local input="$1"
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$input" | jq -sRr @uri
  else
    printf '%s' "$input"
  fi
}

mask_query() {
  local q="${1:-}"
  if [[ -z "$q" ]]; then
    printf ''
    return 0
  fi
  printf '%s' "$q" \
    | sed -E 's/(password=)[^&]*/\1***MASKED***/g' \
    | sed -E 's/(passwd=)[^&]*/\1***MASKED***/g' \
    | sed -E 's/(apipass=)[^&]*/\1***MASKED***/g'
}

extract_xml_value() {
  local xml_file="$1"
  local xpath="$2"
  xmllint --xpath "$xpath" "$xml_file" 2>/dev/null || true
}

run_endpoint_call() {
  local endpoint="$1"
  local scenario="$2"
  local query="${3:-}"
  local max_time="${4:-30}"

  local scope="licensing"
  ensure_capture_dir "$scope"

  local ts
  ts="$(utc_ts)"

  local slug
  slug="$(safe_endpoint_slug "$endpoint")"

  local base
  base="$(api_base)"

  local url="${base}/${endpoint}"
  if [[ -n "$query" ]]; then
    url="${url}?${query}"
  fi

  local raw_file="${CAPTURE_ROOT}/${scope}/${slug}__${scenario}__${ts}.xml"
  local info_file="${CAPTURE_ROOT}/${scope}/${slug}__${scenario}__${ts}.info.txt"

  sleep 1
  curl -k -sS --connect-timeout 5 --max-time "${max_time}" -u "${Api_User}:${Api_Pass}" "$url" > "$raw_file" || true

  local code
  code="$(extract_xml_value "$raw_file" 'string(/Response/@code)')"
  local error_text
  error_text="$(extract_xml_value "$raw_file" 'string(//Error)')"
  local magic
  magic="$(extract_xml_value "$raw_file" 'string(//Magic)')"

  LAST_ENDPOINT="$endpoint"
  LAST_SCENARIO="$scenario"
  LAST_URL="$url"
  LAST_RAW_FILE="$raw_file"
  LAST_CODE="$code"
  LAST_ERROR="$error_text"
  LAST_MAGIC="$magic"

  cat > "$info_file" <<EOF
endpoint=${endpoint}
scenario=${scenario}
method=GET
timestamp_utc=${ts}
api_host=${Api_Ip}:${Api_Port}
query_masked=$(mask_query "$query")
code=${code}
error=${error_text}
magic=${magic}
raw_response_file=${raw_file}
EOF

  echo "endpoint=${endpoint} scenario=${scenario} code=${code}"
  [[ -n "$error_text" ]] && echo "error=${error_text}"
  [[ -n "$magic" ]] && echo "magic=${magic}"
  echo "raw=${raw_file}"
  echo "info=${info_file}"
}

# ── VM discovery ───────────────────────────────────────────────────────────────

discover_vm_ip() {
  # Discover the actual IP of a libvirt VM using virsh.
  # Uses --source arp (guest agent not available on LoadMaster).
  #
  # Args:
  #   $1 - VM name (e.g. 14_vlm14)
  #
  # Sets:
  #   VM_STATE  - "running", "shut off", etc.
  #   VM_IPS    - space-separated list of discovered IPs
  #   VM_IP     - first discovered IP (empty if none found)
  #
  local vm_name="${1:?VM name required}"

  VM_STATE=""
  VM_IPS=""
  VM_IP=""

  if ! command -v virsh >/dev/null 2>&1; then
    echo "virsh not found, skipping VM discovery" >&2
    return 1
  fi

  VM_STATE="$(virsh domstate "$vm_name" 2>/dev/null || true)"
  VM_STATE="$(echo "$VM_STATE" | tr -d '[:space:]')"

  if [[ "$VM_STATE" != "running" ]]; then
    echo "VM '$vm_name' is not running (state: ${VM_STATE:-unknown})" >&2
    return 1
  fi

  # Parse IPs from virsh domifaddr --source arp
  # Output format: " vnet7  52:54:00:42:59:62  ipv4  10.0.0.223/0"
  local arp_output
  arp_output="$(virsh domifaddr "$vm_name" --source arp 2>/dev/null || true)"

  VM_IPS="$(echo "$arp_output" | awk '/ipv4/ { split($4, a, "/"); print a[1] }')"
  VM_IP="$(echo "$VM_IPS" | head -1)"

  if [[ -z "$VM_IP" ]]; then
    echo "VM '$vm_name' is running but no IP found via ARP" >&2
    return 1
  fi

  return 0
}
