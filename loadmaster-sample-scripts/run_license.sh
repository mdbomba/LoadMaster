#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

ensure_tools

echo ""
echo "=== Kemp LoadMaster Licensing Wizard ==="
echo ""

# ── credentials ───────────────────────────────────────────────────────────────

load_license_params

prompt_if_empty Api_Ip       "Appliance IP address"
prompt_if_empty Api_Port     "Management port (default 443)"
prompt_if_empty Api_User     "API admin username"
prompt_if_empty Api_Pass     "API admin password" yes
prompt_if_empty New_Api_Pass "New password for admin account" yes
prompt_if_empty License_Type "License model (e.g. mela, melaenterprise)"
if [[ "${License_Type,,}" != "free" ]]; then
  prompt_if_empty Non_Free_License_Choice "Non-Free license choice (trial or paid)"
  Non_Free_License_Choice="${Non_Free_License_Choice,,}"
  if [[ "$Non_Free_License_Choice" != "trial" && "$Non_Free_License_Choice" != "paid" ]]; then
    echo "Non-Free license choice must be 'trial' or 'paid'." >&2
    exit 1
  fi
  if [[ "$Non_Free_License_Choice" == "paid" && -z "${Order_Id:-}" ]]; then
    if ! read -r -p "  Progress Order ID (required for paid license): " Order_Id; then
      Order_Id=""
    fi
    if [[ -z "$Order_Id" ]]; then
      echo "A valid Progress Order ID is required for a paid LoadMaster license. Build stopped before licensing." >&2
      exit 1
    fi
  fi
  if [[ "$Non_Free_License_Choice" == "trial" ]]; then
    License_Type="trial"
    Order_Id=""
  fi
fi
prompt_if_empty Progress_User "Progress (KEMP) account email"
prompt_if_empty Progress_Pass "Progress (KEMP) account password" yes
prompt_if_empty ntphost      "NTP server hostname or IP"
prompt_if_empty nameserver   "DNS nameserver(s) (comma-separated for multiple)"
prompt_if_empty hostname     "Appliance hostname"

echo ""
echo "  Appliance  : ${Api_Ip}:${Api_Port}"
echo "  API user   : ${Api_User}"
echo "  License    : ${License_Type}"
echo "  NTP        : ${ntphost}"
echo "  DNS        : ${nameserver}"
echo "  Hostname   : ${hostname}"
echo "  KEMP user  : ${Progress_User}"
echo "  Order ID   : ${Order_Id:-(trial)}"
echo ""

# ── step 0: discover VM IP if Vm_Name is set ──────────────────────────────────
#
# If Vm_Name is configured, use virsh to find the VM's actual IP.  This
# handles the common case where the VM boots with a DHCP address that differs
# from the desired Api_Ip.
#
#   - If the desired Api_Ip is already reachable → use it (already licensed check follows)
#   - If not, discover the actual IP via virsh and use that for licensing

if [[ -n "${Vm_Name:-}" ]]; then
  begin_step "Discovering VM IP (${Vm_Name})"
  if discover_vm_ip "$Vm_Name"; then
    if [[ "$VM_IP" != "$Api_Ip" ]]; then
      end_step_ok "found ${VM_IP} (desired: ${Api_Ip})"
      echo "  VM '${Vm_Name}' is at ${VM_IP}, not at desired ${Api_Ip}."
      echo "  Using ${VM_IP} for licensing; will set ${Api_Ip} after."
      _desired_ip="$Api_Ip"
      Api_Ip="$VM_IP"
    else
      end_step_ok "${VM_IP} (matches desired IP)"
    fi
  else
    end_step_ok "skipped (VM not reachable via virsh)"
  fi
fi

# ── step 1: check current license status ──────────────────────────────────────
#
# Test 1: Try the post-licensing password (New_Api_Pass) against the target IP.
#          If the appliance responds with code=ok, it is already licensed and
#          configured -- skip the entire workflow.
#
# Test 2: If test 1 fails, try the factory-default password (Api_Pass).
#          If that succeeds, the appliance is reachable but unlicensed --
#          proceed with licensing.
#
# If both tests fail, the appliance is unreachable at this IP.

begin_step "Checking license status (${Api_Ip})"

# Test 1 - post-licensing credentials
_saved_pass="$Api_Pass"
Api_Pass="${New_Api_Pass}"
run_endpoint_call "access/get" "postlic-check" "param=version" >/dev/null 2>&1
Api_Pass="$_saved_pass"
if [[ "$LAST_CODE" == "ok" ]]; then
  end_step_ok "already licensed"
  echo ""
  echo "  Appliance at ${Api_Ip} is already licensed (responded to post-licensing credentials)."
  echo "  Nothing to do."
  echo ""
  exit 0
fi

# Test 2 - factory-default credentials
run_endpoint_call "access/readeula" "precheck" "" >/dev/null 2>&1
if [[ -z "$LAST_CODE" ]] && [[ -z "$LAST_MAGIC" ]]; then
  end_step_fail "appliance at ${Api_Ip} is unreachable (no response to EULA or version check)"
fi
end_step_ok "unlicensed, proceeding"

# ── step 2: read EULA and get magic token ─────────────────────────────────────

begin_step "Reading EULA"
run_endpoint_call "access/readeula" "check" "" >/dev/null 2>&1
magic="$LAST_MAGIC"
if [[ -z "$magic" ]]; then
  end_step_fail "${LAST_ERROR:-no magic token returned}"
fi
end_step_ok "EULA token received"

# ── step 3: accept EULA (step 1) ──────────────────────────────────────────────

begin_step "Accepting EULA (step 1 of 2)"
run_endpoint_call "access/accepteula" "step1" "magic=${magic}&type=${License_Type}" >/dev/null 2>&1
magic2="$LAST_MAGIC"
if [[ -z "$magic2" ]]; then
  end_step_fail "${LAST_ERROR:-no second magic token}"
fi
end_step_ok

# ── step 4: accept EULA (step 2) ──────────────────────────────────────────────

begin_step "Accepting EULA (step 2 of 2)"
run_endpoint_call "access/accepteula2" "step2" "magic=${magic2}&accept=yes" >/dev/null 2>&1
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok

# ── step 5: fetch available license types ─────────────────────────────────────

begin_step "Fetching available license types"
encoded_pass="$(urlencode "$Progress_Pass")"
query="kempid=${Progress_User}&password=${encoded_pass}"
[[ -n "$Order_Id" ]] && query="${query}&orderid=${Order_Id}"
run_endpoint_call "access/alsilicensetypes" "fetch" "$query" >/dev/null 2>&1
success_json="$(extract_xml_value "$LAST_RAW_FILE" 'string(//Success)')"
if [[ -z "$success_json" ]]; then
  end_step_fail "${LAST_ERROR:-no license types returned}"
fi
mapfile -t _choices < <(printf '%s' "$success_json" | jq -r '.categories[].licenseTypes[] | "\(.id)|\(.description)"')
if [[ "${Non_Free_License_Choice:-}" == "trial" ]]; then
  mapfile -t _choices < <(printf '%s' "$success_json" | jq -r '.categories[].licenseTypes[] | select((.description // .name // "") | ascii_downcase | contains("trial")) | "\(.id)|\(.description)"')
fi
if [[ "${Non_Free_License_Choice:-}" == "paid" ]]; then
  mapfile -t _choices < <(printf '%s' "$success_json" | jq -r '.categories[].licenseTypes[] | select((((.description // .name // "") | ascii_downcase | contains("trial")) or (.free // false) or ((.description // .name // "") | ascii_downcase | contains("free"))) | not) | "\(.id)|\(.description)"')
fi
if [[ "${#_choices[@]}" -eq 0 ]]; then
  end_step_fail "no ${Non_Free_License_Choice:-requested} license types are available for this account"
fi
end_step_ok "${#_choices[@]} type(s) available"

# ── interactive license selection ─────────────────────────────────────────────

echo ""
echo "  Available license types:"
for i in "${!_choices[@]}"; do
  desc="${_choices[$i]#*|}"
  printf '    %d) %s\n' "$((i+1))" "$desc"
done
echo ""
while true; do
  read -r -p "  Select license type [1-${#_choices[@]}]: " _sel
  if [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_choices[@]} )); then
    lic_id="${_choices[$((_sel-1))]%%|*}"
    lic_desc="${_choices[$((_sel-1))]#*|}"
    echo "  → ${lic_desc}"
    echo ""
    break
  fi
  echo "  Invalid selection, please try again."
done

# ── step 6: install license ───────────────────────────────────────────────────

begin_step "Installing license"
query="kempid=${Progress_User}&password=${encoded_pass}&lic_type_id=${lic_id}"
[[ -n "$Order_Id" ]] && query="${query}&orderid=${Order_Id}"
run_endpoint_call "access/alsilicense" "install" "$query" 60 >/dev/null 2>&1
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok

# ── step 7: reset admin password ──────────────────────────────────────────────

begin_step "Resetting admin password"
encoded_new_pass="$(urlencode "$New_Api_Pass")"
for _attempt in 1 2 3 4 5; do
  run_endpoint_call "access/set_initial_passwd" "reset" "passwd=${encoded_new_pass}" >/dev/null 2>&1
  [[ "$LAST_CODE" == "ok" ]] && break
  sleep 5
done
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok
Api_Pass="${New_Api_Pass}"

sleep 10  # wait for appliance to complete post-licensing setup before re-enabling API

# ── step 8: re-enable API ─────────────────────────────────────────────────────

begin_step "Re-enabling API"
for _attempt in 1 2 3; do
  run_endpoint_call "access/set" "enableapi" "param=enableapi&value=yes" >/dev/null 2>&1
  [[ "$LAST_CODE" == "ok" ]] && break
  sleep 5
done
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok

# ── step 9: set NTP server ────────────────────────────────────────────────────

begin_step "Setting NTP server"
for _attempt in 1 2 3; do
  run_endpoint_call "access/set" "ntp" "param=ntphost&value=${ntphost}" >/dev/null 2>&1
  [[ "$LAST_CODE" == "ok" ]] && break
  sleep 3
done
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok "${ntphost}"

# ── step 10: set nameserver ───────────────────────────────────────────────────

begin_step "Setting DNS nameserver"
run_endpoint_call "access/set" "nameserver" "param=nameserver&value=${nameserver}" >/dev/null 2>&1
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok "${nameserver}"

# ── step 11: set hostname ─────────────────────────────────────────────────────

begin_step "Setting hostname"
run_endpoint_call "access/set" "hostname" "param=hostname&value=${hostname}" >/dev/null 2>&1
if [[ "$LAST_CODE" != "ok" ]]; then
  end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
fi
end_step_ok "${hostname}"

# ── step 12: change interface IP to desired address ───────────────────────────

if [[ -n "${_desired_ip:-}" ]]; then
  begin_step "Changing IP to ${_desired_ip}"
  run_endpoint_call "access/modiface" "setip" "iface=0&addr=${_desired_ip}/24" >/dev/null 2>&1
  if [[ "$LAST_CODE" != "ok" ]]; then
    end_step_fail "${LAST_ERROR:-code=${LAST_CODE}}"
  fi
  end_step_ok "${Api_Ip} -> ${_desired_ip}"
  Api_Ip="${_desired_ip}"
fi

# ── done ──────────────────────────────────────────────────────────────────────

echo ""
echo "  ✓  License installed successfully."
echo "  ✓  Admin password has been reset."
echo "  ✓  NTP server set to ${ntphost}."
echo "  ✓  DNS nameserver set to ${nameserver}."
echo "  ✓  Hostname set to ${hostname}."
echo "  ✓  Appliance reachable at ${Api_Ip}."
if [[ "${Vm_Name:-}" =~ ^[0-9]+_vlm[0-9]+$ ]]; then
  echo "  !  Test build incomplete: install and verify the required management TLS certificate."
  echo "     Follow ../loadmaster-documents/TEST-LOADMASTER-RUNBOOK.md#required-management-tls-certificate."
fi
echo "  Captures saved to: ${CAPTURE_ROOT}/licensing/"
echo ""
