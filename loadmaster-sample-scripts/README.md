# LoadMaster Sample Scripts & Reference

Automation scripts, parameter reference, and the KEMP PowerShell SDK for managing LoadMaster appliances.

## Contents

| File/Directory | Description |
|----------------|-------------|
| `_common.sh` | Shared bash helpers (config loading, API capture, display, prompting) |
| `run_license.sh` | Interactive production runner — full licensing workflow |
| `license.sh` | Standalone licensing script (single-file alternative) |
| `license.params` | Configuration file for credentials and settings |
| `licensing/*.sh` | One script per API endpoint for testing individual calls |
| `params-reference.md` | Complete parameter reference with current values and APIv2 usage |
| `getall.xml` | Raw XML output from `access/getall` for reference |
| `LM-STIG-Script_v3.ps1` | PowerShell STIG hardening script (US Gov compliance) |
| `powershell-sdk-vnext-master/` | KEMP PowerShell SDK (Apache 2.0, third-party) |

## Licensing Scripts

### Layout
- `_common.sh` — shared helpers (config, capture, display, prompting)
- `run_license.sh` — interactive production runner; walks through the full licensing workflow
- `licensing/*.sh` — one script per API endpoint; can be run standalone for testing

## Usage
From `/home/chef`:

```bash
./loadmaster-sample-scripts/run_license.sh
```

Credentials are read from `license.params` if it exists; any missing values are prompted interactively.

## Standalone endpoint scripts
Each script in `licensing/` accepts an optional scenario label:

```bash
./loadmaster-sample-scripts/licensing/access-readeula.sh success
./loadmaster-sample-scripts/licensing/access-accepteula.sh missing-param
```

Supported scenarios: `success`, `missing-param`, `invalid-value`, `out-of-sequence`, `auth-failed`

## Environment overrides
- `LICENSE_PARAMS_FILE` — parameter file path (default: `/home/chef/license.params`)
- `CAPTURE_ROOT` — where raw responses are saved (default: `/home/chef/captures`)
- `LICENSE_TYPE` — license model passed to `access/accepteula` (default: `freemax`)
- `MAGIC` / `MAGIC2` / `LIC_TYPE_ID` — token overrides for standalone scriptlet use

## Captured output
Every API call saves two files under `captures/licensing/`:
- `*.xml` — raw response body
- `*.info.txt` — request metadata with passwords masked

## Known timing delays
Certain commands take significantly longer than normal API calls. The runner handles
these automatically, but be aware when calling scriptlets standalone:

| Command / Step | Reason | Handling |
|---|---|---|
| `access/alsilicense` | Contacts Progress licensing servers externally | `max_time=60`, retries |
| `access/set_initial_passwd` | Appliance settling after post-license restart | 5 retries × 5s gap |
| `access/set?param=enableapi` | Same post-license restart window | 3 retries × 5s gap |
| `access/modiface` | Interface reconfiguration | Subsequent calls must use new IP |
| Certificate operations | External CA calls / key generation | Use `max_time=60`, add retries |

The default `max_time` for all other calls is 30 seconds.

The PS module (`master-deployment.ps1`) notes online licensing checks "could take up to 5 minutes"
and uses `sleep 5` after appliance online detection plus `sleep 3` before/after several init calls.

## Post-licensing required steps

After licensing completes and the initial password is set, the API interface must be
re-enabled before any further configuration commands will work:

```bash
# Re-enable the API interface (REQUIRED after licensing)
curl -sk -u "bal:$NEW_PASS" "https://$LM_IP/access/set?param=enableapi&value=1"
```

Without this step, subsequent API calls will fail with authentication or access errors.

For a test-VM build, management TLS is also required after networking is
configured. Generate the locally signed certificate, install it as `admincert`,
and verify the presented certificate as described in
`../loadmaster-documents/TEST-LOADMASTER-RUNBOOK.md`. The license runner prints
this requirement when `Vm_Name` follows the test VM naming convention.

## Management interface IP configuration

After licensing, the management interface IP can be changed using `access/modiface`.
The address must use **CIDR notation** (e.g., `10.0.0.14/24`):

```bash
# Set management interface (eth0 = iface 0) to new IP
curl -sk -u "bal:$PASS" "https://$LM_IP/access/modiface?iface=0&addr=10.0.0.14/24"

# IMPORTANT: After this call, the appliance only responds on the NEW address
curl -sk -u "bal:$PASS" "https://10.0.0.14/access/showiface?iface=0"
```

**Notes:**
- The `addr` parameter requires CIDR notation (e.g., `10.0.0.14/24`), not separate mask parameters
- Passing `mask=255.255.255.0` as a separate parameter returns `Network prefix out of range`
- After the address change, the original IP is no longer reachable
- Verify connectivity at the new address before proceeding with further configuration

## API Strategy: APIv2 Default, APIv1 Fallback

**Use APIv2 (`/accessv2` JSON POST) as the default** for all post-licensing operations.
Fall back to APIv1 (`/access/<cmd>?params`) only during the pre-license phase or for
quick interactive debugging.

| Phase | Interface | Reason |
|-------|-----------|--------|
| EULA + Licensing | APIv1 | Appliance not fully initialized |
| Set initial password | APIv1 | Appliance not fully initialized |
| Re-enable API | APIv2 | STIG script pattern |
| **All post-license config** | **APIv2** | No size limits, JSON responses, reliable |
| Template upload (`uploadtemplate`) | APIv1 | Binary file POST — not a JSON operation |
| Quick spot checks | APIv1 | Convenience (one-liner) |

### APIv2 Usage (Recommended Default)

```bash
# Generic pattern for any command:
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"<command>","param":"<name>","value":"<value>"}'

# Set a parameter
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"set","param":"hostname","value":"vlm14"}'

# Get a parameter
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"get","param":"hostname"}'

# Response is always JSON:
# {"code": 200, "hostname": "vlm14", "status": "ok"}

# Using API key instead of username/password:
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apikey":"<key>","cmd":"set","param":"hostname","value":"vlm14"}'
```

### APIv1 Fallback (Pre-License / Debugging Only)

```bash
# Simple one-liner for quick checks (short values only)
curl -sk -u "bal:PASS" "https://$LM_IP/access/get?param=hostname"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=hostname&value=vlm14"
```

### Why APIv2 is Default

| Feature | APIv1 | APIv2 |
|---------|-------|-------|
| Size limit | ~2000-4000 chars (fails silently) | None |
| Response format | XML (harder to parse) | JSON (use `jq`) |
| Auth | Basic Auth header | In JSON body |
| Special chars | Must URL-encode | JSON escaping |
| STIG script | Not used | Primary method |

### Known APIv1 Failure Case

Setting parameters with long values (e.g., HTML warning banners) via APIv1 causes a
**connection reset** (HTTP status 000 / empty response). This was observed live when
setting the `WUIPreauth` HTML banner (~1800 characters). The `SSHPreAuth` banner (~500
chars) worked via APIv1, but it's safer to use APIv2 for all operations to avoid guessing
whether a value might exceed the limit.

## License source flows
| Source | EULA type | License command |
|--------|-----------|-----------------|
| `ONLINE` | `free`/`trial` | `alsilicense` (no orderid) |
| `ONLINE-SPLA` | `free`/`trial` | `alsilicense` (with orderid) or `spla_license` |
| `LOCAL-SPLA` | `free`/`trial` | `aslactivate` (`aslhost`, `aslport`) |
| `LOCAL-MELA` | `free`/`trial` | `aslactivate` (`aslhost`, `aslport`) |

## Kill / deactivate commands (from PS module source)
| REST Command | PS Cmdlet | Parameters | Notes |
|-------------|-----------|------------|-------|
| `access/kill_instance` | `Remove-Instance` | `name`, `passwd`, `kill=1` | Non-SPLA deactivation |
| `access/kill_spla_instance` | `Remove-SplaInstance` | `name`, `passwd`, `kill=1` | SPLA deactivation |
| `access/killaslinstance` | `Stop-AslInstance` | none | ASL deactivation |

All three kill commands return `Unknown command` on firmware `7.2.54.x` (LTSF train).
