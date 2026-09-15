"""
Licensing Tools

Tools for managing LoadMaster licensing, EULA acceptance, and initial setup.

Includes a pre-flight license check: before attempting any licensing operation,
the server tests whether the configured LoadMaster (LM_HOST) is already licensed
by issuing a lightweight API call with the configured credentials.  If the
appliance responds successfully, it is already licensed and the operation is
skipped.  This avoids redundant licensing attempts and makes the workflow
idempotent.

Also includes VM discovery: if LM_VM_NAME is set in .env, the server can query
libvirt (virsh) to discover the VM's actual IP address, which may differ from
LM_HOST when the VM has a DHCP-assigned address.

Licensing tools accept an optional host override so they can target an
unlicensed appliance at its DHCP address (different from LM_HOST in .env).
When host is provided, a temporary client is created with factory-default
credentials (bal / 1fourall).
"""

import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET

from mcp.server.fastmcp import FastMCP

from ..client import LoadMasterClient
from ..config import require_client, get_client, LMConfig

# Factory-default credentials for an unlicensed LoadMaster.
# These are well-known public defaults shipped with every LoadMaster appliance
# and are not secrets.  They are only used to communicate with an unlicensed
# appliance before the admin sets a real password.
_FACTORY_USER = "bal"
_FACTORY_PASS = "1fourall"


def _make_client(host: str = "", password: str = "") -> LoadMasterClient:
    """Create a LoadMaster client.

    If host is provided, creates a temporary client targeting that host
    with the given password (or factory-default credentials if no password).
    Otherwise returns the configured client from .env.
    """
    if host:
        return LoadMasterClient(
            host=host,
            port=443,
            username=_FACTORY_USER,
            password=password or _FACTORY_PASS,
            verify_ssl=False,
            timeout=30.0,
            use_api_v1=True,
        )
    return require_client()


def _make_prelicense_client(host: str = "", password: str = "") -> LoadMasterClient:
    """Create an APIv1 client for appliance initialization and licensing."""
    client = _make_client(host, password)
    return LoadMasterClient(
        host=client.host,
        port=client.port,
        username=client.username,
        password=client.password,
        api_key=client.api_key,
        verify_ssl=client.verify_ssl,
        timeout=client.timeout,
        use_api_v1=True,
    )


def _is_already_licensed() -> tuple[bool, str]:
    """Check if the configured LoadMaster is already licensed.

    Attempts a lightweight API call (access/get?param=version) using the
    configured credentials (LM_HOST + LM_PASSWORD from .env).

    Returns:
        (True, detail_message) if the appliance is already licensed.
        (False, detail_message) if it is not licensed or unreachable.
    """
    client = get_client()
    if client is None:
        return False, "LoadMaster not configured (LM_HOST not set)."

    try:
        resp = client.execute("get", params={"param": "version"})
        if resp.success:
            version = ""
            if isinstance(resp.data, dict):
                version = resp.data.get("version", resp.data.get("Version", ""))
            return True, (
                f"LoadMaster at {client.host} is already licensed"
                f"{f' (version {version})' if version else ''}. "
                f"Licensing is not required."
            )
        # Non-success could mean unlicensed (returns error), wrong password, etc.
        return False, (
            f"LoadMaster at {client.host} responded but may not be licensed: "
            f"{resp.message}"
        )
    except Exception as e:
        return False, (
            f"Could not reach LoadMaster at {client.host}: {e}. "
            f"The appliance may be unlicensed or unreachable."
        )


def _discover_vm_ip(vm_name: str) -> tuple[str, list[str], str]:
    """Discover the actual IP(s) of a libvirt VM using virsh.

    Uses 'virsh domifaddr --source arp' since LoadMaster VMs do not
    have the QEMU guest agent installed.

    Args:
        vm_name: The libvirt domain name (e.g. '14_vlm14')

    Returns:
        (state, ip_list, detail_message)
        state: VM state string ('running', 'shut off', etc.) or empty on error
        ip_list: list of discovered IPs (may be empty)
        detail_message: human-readable description of the result
    """
    try:
        state_result = subprocess.run(
            ["virsh", "domstate", vm_name],
            capture_output=True, text=True, timeout=10,
        )
        state = state_result.stdout.strip()
    except FileNotFoundError:
        return "", [], "virsh not found on this system."
    except subprocess.TimeoutExpired:
        return "", [], f"Timed out querying VM state for '{vm_name}'."
    except Exception as e:
        return "", [], f"Error querying VM state: {e}"

    if state != "running":
        return state, [], f"VM '{vm_name}' is not running (state: {state})."

    try:
        arp_result = subprocess.run(
            ["virsh", "domifaddr", vm_name, "--source", "arp"],
            capture_output=True, text=True, timeout=10,
        )
        # Parse lines like: " vnet7  52:54:00:42:59:62  ipv4  10.0.0.223/0"
        ips = re.findall(r"ipv4\s+(\d+\.\d+\.\d+\.\d+)", arp_result.stdout)
    except Exception as e:
        return state, [], f"VM '{vm_name}' is running but ARP lookup failed: {e}"

    if not ips:
        return state, [], f"VM '{vm_name}' is running but no IP found via ARP."

    return state, ips, f"VM '{vm_name}' is running with IP(s): {', '.join(ips)}"


def _select_license_type(raw_success: str, license_choice: str) -> str:
    """Return the first available license ID matching the requested class."""
    try:
        license_data = json.loads(raw_success)
    except json.JSONDecodeError:
        return ""

    for category in license_data.get("categories", []):
        for license_type in category.get("licenseTypes", []):
            label = " ".join(
                str(license_type.get(field, ""))
                for field in ("name", "description")
            ).lower()
            is_free = bool(license_type.get("free")) or "free" in label
            is_trial = "trial" in label
            if license_choice == "free" and is_free:
                return str(license_type.get("id", ""))
            if license_choice == "trial" and is_trial:
                return str(license_type.get("id", ""))
            if license_choice == "paid" and not is_free and not is_trial:
                return str(license_type.get("id", ""))
    return ""


def register(mcp: FastMCP) -> None:
    """Register licensing tools with the MCP server."""

    # ── Status / Discovery ─────────────────────────────────────────────────

    @mcp.tool()
    def lm_check_license_status() -> str:
        """Check if the LoadMaster is already licensed.

        Tests the configured LoadMaster (LM_HOST from .env) by making a
        lightweight API call with the configured credentials.  Use this
        before attempting any licensing operation to avoid redundant work.

        Returns:
            A message indicating whether the appliance is already licensed
            or needs licensing.
        """
        licensed, detail = _is_already_licensed()
        if licensed:
            return f"ALREADY LICENSED: {detail}"
        return f"NOT LICENSED: {detail}"

    @mcp.tool()
    def lm_discover_vm_ip() -> str:
        """Discover the actual IP of the LoadMaster VM using libvirt/virsh.

        Requires LM_VM_NAME to be set in .env (e.g. LM_VM_NAME=14_vlm14).
        Uses 'virsh domifaddr --source arp' to find the VM's IP address(es).

        This is useful when the VM boots with a DHCP address that differs
        from the configured LM_HOST.

        Returns:
            VM state, discovered IP(s), and whether they match LM_HOST.
        """
        config = LMConfig.from_env()
        if not config.vm_name:
            return (
                "LM_VM_NAME is not set in .env. "
                "Set it to the libvirt domain name (e.g. LM_VM_NAME=14_vlm14) "
                "to enable VM IP discovery."
            )

        state, ips, detail = _discover_vm_ip(config.vm_name)
        lines = [detail]

        if ips and config.host:
            if config.host in ips:
                lines.append(
                    f"Configured LM_HOST ({config.host}) matches a discovered IP."
                )
            else:
                lines.append(
                    f"Configured LM_HOST ({config.host}) does NOT match "
                    f"any discovered IP ({', '.join(ips)}). "
                    f"The VM may need licensing at {ips[0]}."
                )

        return "\n".join(lines)

    # ── EULA Flow ──────────────────────────────────────────────────────────

    @mcp.tool()
    def lm_read_eula() -> str:
        """Read the LoadMaster EULA.

        Returns the EULA text and a magic string needed for acceptance.
        This is the first step in the licensing workflow.

        NOTE: Automatically checks if the appliance is already licensed first.
        If it is, returns a message indicating licensing is not needed.
        """
        licensed, detail = _is_already_licensed()
        if licensed:
            return f"SKIP: {detail}"

        client = _make_prelicense_client()
        resp = client.get("readeula")
        return resp.to_text()

    @mcp.tool()
    def lm_accept_eula(magic: str) -> str:
        """Accept the LoadMaster EULA (step 1).

        Args:
            magic: The magic string from lm_read_eula response
        """
        client = _make_prelicense_client()
        resp = client.execute("accepteula", params={"magic": magic, "accept": "yes"})
        return resp.to_text()

    @mcp.tool()
    def lm_accept_eula2(magic: str, accept: str = "yes") -> str:
        """Accept/decline the telemetry EULA (step 2).

        Args:
            magic: The magic string from lm_accept_eula response
            accept: Accept telemetry - 'yes' or 'no'
        """
        client = _make_prelicense_client()
        resp = client.execute("accepteula2", params={"magic": magic, "accept": accept})
        return resp.to_text()

    # ── Licensing ──────────────────────────────────────────────────────────

    @mcp.tool()
    def lm_license_online(
        kemp_id: str,
        password: str,
        license_type: str = "",
    ) -> str:
        """License the LoadMaster online through KEMP licensing servers.

        NOTE: Automatically checks if the appliance is already licensed first.
        If it is, returns a message indicating licensing is not needed.

        IMPORTANT: The kemp_id and password are required. The AI assistant
        must ask the user for their Progress/KEMP account credentials before
        calling this tool. Never store these credentials in config files.

        Args:
            kemp_id: KEMP account ID/email (ask the user for this)
            password: KEMP account password (ask the user for this)
            license_type: License type (if applicable)
        """
        licensed, detail = _is_already_licensed()
        if licensed:
            return f"SKIP: {detail}"

        client = _make_prelicense_client()
        params: dict = {"kempid": kemp_id, "password": password}
        if license_type:
            params["type"] = license_type
        resp = client.execute("license", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_license_onpremise(
        kemp_id: str,
        password: str,
        lic_type_id: str,
        license_type: str = "free",
    ) -> str:
        """License the LoadMaster via on-premises ASL server.

        NOTE: Automatically checks if the appliance is already licensed first.
        If it is, returns a message indicating licensing is not needed.

        IMPORTANT: The kemp_id and password are required by the licensing API
        even for free licenses. The AI assistant must ask the user for their
        Progress/KEMP account credentials before calling this tool. Never
        store these credentials in config files.

        The lic_type_id should come from the lm_get_license_types response.

        Args:
            kemp_id: KEMP account ID/email (ask the user for this)
            password: KEMP account password (ask the user for this)
            lic_type_id: License type ID from lm_get_license_types response
            license_type: License type label (default: free)
        """
        licensed, detail = _is_already_licensed()
        if licensed:
            return f"SKIP: {detail}"

        client = _make_prelicense_client()
        params: dict = {
            "kempid": kemp_id,
            "password": password,
            "lic_type_id": lic_type_id,
        }
        resp = client.execute("alsilicense", params=params, timeout=90)
        return resp.to_text()

    @mcp.tool()
    def lm_get_license_types(
        kemp_id: str,
        password: str,
        order_id: str = "",
    ) -> str:
        """Get available license types from the KEMP licensing servers.

        IMPORTANT: The kemp_id and password are required. The AI assistant
        must ask the user for their Progress/KEMP account credentials before
        calling this tool. Never store these credentials in config files.

        Args:
            kemp_id: KEMP account ID/email (ask the user for this)
            password: KEMP account password (ask the user for this)
            order_id: Optional order ID to filter license types
        """
        client = _make_prelicense_client()
        params: dict = {"kempid": kemp_id, "password": password}
        if order_id:
            params["orderid"] = order_id
        resp = client.execute("alsilicensetypes", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_get_license_info() -> str:
        """Get current license information."""
        client = require_client()
        resp = client.get("licenseinfo")
        return resp.to_text()

    # ── Post-License Setup ─────────────────────────────────────────────────

    @mcp.tool()
    def lm_set_initial_password(password: str) -> str:
        """Set the initial system password after licensing.

        This is required after first licensing a new LoadMaster.

        IMPORTANT: The AI assistant must ask the user what password they
        want for the LoadMaster admin (bal) account before calling this
        tool. Never use a default or assume a password.

        Args:
            password: New admin password (ask the user for this)
        """
        client = _make_prelicense_client()
        resp = client.execute("set_initial_passwd", params={"passwd": password})
        return resp.to_text()

    @mcp.tool()
    def lm_enable_api() -> str:
        """Re-enable the API interface.

        Sometimes needed after password changes or licensing operations.
        """
        client = require_client()
        resp = client.execute("set", params={"param": "enableapi", "value": "yes"})
        return resp.to_text()

    # ── Full Workflow ──────────────────────────────────────────────────────

    @mcp.tool()
    def lm_license_full_workflow(
        kemp_id: str,
        password: str,
        new_password: str = "",
        image_type: str = "free",
        non_free_license: str = "",
        order_id: str = "",
        desired_ip: str = "",
        ntp_host: str = "pool.ntp.org",
        nameserver: str = "8.8.8.8,8.8.4.4",
        hostname: str = "",
    ) -> str:
        """Run the complete licensing workflow for a fresh LoadMaster.

        This is the all-in-one orchestration tool. It:
          1. Discovers the VM's actual IP via virsh (if LM_VM_NAME is set)
          2. Checks if already licensed at LM_HOST — skips if so
          3. Reads and accepts the EULA (both steps)
          4. Fetches license types and selects the requested license
          5. Installs the license
          6. Sets the initial admin password
          7. Re-enables the API
          8. Configures NTP, DNS, and hostname
          9. Changes the interface IP to the desired address (if provided)
         10. Requires management TLS certificate installation and verification
             before a test-VM build is complete; see TEST-LOADMASTER-RUNBOOK.md.

        IMPORTANT: The kemp_id, password, and new_password are required.
        For an explicitly requested non-Free image, ask the user whether they
        want a Trial License or Paid License. Paid License requires order_id;
        the workflow stops before changing the appliance when it is missing.
        The AI assistant must ask the user for:
          1. Their Progress/KEMP account credentials (kemp_id + password)
          2. The desired admin password for the LoadMaster (new_password)
        Never store these credentials in config files.

        Args:
            kemp_id: Progress/KEMP account email (ask the user for this)
            password: Progress/KEMP account password (ask the user for this)
            new_password: New admin password for the LoadMaster bal account
                          (ask the user for this - REQUIRED)
            image_type: 'free' (default) or 'non-free' for an explicitly
                        requested non-Free image.
            non_free_license: Required for non-Free images: 'trial' or 'paid'.
            order_id: Required for a non-Free paid license; omit for trial.
            desired_ip: Target IP with CIDR (e.g. '10.0.0.14/24'). If empty,
                        uses LM_HOST from .env with /24.
            ntp_host: NTP server (default: pool.ntp.org)
            nameserver: DNS nameservers, comma-separated (default: 8.8.8.8,8.8.4.4)
            hostname: Appliance hostname (default: derived from LM_VM_NAME)
        """
        config = LMConfig.from_env()
        log = []

        # ── Validate required credentials ──────────────────────────────────
        if not new_password:
            return (
                "FAILED: new_password is required. The AI assistant must ask "
                "the user what password they want for the LoadMaster admin "
                "account (bal) before calling this tool."
            )
        image_type = image_type.lower().strip()
        non_free_license = non_free_license.lower().strip()
        if image_type not in {"free", "non-free"}:
            return "FAILED: image_type must be 'free' or 'non-free'."
        if image_type == "non-free":
            if non_free_license not in {"trial", "paid"}:
                return (
                    "FAILED: A non-Free image requires an explicit license choice: "
                    "'trial' or 'paid'."
                )
            if non_free_license == "paid" and not order_id.strip():
                return (
                    "FAILED: A valid Progress Order ID is required for a paid "
                    "LoadMaster license. Build stopped before licensing."
                )
        else:
            non_free_license = "free"
        if not desired_ip:
            desired_ip = f"{config.host}/24" if config.host else ""
        desired_host = desired_ip.split("/")[0] if desired_ip else ""
        if not hostname:
            hostname = config.vm_name.split("_", 1)[-1] if config.vm_name else ""

        # ── Step 1: Check if already licensed at desired IP ────────────────
        licensed, detail = _is_already_licensed()
        if licensed:
            return f"ALREADY LICENSED: {detail}\nNo action taken."

        log.append(f"1. License check: not licensed at {config.host}")

        # ── Step 2: Discover actual VM IP ──────────────────────────────────
        actual_ip = ""
        if config.vm_name:
            state, ips, vm_detail = _discover_vm_ip(config.vm_name)
            log.append(f"2. VM discovery: {vm_detail}")
            if ips:
                actual_ip = ips[0]
            else:
                return f"FAILED at step 2: {vm_detail}"
        else:
            actual_ip = config.host
            log.append(f"2. VM discovery: skipped (LM_VM_NAME not set), using {actual_ip}")

        if not actual_ip:
            return "FAILED: Could not determine appliance IP address."

        # Create a client targeting the actual DHCP IP with factory creds
        client = _make_prelicense_client(actual_ip)

        # ── Step 3: Read EULA ──────────────────────────────────────────────
        resp = client.get("readeula")
        if not resp.success:
            return f"FAILED at step 3 (read EULA): {resp.message}"
        magic = ""
        if isinstance(resp.data, dict):
            magic = resp.data.get("Magic", resp.data.get("magic", ""))
        if not magic:
            # Try parsing from raw XML
            try:
                root = ET.fromstring(resp.raw_xml)
                magic_el = root.find(".//Magic")
                if magic_el is not None:
                    magic = magic_el.text or ""
            except Exception:
                pass
        if not magic:
            return f"FAILED at step 3: No magic token in EULA response."
        log.append("3. EULA read: token received")

        # ── Step 4: Accept EULA (step 1) ───────────────────────────────────
        resp = client.execute("accepteula", params={
            "magic": magic, "accept": "yes", "type": non_free_license,
        })
        if not resp.success:
            return f"FAILED at step 4 (accept EULA 1): {resp.message}"
        magic2 = ""
        if isinstance(resp.data, dict):
            magic2 = resp.data.get("Magic", resp.data.get("magic", ""))
        if not magic2:
            try:
                root = ET.fromstring(resp.raw_xml)
                magic_el = root.find(".//Magic")
                if magic_el is not None:
                    magic2 = magic_el.text or ""
            except Exception:
                pass
        if not magic2:
            return f"FAILED at step 4: No second magic token."
        log.append("4. EULA step 1: accepted")

        # ── Step 5: Accept EULA (step 2 — telemetry) ──────────────────────
        resp = client.execute("accepteula2", params={
            "magic": magic2, "accept": "yes",
        })
        if not resp.success:
            return f"FAILED at step 5 (accept EULA 2): {resp.message}"
        log.append("5. EULA step 2: accepted")

        # ── Step 6: Fetch license types ────────────────────────────────────
        license_params = {
            "kempid": kemp_id, "password": password,
        }
        if order_id:
            license_params["orderid"] = order_id
        resp = client.execute("alsilicensetypes", params=license_params)
        if not resp.success:
            return f"FAILED at step 6 (license types): {resp.message}"

        # Parse the JSON from the Success element to find the requested license.
        license_id = ""
        raw_success = ""
        if resp.raw_xml:
            try:
                root = ET.fromstring(resp.raw_xml)
                success_el = root.find(".//Success")
                if success_el is not None:
                    raw_success = success_el.text or ""
            except Exception:
                pass
        if raw_success:
            try:
                license_id = _select_license_type(raw_success, non_free_license)
            except (json.JSONDecodeError, KeyError):
                pass
        if not license_id:
            return (
                f"FAILED at step 6: Could not find a {non_free_license} license type. "
                f"Raw response available for manual inspection."
            )
        log.append(f"6. License types: {non_free_license} license found (id: {license_id[:12]}...)")

        # ── Step 7: Install the selected license ────────────────────────────
        license_params = {
            "kempid": kemp_id,
            "password": password,
            "lic_type_id": license_id,
        }
        if order_id:
            license_params["orderid"] = order_id
        resp = client.execute("alsilicense", params=license_params, timeout=90)
        if not resp.success:
            return f"FAILED at step 7 (install license): {resp.message}"
        log.append(f"7. License installed: {non_free_license} LoadMaster")

        # ── Step 8: Set initial password ───────────────────────────────────
        time.sleep(10)  # appliance restarts internally after licensing
        for attempt in range(1, 6):
            resp = client.execute("set_initial_passwd", params={
                "passwd": new_password,
            })
            if resp.success:
                break
            time.sleep(5)
        if not resp.success:
            return f"FAILED at step 8 (set password): {resp.message}"
        log.append("8. Admin password set")

        # Switch to new-password client for remaining steps
        client = _make_prelicense_client(actual_ip, new_password)
        time.sleep(5)

        # ── Step 9: Re-enable API ──────────────────────────────────────────
        for attempt in range(1, 4):
            resp = client.execute("set", params={
                "param": "enableapi", "value": "yes",
            })
            if resp.success:
                break
            time.sleep(5)
        if not resp.success:
            return f"FAILED at step 9 (enable API): {resp.message}"
        log.append("9. API re-enabled")

        # APIv2 is now available and avoids APIv1 URL size and escaping limits.
        client.use_api_v1 = False

        # ── Step 10: Set NTP ───────────────────────────────────────────────
        resp = client.execute("set", params={
            "param": "ntphost", "value": ntp_host,
        })
        if resp.success:
            log.append(f"10. NTP set: {ntp_host}")
        else:
            log.append(f"10. NTP failed: {resp.message} (non-fatal)")

        # ── Step 11: Set DNS ───────────────────────────────────────────────
        resp = client.execute("set", params={
            "param": "nameserver", "value": nameserver,
        })
        if resp.success:
            log.append(f"11. DNS set: {nameserver}")
        else:
            log.append(f"11. DNS failed: {resp.message} (non-fatal)")

        # ── Step 12: Set hostname ──────────────────────────────────────────
        if hostname:
            resp = client.execute("set", params={
                "param": "hostname", "value": hostname,
            })
            if resp.success:
                log.append(f"12. Hostname set: {hostname}")
            else:
                log.append(f"12. Hostname failed: {resp.message} (non-fatal)")
        else:
            log.append("12. Hostname: skipped (not provided)")

        # ── Step 13: Change interface IP ───────────────────────────────────
        if desired_ip and desired_host != actual_ip:
            resp = client.execute("modiface", params={
                "iface": "0", "addr": desired_ip,
            })
            if resp.success:
                log.append(f"13. IP changed: {actual_ip} -> {desired_ip}")
                log.append(f"    Appliance now reachable at {desired_host}")
            else:
                log.append(f"13. IP change failed: {resp.message}")
        else:
            log.append(f"13. IP change: skipped (already at desired IP)")

        # ── Summary ────────────────────────────────────────────────────────
        log.insert(0, "=== LoadMaster Licensing Complete ===\n")
        log.append("")
        log.append("Done. The LoadMaster is licensed and configured.")
        if config.vm_name and re.fullmatch(r"\d+_vlm\d+", config.vm_name):
            log.append(
                "REQUIRED NEXT STEP: Generate, install, and verify the locally signed "
                "management TLS certificate before considering this test build complete. "
                "Follow loadmaster-documents/TEST-LOADMASTER-RUNBOOK.md."
            )
        if new_password != config.password:
            log.append("")
            log.append(
                f"NOTE: The admin password was set to a value different from "
                f"LM_PASSWORD in .env. Update .env and restart the MCP server "
                f"so that lm_check_license_status and other tools use the "
                f"correct password."
            )
        return "\n".join(log)
