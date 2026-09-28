"""
System Management Tools

Tools for managing LoadMaster system settings, backup/restore, and maintenance.
"""

import base64
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..config import require_client
from ._binary import decode_base64, format_binary_result, validate_base64


def register(mcp: FastMCP) -> None:
    """Register system management tools with the MCP server."""

    @mcp.tool()
    def lm_set_parameter(param: str, value: str) -> str:
        """Set a LoadMaster system parameter.

        Args:
            param: The parameter name (e.g., 'hostname', 'ntphost', 'nameserver',
                   'hamode', 'WUITLSProtocols', 'sessioncontrol')
            value: The value to set
        """
        client = require_client()
        resp = client.execute("set", params={"param": param, "value": value})
        return resp.to_text()

    @mcp.tool()
    def lm_reboot() -> str:
        """Reboot the LoadMaster.

        WARNING: This will cause a service interruption. In HA configurations,
        the partner unit will take over.
        """
        client = require_client()
        resp = client.get("reboot")
        return resp.to_text()

    @mcp.tool()
    def lm_shutdown() -> str:
        """Shutdown the LoadMaster.

        WARNING: This will completely shut down the unit. It will need to be
        manually powered back on.
        """
        client = require_client()
        resp = client.get("shutdown")
        return resp.to_text()

    @mcp.tool()
    def lm_backup(api_version: Literal[1, 2] = 2) -> str:
        """Create a backup of the LoadMaster configuration.

        Returns JSON containing base64 backup data, its size, and SHA-256 hash.
        Pass the JSON data field to lm_restore.

        Args:
            api_version: API interface to use, 2 by default or 1 for compatibility
        """
        client = require_client()
        if api_version == 1:
            download = client.download_binary("backup")
            if not download.success:
                return f"Error (code {download.status_code}): {download.message}"
            return format_binary_result(
                base64.b64encode(download.content).decode("ascii"),
                download.filename,
            )
        resp = client.execute("backup", api_version=2)
        if not resp.success:
            return resp.to_text()
        data = resp.data.get("data")
        if not isinstance(data, str):
            return "Error: LoadMaster backup response did not contain base64 data"
        try:
            return format_binary_result(data)
        except ValueError as error:
            return f"Error: LoadMaster returned invalid backup data: {error}"

    @mcp.tool()
    def lm_restore(
        backup_data: str,
        restore_type: Annotated[int, Field(ge=1, le=15)],
        confirm_restore: bool,
        api_version: Literal[1, 2] = 2,
    ) -> str:
        """Restore a LoadMaster configuration from backup.

        Args:
            backup_data: The base64 data field returned by lm_backup
            restore_type: Configuration scope, an integer from 1 through 15
            confirm_restore: Must be true to authorize the configuration change
            api_version: API interface to use, 2 by default or 1 for compatibility
        """
        if not 1 <= restore_type <= 15:
            return "Error: restore_type must be an integer from 1 through 15"
        if not confirm_restore:
            return "Error: confirm_restore must be true to perform a configuration restore"
        try:
            data = validate_base64(backup_data)
        except ValueError as error:
            return f"Error: {error}"
        client = require_client()
        if api_version == 1:
            resp = client.upload_binary(
                "restore",
                decode_base64(data),
                params={"type": restore_type},
                content_type="application/octet-stream",
            )
        else:
            resp = client.execute(
                "restore",
                params={"type": restore_type, "data": data},
                api_version=2,
            )
        return resp.to_text()

    @mcp.tool()
    def lm_get_datetime() -> str:
        """Get the current date/time configuration of the LoadMaster."""
        client = require_client()
        resp = client.get("get", param="ntphost")
        ntp = resp.to_text()
        resp2 = client.get("get", param="time")
        time_info = resp2.to_text()
        return f"NTP Configuration:\n{ntp}\n\nCurrent Time:\n{time_info}"

    @mcp.tool()
    def lm_install_patch(patch_data: str, confirm: bool = False) -> str:
        """Install a firmware patch on the LoadMaster.

        Args:
            patch_data: The patch file content (base64 encoded)
            confirm: Confirm installation, required for LoadMaster 7.2.61 and newer
        """
        client = require_client()
        try:
            patch = decode_base64(patch_data)
        except ValueError as error:
            return f"Error: {error}"
        resp = client.upload_binary(
            "installpatch",
            data=patch,
            params={"confirm": "yes"} if confirm else None,
            content_type="application/octet-stream",
        )
        return resp.to_text()

    @mcp.tool()
    def lm_rollback_patch() -> str:
        """Rollback the last installed firmware patch."""
        client = require_client()
        resp = client.get("restorepatch")
        return resp.to_text()

    @mcp.tool()
    def lm_get_firmware_version() -> str:
        """Get the current and previous firmware versions."""
        client = require_client()
        resp = client.get("get", param="version")
        version = resp.to_text()
        resp2 = client.get("getpreviousfirmwareversion")
        prev = resp2.to_text()
        return f"Current Version:\n{version}\n\nPrevious Version:\n{prev}"

    @mcp.tool()
    def lm_install_addon(addon_data: str) -> str:
        """Install an add-on package on the LoadMaster.

        Args:
            addon_data: The add-on package content (base64 encoded)
        """
        client = require_client()
        try:
            addon = decode_base64(addon_data)
        except ValueError as error:
            return f"Error: {error}"
        resp = client.upload_binary(
            "addaddon",
            data=addon,
            content_type="application/octet-stream",
        )
        return resp.to_text()

    @mcp.tool()
    def lm_list_addons() -> str:
        """List all installed add-on packages."""
        client = require_client()
        resp = client.get("listaddon")
        return resp.to_text()

    @mcp.tool()
    def lm_remove_addon(name: str) -> str:
        """Remove an installed add-on package.

        Args:
            name: The add-on name to remove
        """
        client = require_client()
        resp = client.execute("deladdon", params={"name": name})
        return resp.to_text()

    @mcp.tool()
    def lm_get_statistics() -> str:
        """Get LoadMaster statistics (CPU, memory, network, TPS, disk usage)."""
        client = require_client()
        resp = client.get("stats")
        return resp.to_text()
