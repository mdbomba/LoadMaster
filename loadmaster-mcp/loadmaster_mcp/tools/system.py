"""
System Management Tools

Tools for managing LoadMaster system settings, backup/restore, and maintenance.
"""

import base64
import binascii

from mcp.server.fastmcp import FastMCP

from ..config import require_client


def _decode_base64(data: str) -> bytes:
    """Decode MCP-provided base64 upload data with a clear user-facing error."""
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Upload data must be valid base64: {e}") from e


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
    def lm_backup() -> str:
        """Create a backup of the LoadMaster configuration.

        Returns the backup data that can be used for restore operations.
        """
        client = require_client()
        resp = client.get("backup")
        return resp.to_text()

    @mcp.tool()
    def lm_restore(backup_data: str) -> str:
        """Restore a LoadMaster configuration from backup.

        Args:
            backup_data: The backup data (base64 encoded configuration)
        """
        client = require_client()
        resp = client.post(
            "restore",
            data=_decode_base64(backup_data),
            content_type="application/octet-stream",
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
    def lm_install_patch(patch_data: str) -> str:
        """Install a firmware patch on the LoadMaster.

        Args:
            patch_data: The patch file content (base64 encoded)
        """
        client = require_client()
        resp = client.post(
            "installpatch",
            data=_decode_base64(patch_data),
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
        resp = client.post(
            "installaddon",
            data=_decode_base64(addon_data),
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
