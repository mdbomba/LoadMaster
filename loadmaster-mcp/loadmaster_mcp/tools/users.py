"""
User & Security Tools

Tools for managing users, API keys, and security settings on the LoadMaster.
"""

from mcp.server.fastmcp import FastMCP

from ..config import require_client


def register(mcp: FastMCP) -> None:
    """Register user/security tools with the MCP server."""

    # --- Local Users ---

    @mcp.tool()
    def lm_list_users() -> str:
        """List all local admin users on the LoadMaster."""
        client = require_client()
        resp = client.get("userlist")
        return resp.to_text()

    @mcp.tool()
    def lm_add_user(user: str, password: str, perms: str = "1") -> str:
        """Create a new local admin user.

        Permission levels:
          1 = Read-only
          2 = Read-write (no security)
          3 = Full admin

        Args:
            user: Username
            password: User password
            perms: Permission level (1, 2, or 3)
        """
        client = require_client()
        resp = client.execute("adduser", params={"user": user, "password": password, "perms": perms})
        return resp.to_text()

    @mcp.tool()
    def lm_delete_user(user: str) -> str:
        """Delete a local admin user.

        Args:
            user: Username to delete
        """
        client = require_client()
        resp = client.execute("deluser", params={"user": user})
        return resp.to_text()

    @mcp.tool()
    def lm_set_user_permission(user: str, perms: str) -> str:
        """Set permissions for a user.

        Args:
            user: Username
            perms: Permission level (1=read-only, 2=read-write, 3=full admin)
        """
        client = require_client()
        resp = client.execute("moduser", params={"user": user, "perms": perms})
        return resp.to_text()

    @mcp.tool()
    def lm_change_user_password(user: str, currpassword: str, password: str) -> str:
        """Change a user's password.

        Args:
            user: Username
            currpassword: Current password
            password: New password
        """
        client = require_client()
        resp = client.execute(
            "moduser",
            params={"user": user, "currpassword": currpassword, "password": password},
        )
        return resp.to_text()

    # --- Remote User Groups ---

    @mcp.tool()
    def lm_list_remote_user_groups() -> str:
        """List all remote user groups (LDAP/RADIUS-authenticated groups)."""
        client = require_client()
        resp = client.get("showremotegroup")
        return resp.to_text()

    @mcp.tool()
    def lm_add_remote_user_group(group: str, perms: str = "1") -> str:
        """Create a remote user group.

        Args:
            group: Group name (must match LDAP/RADIUS group)
            perms: Permission level (1=read-only, 2=read-write, 3=full admin)
        """
        client = require_client()
        resp = client.execute("addremotegroup", params={"group": group, "perms": perms})
        return resp.to_text()

    @mcp.tool()
    def lm_delete_remote_user_group(group: str) -> str:
        """Delete a remote user group.

        Args:
            group: Group name to delete
        """
        client = require_client()
        resp = client.execute("delremotegroup", params={"group": group})
        return resp.to_text()

    # --- API Keys ---

    @mcp.tool()
    def lm_list_api_keys() -> str:
        """List all API security keys."""
        client = require_client()
        resp = client.get("listapikeys")
        return resp.to_text()

    @mcp.tool()
    def lm_generate_api_key() -> str:
        """Generate a new API key for the authenticated user."""
        client = require_client()
        resp = client.execute("addapikey")
        return resp.to_text()

    @mcp.tool()
    def lm_revoke_api_key(key: str) -> str:
        """Revoke/delete an API security key.

        Args:
            key: The complete API key value to revoke
        """
        client = require_client()
        resp = client.execute("delapikey", params={"key": key})
        return resp.to_text()

    # --- WUI Security ---

    @mcp.tool()
    def lm_get_wui_security() -> str:
        """Get WUI (Web User Interface) security configuration.

        Returns TLS protocol settings, login method, and cert mapping config.
        """
        client = require_client()
        resp = client.get("get", param="WUITLSProtocols")
        tls = resp.to_text()
        resp2 = client.get("get", param="wuiloginmethod")
        login = resp2.to_text()
        return f"WUI TLS Protocols:\n{tls}\n\nLogin Method:\n{login}"

    @mcp.tool()
    def lm_set_wui_tls_protocols(protocols: str) -> str:
        """Set the TLS protocols allowed for WUI access.

        Args:
            protocols: TLS protocol range (e.g., 'tls1.2-tls1.3')
        """
        client = require_client()
        resp = client.execute("set", params={"param": "WUITLSProtocols", "value": protocols})
        return resp.to_text()

    @mcp.tool()
    def lm_set_wui_login_method(method: str) -> str:
        """Set the WUI login method.

        Login methods:
          0 = Password Only
          1 = Password or Client Certificate
          2 = Client Certificate Required
          3 = Client Certificate Required with OCSP

        Args:
            method: Login method number (0-3)
        """
        client = require_client()
        resp = client.execute("set", params={"param": "wuiloginmethod", "value": method})
        return resp.to_text()
