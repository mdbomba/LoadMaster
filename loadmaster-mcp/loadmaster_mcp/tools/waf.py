"""
WAF (Web Application Firewall) Tools

Tools for managing WAF rules and configuration on the LoadMaster.
"""

from mcp.server.fastmcp import FastMCP

from ..config import require_client


def register(mcp: FastMCP) -> None:
    """Register WAF tools with the MCP server."""

    @mcp.tool()
    def lm_waf_get_rules() -> str:
        """List all WAF rules/rulesets on the LoadMaster."""
        client = require_client()
        resp = client.get("listawfrules")
        return resp.to_text()

    @mcp.tool()
    def lm_waf_install_rules(rules_data: str = "") -> str:
        """Install the WAF rules database previously downloaded by LoadMaster.

        Args:
            rules_data: Deprecated. Direct WAF database upload is not supported.
        """
        if rules_data:
            return (
                "Error: rules_data is no longer accepted because the documented "
                "maninstallwafrules command does not upload a request body"
            )
        client = require_client()
        resp = client.execute("maninstallwafrules")
        return resp.to_text()

    @mcp.tool()
    def lm_waf_get_auto_update() -> str:
        """Get WAF rules auto-update configuration."""
        client = require_client()
        resp = client.get("getwafautoupdate")
        return resp.to_text()

    @mcp.tool()
    def lm_waf_set_auto_update(
        enable: str = "",
        hour: str = "",
        interval: str = "",
    ) -> str:
        """Configure WAF rules auto-update settings.

        Args:
            enable: Enable auto-update - 'yes' or 'no'
            hour: Hour to run update (0-23)
            interval: Update interval in hours
        """
        client = require_client()
        params: dict = {}
        if enable:
            params["enable"] = enable
        if hour:
            params["hour"] = hour
        if interval:
            params["interval"] = interval
        resp = client.execute("setwafautoupdate", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_waf_get_audit_files() -> str:
        """List WAF audit log files."""
        client = require_client()
        resp = client.get("listwafauditfiles")
        return resp.to_text()

    @mcp.tool()
    def lm_waf_get_changelog() -> str:
        """Get the WAF rules change log."""
        client = require_client()
        resp = client.get("getwafchangelog")
        return resp.to_text()

    @mcp.tool()
    def lm_waf_get_custom_rulesets() -> str:
        """List custom WAF rule sets."""
        client = require_client()
        resp = client.get("listwafcustomrulesets")
        return resp.to_text()

    @mcp.tool()
    def lm_waf_add_custom_ruleset(name: str) -> str:
        """Create a new custom WAF rule set.

        Args:
            name: Name for the custom rule set
        """
        client = require_client()
        resp = client.execute("addwafcustomruleset", params={"name": name})
        return resp.to_text()

    @mcp.tool()
    def lm_waf_delete_custom_ruleset(name: str) -> str:
        """Delete a custom WAF rule set.

        Args:
            name: Name of the custom rule set to delete
        """
        client = require_client()
        resp = client.execute("delwafcustomruleset", params={"name": name})
        return resp.to_text()

    @mcp.tool()
    def lm_waf_get_custom_rule_data(name: str) -> str:
        """Get the content/data of a custom WAF rule set.

        Args:
            name: Custom rule set name
        """
        client = require_client()
        resp = client.execute("getwafcustomruledata", params={"name": name})
        return resp.to_text()

    @mcp.tool()
    def lm_waf_set_custom_rule_data(name: str, data: str) -> str:
        """Set/update the content of a custom WAF rule set.

        Args:
            name: Custom rule set name
            data: Rule data content
        """
        client = require_client()
        resp = client.post(
            "setwafcustomruledata",
            params={"name": name},
            data=data.encode("utf-8"),
            content_type="application/octet-stream",
        )
        return resp.to_text()

    @mcp.tool()
    def lm_waf_enable_on_vs(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        intercept_mode: str = "1",
        intercept_opts: str = "",
        blocking_paranoia: str = "",
    ) -> str:
        """Enable WAF on a virtual service.

        Intercept modes:
          0 = Detection Only (log but don't block)
          1 = Block (actively block malicious requests)

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            intercept_mode: WAF mode - '0' (detect) or '1' (block)
            intercept_opts: OWASP options flags
            blocking_paranoia: Paranoia level (1-4, higher = stricter)
        """
        client = require_client()
        params: dict = {"Intercept": "1"}
        if vs_index:
            params["vs"] = vs_index
        else:
            if vs:
                params["vs"] = vs
            if port:
                params["port"] = port
            if prot:
                params["prot"] = prot
        if intercept_mode:
            params["InterceptMode"] = intercept_mode
        if intercept_opts:
            params["OwaspOpts"] = intercept_opts
        if blocking_paranoia:
            params["BlockingParanoia"] = blocking_paranoia
        resp = client.execute("modvs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_waf_disable_on_vs(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
    ) -> str:
        """Disable WAF on a virtual service.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
        """
        client = require_client()
        params: dict = {"Intercept": "0"}
        if vs_index:
            params["vs"] = vs_index
        else:
            if vs:
                params["vs"] = vs
            if port:
                params["port"] = port
            if prot:
                params["prot"] = prot
        resp = client.execute("modvs", params=params)
        return resp.to_text()
