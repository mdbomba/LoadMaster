"""
Real Server Tools

Tools for managing real servers within virtual services on the LoadMaster.
"""

from mcp.server.fastmcp import FastMCP

from ..config import require_client


def _rs_selector(vs: str, port: str, prot: str, vs_index: str, rs: str, rsport: str) -> dict[str, str]:
    if vs_index:
        params = {"vs": vs_index}
    elif vs and port and prot:
        params = {"vs": vs, "port": port, "prot": prot}
    else:
        raise ValueError("Provide vs_index or all of vs, port, and prot.")
    if not rs or not rsport:
        raise ValueError("Both rs and rsport are required.")
    return {**params, "rs": rs, "rsport": rsport}


def register(mcp: FastMCP) -> None:
    """Register real server tools with the MCP server."""

    @mcp.tool()
    def lm_add_real_server(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        rs: str = "",
        rsport: str = "",
        weight: str = "",
        forward: str = "",
        enable: str = "Y",
        limit: str = "",
        critical: str = "",
        follow: str = "",
    ) -> str:
        """Add a real server to a virtual service.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            rs: Real server IP address
            rsport: Real server port
            weight: Server weight for weighted scheduling (1-65535)
            forward: Forwarding method (nat, route, masq)
            enable: Enable the RS - 'Y' or 'N' (default: Y)
            limit: Connection limit (0 = no limit)
            critical: Mark as critical - 'Y' or 'N'
            follow: Follow VS port - port number to follow
        """
        client = require_client()
        params = _rs_selector(vs, port, prot, vs_index, rs, rsport)
        if weight:
            params["Weight"] = weight
        if forward:
            params["Forward"] = forward
        if enable:
            params["Enable"] = enable
        if limit:
            params["Limit"] = limit
        if critical:
            params["Critical"] = critical
        if follow:
            params["Follow"] = follow

        resp = client.execute("addrs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_modify_real_server(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        rs: str = "",
        rsport: str = "",
        weight: str = "",
        forward: str = "",
        enable: str = "",
        limit: str = "",
        critical: str = "",
        follow: str = "",
        extra_params: str = "",
    ) -> str:
        """Modify an existing real server within a virtual service.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            rs: Real server IP address
            rsport: Real server port
            weight: Server weight (1-65535)
            forward: Forwarding method (nat, route, masq)
            enable: Enable/disable - 'Y' or 'N'
            limit: Connection limit (0 = no limit)
            critical: Mark as critical - 'Y' or 'N'
            follow: Follow VS port
            extra_params: Additional params as 'key1=val1&key2=val2'
        """
        client = require_client()
        params = _rs_selector(vs, port, prot, vs_index, rs, rsport)
        if weight:
            params["Weight"] = weight
        if forward:
            params["Forward"] = forward
        if enable:
            params["Enable"] = enable
        if limit:
            params["Limit"] = limit
        if critical:
            params["Critical"] = critical
        if follow:
            params["Follow"] = follow

        if extra_params:
            for pair in extra_params.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k.strip()] = v.strip()

        resp = client.execute("modrs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_delete_real_server(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        rs: str = "",
        rsport: str = "",
    ) -> str:
        """Remove a real server from a virtual service.

        WARNING: This permanently removes the real server from the VS.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            rs: Real server IP address
            rsport: Real server port
        """
        client = require_client()
        params = _rs_selector(vs, port, prot, vs_index, rs, rsport)

        resp = client.execute("delrs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_enable_real_server(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        rs: str = "",
        rsport: str = "",
    ) -> str:
        """Enable a real server (bring it back into rotation).

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            rs: Real server IP address
            rsport: Real server port
        """
        client = require_client()
        params = _rs_selector(vs, port, prot, vs_index, rs, rsport)
        params["Enable"] = "Y"

        resp = client.execute("modrs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_disable_real_server(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        rs: str = "",
        rsport: str = "",
    ) -> str:
        """Disable a real server (take it out of rotation gracefully).

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            rs: Real server IP address
            rsport: Real server port
        """
        client = require_client()
        params = _rs_selector(vs, port, prot, vs_index, rs, rsport)
        params["Enable"] = "N"

        resp = client.execute("modrs", params=params)
        return resp.to_text()
