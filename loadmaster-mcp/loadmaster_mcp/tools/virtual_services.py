"""
Virtual Service Tools

Tools for creating, modifying, and deleting virtual services on the LoadMaster.
"""

from typing import Optional

from mcp.server.fastmcp import FastMCP

from ..config import require_client


def _vs_selector(vs: str, port: str, prot: str, vs_index: str) -> dict[str, str]:
    if vs_index:
        return {"vs": vs_index}
    if vs and port and prot:
        return {"vs": vs, "port": port, "prot": prot}
    raise ValueError("Provide vs_index or all of vs, port, and prot.")


def register(mcp: FastMCP) -> None:
    """Register virtual service tools with the MCP server."""

    @mcp.tool()
    def lm_add_virtual_service(
        vs: str,
        port: str,
        prot: str = "tcp",
        nickname: str = "",
        enable: str = "Y",
        schedule: str = "",
        persist: str = "",
        check_type: str = "",
        transparent: str = "",
        forcel7: str = "",
    ) -> str:
        """Create a new virtual service on the LoadMaster.

        Args:
            vs: Virtual service IP address
            port: Virtual service port (e.g., '80', '443')
            prot: Protocol - 'tcp' or 'udp' (default: tcp)
            nickname: Friendly name for the VS
            enable: Enable the VS - 'Y' or 'N' (default: Y)
            schedule: Scheduling method (rr, wrr, lc, wlc, fixed, adaptive, sh, rsh)
            persist: Persistence mode (none, cookie, src, super, rdp, ssl)
            check_type: Health check type (tcp, icmp, https, http, nntp, ftp, smtp, dns, ldap, none)
            transparent: Transparent mode - 'Y' or 'N'
            forcel7: Force L7 processing - 'Y' or 'N'
        """
        client = require_client()
        params: dict = {"vs": vs, "port": port, "prot": prot}
        if nickname:
            params["NickName"] = nickname
        if enable:
            params["Enable"] = enable
        if schedule:
            params["Schedule"] = schedule
        if persist:
            params["Persist"] = persist
        if check_type:
            params["CheckType"] = check_type
        if transparent:
            params["Transparent"] = transparent
        if forcel7:
            params["ForceL7"] = forcel7
        resp = client.execute("addvs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_modify_virtual_service(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
        nickname: str = "",
        enable: str = "",
        schedule: str = "",
        persist: str = "",
        persist_timeout: str = "",
        check_type: str = "",
        check_url: str = "",
        check_port: str = "",
        transparent: str = "",
        forcel7: str = "",
        forcel4: str = "",
        idletime: str = "",
        server_init: str = "",
        client_cert: str = "",
        security_header_options: str = "",
        extra_params: str = "",
    ) -> str:
        """Modify an existing virtual service.

        Identify the VS by either vs+port+prot OR vs_index.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
            nickname: Friendly name for the VS
            enable: Enable/disable - 'Y' or 'N'
            schedule: Scheduling method (rr, wrr, lc, wlc, fixed, adaptive, sh, rsh)
            persist: Persistence mode (none, cookie, src, super, rdp, ssl)
            persist_timeout: Persistence timeout in seconds
            check_type: Health check type (tcp, icmp, https, http, none, etc.)
            check_url: Health check URL path
            check_port: Health check port
            transparent: Transparent mode - 'Y' or 'N'
            forcel7: Force L7 processing - 'Y' or 'N'
            forcel4: Force L4 processing - 'Y' or 'N'
            idletime: Idle timeout in seconds
            server_init: Server-initiated connections - 'Y' or 'N'
            client_cert: Client certificate requirement (0=no, 1=optional, 2=required)
            security_header_options: Security header options
            extra_params: Additional params as 'key1=val1&key2=val2' for parameters
                          not explicitly listed above
        """
        client = require_client()
        params: dict = _vs_selector(vs, port, prot, vs_index)

        if nickname:
            params["NickName"] = nickname
        if enable:
            params["Enable"] = enable
        if schedule:
            params["Schedule"] = schedule
        if persist:
            params["Persist"] = persist
        if persist_timeout:
            params["PersistTimeout"] = persist_timeout
        if check_type:
            params["CheckType"] = check_type
        if check_url:
            params["CheckUrl"] = check_url
        if check_port:
            params["CheckPort"] = check_port
        if transparent:
            params["Transparent"] = transparent
        if forcel7:
            params["ForceL7"] = forcel7
        if forcel4:
            params["ForceL4"] = forcel4
        if idletime:
            params["Idletime"] = idletime
        if server_init:
            params["ServerInit"] = server_init
        if client_cert:
            params["ClientCert"] = client_cert
        if security_header_options:
            params["SecurityHeaderOptions"] = security_header_options

        # Parse extra params
        if extra_params:
            for pair in extra_params.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k.strip()] = v.strip()

        if len(params) == 1 if vs_index else len(params) == 3:
            raise ValueError("Provide at least one virtual service setting to modify.")

        resp = client.execute("modvs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_delete_virtual_service(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
    ) -> str:
        """Delete a virtual service from the LoadMaster.

        WARNING: This permanently removes the VS and all associated real servers.

        Identify the VS by either vs+port+prot OR vs_index.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
        """
        client = require_client()
        params = _vs_selector(vs, port, prot, vs_index)

        resp = client.execute("delvs", params=params)
        return resp.to_text()

    @mcp.tool()
    def lm_export_vs_template(
        vs: str = "",
        port: str = "",
        prot: str = "",
        vs_index: str = "",
    ) -> str:
        """Export a virtual service configuration as a reusable template.

        Args:
            vs: Virtual service IP address
            port: Virtual service port
            prot: Protocol (tcp or udp)
            vs_index: VS index number (alternative to vs+port+prot)
        """
        client = require_client()
        params: dict = {}
        if vs_index:
            params["vs"] = vs_index
        else:
            if vs:
                params["vs"] = vs
            if port:
                params["port"] = port
            if prot:
                params["prot"] = prot

        resp = client.execute("exportvstmplt", params=params)
        return resp.to_text()
