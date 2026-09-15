"""
Certificate Management Tools

Tools for managing TLS/SSL certificates on the LoadMaster.
"""

import base64
import binascii

from mcp.server.fastmcp import FastMCP

from ..config import require_client


def _decode_base64(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Certificate data must be valid base64: {e}") from e


def register(mcp: FastMCP) -> None:
    """Register certificate management tools with the MCP server."""

    @mcp.tool()
    def lm_list_certificates() -> str:
        """List all TLS/SSL certificates installed on the LoadMaster."""
        client = require_client()
        resp = client.get("listcert")
        return resp.to_text()

    @mcp.tool()
    def lm_get_certificate(cert_name: str) -> str:
        """Get details of a specific certificate.

        Args:
            cert_name: The certificate name/identifier
        """
        client = require_client()
        resp = client.execute("readcert", params={"cert": cert_name})
        return resp.to_text()

    @mcp.tool()
    def lm_add_certificate(cert_name: str, cert_data: str, cert_type: str = "pem") -> str:
        """Upload and install a TLS certificate.

        Args:
            cert_name: Name to assign to the certificate
            cert_data: Certificate content (PEM or PKCS12 base64 encoded)
            cert_type: Certificate type - 'pem' or 'p12' (default: pem)
        """
        client = require_client()
        params = {"cert": cert_name, "type": cert_type}
        resp = client.post(
            "addcert",
            params=params,
            data=_decode_base64(cert_data),
            content_type="application/x-www-form-urlencoded",
        )
        return resp.to_text()

    @mcp.tool()
    def lm_delete_certificate(cert_name: str) -> str:
        """Delete a certificate from the LoadMaster.

        WARNING: Ensure the certificate is not in use by any virtual service.

        Args:
            cert_name: The certificate name/identifier to delete
        """
        client = require_client()
        resp = client.execute("delcert", params={"cert": cert_name})
        return resp.to_text()

    @mcp.tool()
    def lm_add_intermediate_certificate(cert_name: str, cert_data: str) -> str:
        """Upload an intermediate CA certificate.

        Args:
            cert_name: Name to assign to the intermediate certificate
            cert_data: Certificate content (PEM format)
        """
        client = require_client()
        params = {"cert": cert_name}
        resp = client.post(
            "addintermediate",
            params=params,
            data=_decode_base64(cert_data),
            content_type="application/x-www-form-urlencoded",
        )
        return resp.to_text()

    @mcp.tool()
    def lm_backup_certificates() -> str:
        """Backup all certificates on the LoadMaster."""
        client = require_client()
        resp = client.get("backupcert")
        return resp.to_text()

    @mcp.tool()
    def lm_get_cipher_set(cipher_set: str = "") -> str:
        """Get the configured TLS cipher set.

        Args:
            cipher_set: Optional cipher set name to query
        """
        client = require_client()
        params = {}
        if cipher_set:
            params["name"] = cipher_set
        resp = client.execute("getcipherset", params=params if params else None)
        return resp.to_text()

    @mcp.tool()
    def lm_set_cipher_set(cipher_set: str, ciphers: str) -> str:
        """Configure the TLS cipher set.

        Args:
            cipher_set: Cipher set name
            ciphers: Colon-separated list of cipher names
        """
        client = require_client()
        resp = client.execute("setcipherset", params={"name": cipher_set, "value": ciphers})
        return resp.to_text()

    # ACME / Let's Encrypt
    @mcp.tool()
    def lm_list_le_certificates() -> str:
        """List all Let's Encrypt certificates."""
        client = require_client()
        resp = client.get("listlecert")
        return resp.to_text()

    @mcp.tool()
    def lm_request_le_certificate(domain: str) -> str:
        """Request a new Let's Encrypt certificate for a domain.

        Args:
            domain: The domain name to get a certificate for
        """
        client = require_client()
        resp = client.execute("addlecert", params={"domain": domain})
        return resp.to_text()

    @mcp.tool()
    def lm_renew_le_certificate(domain: str) -> str:
        """Renew a Let's Encrypt certificate.

        Args:
            domain: The domain name to renew
        """
        client = require_client()
        resp = client.execute("renewlecert", params={"domain": domain})
        return resp.to_text()
