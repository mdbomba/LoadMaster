"""
Certificate Management Tools

Tools for managing TLS/SSL certificates on the LoadMaster.
"""

import base64
import binascii
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..config import require_client
from ._binary import (
    decode_base64,
    format_binary_result,
    validate_base64,
    validate_certificate_password,
)


CertificatePassword = Annotated[
    str,
    Field(
        min_length=7,
        max_length=64,
        pattern=r"^[A-Za-z0-9]+$",
        description="Case-sensitive ASCII alphanumeric passphrase",
    ),
]


def _decode_base64(data: str) -> bytes:
    """Decode certificate data, with certificate-specific error wording.

    Shares validation with the shared _binary helper but keeps its own
    message so certificate upload failures stay actionable.
    """
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
    def lm_add_certificate(
        cert_name: str,
        cert_data: str,
        cert_type: str = "pem",
        password: str = "",
        replace: bool = False,
        api_version: Literal[1, 2] = 2,
    ) -> str:
        """Upload and install a TLS certificate.

        Args:
            cert_name: Name to assign to the certificate
            cert_data: Base64-encoded PEM bundle containing key, leaf, and chain
            cert_type: Deprecated compatibility field; pem or p12
            password: PFX password used when the certificate was generated
            replace: Replace an existing certificate with the same name
            api_version: API interface to use, 2 by default or 1 for compatibility
        """
        if cert_type not in {"pem", "p12"}:
            return "Error: cert_type must be pem or p12"
        try:
            data = validate_base64(cert_data)
        except ValueError as error:
            return f"Error: {error}"
        client = require_client()
        if api_version == 1:
            params = {"cert": cert_name, "replace": int(replace)}
            if password:
                params["password"] = password
            resp = client.upload_binary(
                "addcert",
                decode_base64(data),
                params=params,
                content_type="application/octet-stream",
                timeout=60,
            )
        else:
            # APIv2 addcert accepts the encoded bundle directly.  The password
            # is required by current firmware even when the PEM bundle is
            # unencrypted, and replace must be a string.
            resp = client.execute(
                "addcert",
                params={
                    "cert": cert_name,
                    "password": password,
                    "replace": "1" if replace else "0",
                    "data": data,
                },
                timeout=60,
                api_version=2,
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
    def lm_add_intermediate_certificate(
        cert_name: str,
        cert_data: str,
        api_version: Literal[1, 2] = 2,
    ) -> str:
        """Upload an intermediate CA certificate.

        Args:
            cert_name: Name to assign to the intermediate certificate
            cert_data: Base64-encoded certificate file content
            api_version: API interface to use, 2 by default or 1 for compatibility
        """
        try:
            data = validate_base64(cert_data)
        except ValueError as error:
            return f"Error: {error}"
        client = require_client()
        if api_version == 1:
            resp = client.upload_binary(
                "addintermediate",
                decode_base64(data),
                params={"cert": cert_name},
                content_type="application/x-www-form-urlencoded",
                timeout=60,
            )
        else:
            resp = client.execute(
                "addintermediate",
                params={"cert": cert_name, "data": data},
                timeout=60,
                api_version=2,
            )
        return resp.to_text()

    @mcp.tool()
    def lm_backup_certificates(
        password: CertificatePassword, api_version: Literal[1, 2] = 2
    ) -> str:
        """Backup all certificates using an alphanumeric passphrase.

        Args:
            password: Case-sensitive, 7-64 ASCII alphanumeric characters
            api_version: API interface to use, 2 by default or 1 for compatibility
        """
        try:
            password = validate_certificate_password(password)
        except ValueError as error:
            return f"Error: {error}"
        client = require_client()
        if api_version == 1:
            download = client.download_binary(
                "backupcert", params={"password": password}, timeout=60
            )
            if not download.success:
                return f"Error (code {download.status_code}): {download.message}"
            return format_binary_result(
                base64.b64encode(download.content).decode("ascii"),
                download.filename,
            )
        resp = client.execute(
            "backupcert",
            params={"password": password},
            timeout=60,
            api_version=2,
        )
        if not resp.success:
            return resp.to_text()
        data = resp.data.get("data")
        if not isinstance(data, str):
            return "Error: LoadMaster certificate backup response did not contain base64 data"
        try:
            return format_binary_result(data)
        except ValueError as error:
            return f"Error: LoadMaster returned invalid certificate backup data: {error}"

    @mcp.tool()
    def lm_restore_certificates(
        backup_data: str,
        password: CertificatePassword,
        restore_type: Literal["full", "third", "vs"],
        confirm_restore: bool,
        api_version: Literal[1, 2] = 2,
    ) -> str:
        """Restore a certificate backup.

        Args:
            backup_data: The base64 data field returned by lm_backup_certificates
            password: The alphanumeric passphrase used to create the backup
            restore_type: Restore scope: full, third, or vs
            confirm_restore: Must be true to authorize the certificate-store change
            api_version: API interface to use, 2 by default or 1 for compatibility
        """
        if restore_type not in {"full", "third", "vs"}:
            return "Error: restore_type must be one of: full, third, vs"
        if not confirm_restore:
            return "Error: confirm_restore must be true to restore certificates"
        try:
            password = validate_certificate_password(password)
            data = validate_base64(backup_data)
        except ValueError as error:
            return f"Error: {error}"
        client = require_client()
        params = {"password": password, "type": restore_type}
        if api_version == 1:
            resp = client.upload_binary(
                "restorecert",
                decode_base64(data),
                params=params,
                content_type="application/octet-stream",
                timeout=60,
            )
        else:
            params["data"] = data
            resp = client.execute(
                "restorecert", params=params, timeout=60, api_version=2
            )
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
