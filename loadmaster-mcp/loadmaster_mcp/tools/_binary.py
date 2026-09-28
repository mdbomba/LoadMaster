"""Shared validation and formatting for binary MCP tool inputs and outputs."""

import base64
import binascii
import hashlib
import json


def validate_base64(data: str) -> str:
    """Validate base64 input and return a whitespace-free representation."""
    normalized = "".join(data.split())
    if not normalized:
        raise ValueError("backup or file data must not be empty")
    try:
        raw = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("data must be valid base64") from error
    if base64.b64encode(raw).decode("ascii") != normalized:
        raise ValueError("data must be canonical base64")
    return normalized


def decode_base64(data: str) -> bytes:
    """Validate and decode binary data supplied through MCP."""
    return base64.b64decode(validate_base64(data), validate=True)


def format_binary_result(data: str, filename: str = "") -> str:
    """Return a structured, integrity-checkable base64 result."""
    normalized = validate_base64(data)
    raw = base64.b64decode(normalized, validate=True)
    result = {
        "encoding": "base64",
        "data": normalized,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    if filename:
        result["filename"] = filename
    return json.dumps(result, separators=(",", ":"))


def validate_certificate_password(password: str) -> str:
    """Validate the documented certificate backup passphrase constraints."""
    if not 7 <= len(password) <= 64 or not password.isascii() or not password.isalnum():
        raise ValueError("password must be 7-64 ASCII alphanumeric characters")
    return password
