"""
LoadMaster API client.

Post-license commands use the JSON API by default. API v1 remains available
for pre-license commands and endpoints that require raw binary transfers.
"""

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


_API_V1_COMMANDS = {
    "readeula",
    "accepteula",
    "accepteula2",
    "alsilicensetypes",
    "alsilicense",
    "license",
    "set_initial_passwd",
    "installpatch",
}


@dataclass
class LMResponse:
    """Parsed LoadMaster API response."""

    status_code: int
    success: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    raw_xml: str = ""
    raw_json: str = ""

    def to_text(self) -> str:
        """Format response as readable text for MCP tool output."""
        lines = []
        if self.success:
            lines.append(f"Success (code {self.status_code})")
        else:
            lines.append(f"Error (code {self.status_code}): {self.message}")
            return "\n".join(lines)

        if self.message and self.message not in {
            "Command successfully executed.",
            "Command completed ok",
        }:
            lines.append(f"Message: {self.message}")

        if self.data:
            lines.append("")
            lines.extend(_format_data(self.data))

        return "\n".join(lines)


@dataclass
class LMBinaryResponse:
    """A byte-preserving API v1 download response."""

    status_code: int
    success: bool
    message: str
    content: bytes = b""
    filename: str = ""


def _format_data(data: Any, indent: int = 0) -> list[str]:
    """Recursively format response data into readable lines."""
    lines = []
    prefix = "  " * indent
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.extend(_format_data(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.extend(_format_data(item, indent + 1))
                        lines.append(f"{prefix}  ---")
                    else:
                        lines.append(f"{prefix}  - {item}")
            else:
                lines.append(f"{prefix}{key}: {value}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                lines.extend(_format_data(item, indent))
                lines.append(f"{prefix}---")
            else:
                lines.append(f"{prefix}- {item}")
    else:
        lines.append(f"{prefix}{data}")
    return lines


def _parse_xml_element(element: ET.Element) -> Any:
    """Recursively parse an XML element into a Python dict or string."""
    children = list(element)
    if not children:
        return (element.text or "").strip()

    child_tags = [child.tag for child in children]
    if len(set(child_tags)) == 1 and len(child_tags) > 1:
        return [_parse_xml_element(child) for child in children]

    result: dict[str, Any] = {
        f"@{name}": value for name, value in element.attrib.items()
    }
    for child in children:
        child_value = _parse_xml_element(child)
        if child.tag in result:
            existing = result[child.tag]
            if isinstance(existing, list):
                existing.append(child_value)
            else:
                result[child.tag] = [existing, child_value]
        else:
            result[child.tag] = child_value
    return result


def parse_lm_response(raw_xml: str, http_status: int = 0) -> LMResponse:
    """Parse an API v1 XML response."""
    if not raw_xml.strip():
        return LMResponse(
            status_code=http_status,
            success=False,
            message="Empty response from LoadMaster",
            raw_xml=raw_xml,
        )

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as error:
        return LMResponse(
            status_code=http_status,
            success=False,
            message=f"Failed to parse XML response: {error}",
            raw_xml=raw_xml,
        )

    status_value = root.get("stat", "")
    if not status_value:
        status_element = root.find("stat")
        if status_element is not None and status_element.text:
            status_value = status_element.text.strip()
    try:
        status_code = int(status_value) if status_value else http_status
    except ValueError:
        status_code = http_status

    error_element = root.find(".//Error")
    if error_element is not None and error_element.text:
        return LMResponse(
            status_code=status_code,
            success=False,
            message=error_element.text.strip(),
            raw_xml=raw_xml,
        )

    success_element = root.find(".//Success")
    data: Any = {}
    message = ""
    if success_element is not None:
        data = _parse_xml_element(success_element)
        if isinstance(data, dict):
            message = data.pop("Message", data.pop("message", ""))
            if "Data" in data and isinstance(data["Data"], dict):
                data = data["Data"]
            elif "Data" in data:
                data = {"Data": data["Data"]}
    else:
        data = _parse_xml_element(root)
        if isinstance(data, dict):
            message = data.pop("Message", data.pop("message", ""))

    if not message:
        message = "Command successfully executed."
    success = 200 <= status_code < 300 and root.get("code", "ok") != "fail"
    return LMResponse(
        status_code=status_code,
        success=success,
        message=message,
        data=data if isinstance(data, dict) else {"value": data},
        raw_xml=raw_xml,
    )


def parse_lm_json(raw_json: str, http_status: int = 0) -> LMResponse:
    """Parse an API v2 JSON response."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as error:
        return LMResponse(
            status_code=http_status,
            success=False,
            message=f"Failed to parse JSON response: {error}",
            raw_json=raw_json,
        )
    if not isinstance(payload, dict):
        return LMResponse(
            status_code=http_status,
            success=False,
            message="LoadMaster returned a non-object JSON response",
            raw_json=raw_json,
        )

    try:
        status_code = int(payload.get("code", http_status))
    except (TypeError, ValueError):
        status_code = http_status
    status = str(payload.get("status", "")).lower()
    success = 200 <= status_code < 300 and status != "fail"
    message = str(payload.get("message", ""))
    if not message:
        message = "Command successfully executed." if success else "LoadMaster command failed"
    data = {
        key: value
        for key, value in payload.items()
        if key not in {"code", "status", "message"}
    }
    return LMResponse(
        status_code=status_code,
        success=success,
        message=message,
        data=data,
        raw_json=raw_json,
    )


class LoadMasterClient:
    """HTTP client for the Kemp LoadMaster REST APIs."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
        use_api_v1: bool = False,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._transport = transport
        self.use_api_v1 = use_api_v1
        self._base_url = f"https://{host}:{port}"

    @property
    def _auth(self) -> Optional[httpx.BasicAuth]:
        if not self.api_key and self.username and self.password:
            return httpx.BasicAuth(self.username, self.password)
        return None

    def _client(self, timeout: float) -> httpx.Client:
        return httpx.Client(
            verify=self.verify_ssl,
            timeout=timeout,
            transport=self._transport,
        )

    def _v1_params(self, params: Optional[dict[str, Any]]) -> dict[str, Any]:
        result = {key: value for key, value in (params or {}).items() if value is not None}
        if self.api_key:
            result["apikey"] = self.api_key
        return result

    def _v2_payload(self, command: str, params: Optional[dict[str, Any]]) -> dict[str, Any]:
        payload: dict[str, Any] = {"cmd": command}
        if self.api_key:
            payload["apikey"] = self.api_key
        elif self.username and self.password:
            payload["apiuser"] = self.username
            payload["apipass"] = self.password
        payload.update({key: value for key, value in (params or {}).items() if value is not None})
        return payload

    def _error_response(self, error: Exception, timeout: float) -> LMResponse:
        if isinstance(error, httpx.ConnectError):
            message = f"Connection failed to {self.host}:{self.port}: {error}"
        elif isinstance(error, httpx.TimeoutException):
            message = f"Request timed out after {timeout}s: {error}"
        else:
            message = f"Unexpected error: {error}"
        return LMResponse(status_code=0, success=False, message=message)

    def execute(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
        api_version: Optional[int] = None,
    ) -> LMResponse:
        """Execute a command, using API v2 unless API v1 is explicitly required.

        A client constructed with use_api_v1=True forces every command to
        API v1, which the pre-license flow needs because a license is not
        installed yet and v2 cannot authenticate.
        """
        if self.use_api_v1:
            version = 1
        else:
            version = api_version or (1 if command in _API_V1_COMMANDS else 2)
        if version == 1:
            return self.execute_v1(command, params=params, timeout=timeout)
        if version == 2:
            return self.execute_v2(command, params=params, timeout=timeout)
        raise ValueError("api_version must be 1 or 2")

    def execute_v1(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> LMResponse:
        """Execute an API v1 command and parse its XML response."""
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            with self._client(effective_timeout) as client:
                response = client.get(
                    f"{self._base_url}/access/{command}",
                    params=self._v1_params(params),
                    auth=self._auth,
                    headers={"User-Agent": "LoadMasterMCP/2.0"},
                )
            return parse_lm_response(response.text, response.status_code)
        except Exception as error:
            return self._error_response(error, effective_timeout)

    def execute_v2(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> LMResponse:
        """Execute an API v2 JSON command."""
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            with self._client(effective_timeout) as client:
                response = client.post(
                    f"{self._base_url}/accessv2",
                    json=self._v2_payload(command, params),
                    headers={"User-Agent": "LoadMasterMCP/2.0"},
                )
            return parse_lm_json(response.text, response.status_code)
        except Exception as error:
            return self._error_response(error, effective_timeout)

    def download_binary(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> LMBinaryResponse:
        """Download an API v1 response without decoding or parsing its bytes."""
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            with self._client(effective_timeout) as client:
                response = client.get(
                    f"{self._base_url}/access/{command}",
                    params=self._v1_params(params),
                    auth=self._auth,
                    headers={"User-Agent": "LoadMasterMCP/2.0"},
                )
            content_type = response.headers.get("content-type", "").lower()
            if response.is_success and "application/octet-stream" in content_type:
                disposition = response.headers.get("content-disposition", "")
                filename = disposition.split("filename=", 1)[-1].strip('" ') if "filename=" in disposition else ""
                return LMBinaryResponse(
                    status_code=response.status_code,
                    success=True,
                    message="Binary download completed.",
                    content=response.content,
                    filename=filename,
                )
            parsed = parse_lm_response(response.text, response.status_code)
            return LMBinaryResponse(
                status_code=parsed.status_code,
                success=False,
                message=parsed.message,
            )
        except Exception as error:
            parsed = self._error_response(error, effective_timeout)
            return LMBinaryResponse(parsed.status_code, False, parsed.message)

    def upload_binary(
        self,
        command: str,
        data: bytes,
        params: Optional[dict[str, Any]] = None,
        content_type: str = "application/octet-stream",
        timeout: Optional[float] = None,
    ) -> LMResponse:
        """Upload raw bytes to an API v1 endpoint and parse its XML response."""
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            with self._client(effective_timeout) as client:
                response = client.post(
                    f"{self._base_url}/access/{command}",
                    params=self._v1_params(params),
                    auth=self._auth,
                    headers={
                        "User-Agent": "LoadMasterMCP/2.0",
                        "Content-Type": content_type,
                    },
                    content=data,
                )
            return parse_lm_response(response.text, response.status_code)
        except Exception as error:
            return self._error_response(error, effective_timeout)

    def get(self, command: str, **params: Any) -> LMResponse:
        """Execute a normal command with keyword parameters."""
        return self.execute(command, params=params if params else None)

    def post(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> LMResponse:
        """Backward-compatible shorthand for an API v1 raw upload."""
        return self.upload_binary(
            command,
            data or b"",
            params=params,
            content_type=content_type,
        )

    def test_connection(self) -> LMResponse:
        """Test connectivity to the LoadMaster."""
        return self.get("listapi")
