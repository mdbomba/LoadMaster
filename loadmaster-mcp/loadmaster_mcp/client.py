"""
LoadMaster API Client

Handles connection, authentication, and XML response parsing for the
Kemp LoadMaster RESTful API.
"""

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


@dataclass
class LMResponse:
    """Parsed LoadMaster API response."""

    status_code: int
    success: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    raw_xml: str = ""

    def to_text(self) -> str:
        """Format response as readable text for MCP tool output."""
        lines = []
        if self.success:
            lines.append(f"Success (code {self.status_code})")
        else:
            lines.append(f"Error (code {self.status_code}): {self.message}")
            return "\n".join(lines)

        if self.message and self.message != "Command successfully executed.":
            lines.append(f"Message: {self.message}")

        if self.data:
            lines.append("")
            lines.extend(_format_data(self.data))

        return "\n".join(lines)


def _format_data(data: Any, indent: int = 0) -> list[str]:
    """Recursively format data dict into readable lines."""
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
    """Recursively parse an XML element into a Python dict/str."""
    # If element has no children, return its text
    children = list(element)
    if not children:
        return (element.text or "").strip()

    # Check if all children have the same tag (list pattern)
    child_tags = [c.tag for c in children]
    if len(set(child_tags)) == 1 and len(child_tags) > 1:
        return [_parse_xml_element(c) for c in children]

    # Otherwise build a dict
    result: dict[str, Any] = {}
    # Include attributes
    for attr_name, attr_val in element.attrib.items():
        result[f"@{attr_name}"] = attr_val

    for child in children:
        child_val = _parse_xml_element(child)
        if child.tag in result:
            # Convert to list if duplicate keys
            existing = result[child.tag]
            if isinstance(existing, list):
                existing.append(child_val)
            else:
                result[child.tag] = [existing, child_val]
        else:
            result[child.tag] = child_val

    return result


def parse_lm_response(raw_xml: str) -> LMResponse:
    """Parse a LoadMaster XML response into an LMResponse object."""
    if not raw_xml.strip():
        return LMResponse(
            status_code=0,
            success=False,
            message="Empty response from LoadMaster",
            raw_xml=raw_xml,
        )

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        return LMResponse(
            status_code=0,
            success=False,
            message=f"Failed to parse XML response: {e}",
            raw_xml=raw_xml,
        )

    # Extract status code from <Response code="..."> or <stat>
    code_str = root.get("code", "")
    if not code_str:
        stat_el = root.find("stat")
        if stat_el is not None and stat_el.text:
            code_str = stat_el.text.strip()

    try:
        status_code = int(code_str) if code_str else 0
    except ValueError:
        status_code = 0

    # Check for error
    error_el = root.find(".//Error")
    if error_el is not None and error_el.text:
        return LMResponse(
            status_code=status_code,
            success=False,
            message=error_el.text.strip(),
            raw_xml=raw_xml,
        )
    if status_code >= 400:
        return LMResponse(
            status_code=status_code,
            success=False,
            message=f"LoadMaster returned API code {status_code}",
            raw_xml=raw_xml,
        )

    # Extract success data
    success_el = root.find(".//Success")
    data = {}
    message = ""

    if success_el is not None:
        data = _parse_xml_element(success_el)
        if isinstance(data, dict):
            message = data.pop("Message", data.pop("message", ""))
            # If Data is nested, flatten it
            if "Data" in data and isinstance(data["Data"], dict):
                data = data["Data"]
            elif "Data" in data:
                data = {"Data": data["Data"]}
    else:
        # Some responses don't wrap in Success
        data = _parse_xml_element(root)
        if isinstance(data, dict):
            message = data.pop("Message", data.pop("message", ""))

    if not message:
        message = "Command successfully executed."

    return LMResponse(
        status_code=status_code,
        success=True,
        message=message,
        data=data if isinstance(data, dict) else {"value": data},
        raw_xml=raw_xml,
    )


def parse_lm_json_response(raw_json: str, status_code: int) -> LMResponse:
    """Parse an APIv2 JSON response into an LMResponse object."""
    try:
        payload = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return LMResponse(
            status_code=status_code,
            success=False,
            message=f"Failed to parse JSON response: {e}",
            raw_xml=raw_json,
        )

    if not isinstance(payload, dict):
        return LMResponse(
            status_code=status_code,
            success=False,
            message="Unexpected JSON response",
            raw_xml=raw_json,
        )

    api_code = payload.get("code", status_code)
    try:
        api_code = int(api_code)
    except (TypeError, ValueError):
        api_code = status_code
    message = str(payload.get("message", payload.get("status", "")))
    success = 200 <= status_code < 300 and 200 <= api_code < 300
    if not success and not message:
        message = f"LoadMaster returned API code {api_code}"
    if success and not message:
        message = "Command successfully executed."
    data = {key: value for key, value in payload.items() if key not in {"code", "message", "status"}}
    return LMResponse(status_code=api_code, success=success, message=message, data=data, raw_xml=raw_json)


class LoadMasterClient:
    """HTTP client for the Kemp LoadMaster REST API."""

    def __init__(
        self,
        host: str,
        port: int = 443,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 30.0,
        use_api_v1: bool = False,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.use_api_v1 = use_api_v1
        self._base_url = f"https://{host}:{port}"

    @property
    def _auth(self) -> Optional[httpx.BasicAuth]:
        """Get basic auth credentials if configured."""
        if self.username and self.password:
            return httpx.BasicAuth(self.username, self.password)
        return None

    def _build_url(self, command: str) -> str:
        """Build an APIv1 endpoint URL. Parameters are passed to HTTPX separately."""
        return f"{self._base_url}/access/{command}"

    @staticmethod
    def _clean_params(params: Optional[dict[str, Any]]) -> dict[str, Any]:
        """Remove unset values and normalize booleans for LoadMaster APIs."""
        return {
            key: ("yes" if value else "no") if isinstance(value, bool) else value
            for key, value in (params or {}).items()
            if value is not None
        }

    def _api_v2_payload(self, command: str, params: Optional[dict[str, Any]]) -> dict[str, Any]:
        payload = {"cmd": command, **self._clean_params(params)}
        if self.api_key:
            payload["apikey"] = self.api_key
        elif self.username and self.password:
            payload["apiuser"] = self.username
            payload["apipass"] = self.password
        return payload

    def _get_headers(self) -> dict[str, str]:
        """Build request headers."""
        headers = {"User-Agent": "LoadMasterMCP/2.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def execute(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        method: str = "GET",
        data: Optional[bytes] = None,
        content_type: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> LMResponse:
        """Execute an API command against the LoadMaster.

        Args:
            command: The API command (e.g., 'showvs', 'addvs', 'set')
            params: Query parameters
            method: HTTP method (GET or POST)
            data: POST body data (for file uploads)
            content_type: Content-Type header for POST requests
            timeout: Override the default request timeout (seconds)

        Returns:
            Parsed LMResponse object
        """
        # Binary endpoints remain APIv1 uploads; all normal management calls use APIv2.
        if not self.use_api_v1 and not (method.upper() == "POST" and data is not None):
            return self._execute_v2(command, params, timeout)

        url = self._build_url(command)
        headers = self._get_headers()
        if content_type:
            headers["Content-Type"] = content_type

        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=effective_timeout,
            ) as client:
                if method.upper() == "POST":
                    response = client.post(
                        url,
                        auth=self._auth,
                        headers=headers,
                        params=self._clean_params(params),
                        content=data,
                    )
                else:
                    response = client.get(
                        url,
                        auth=self._auth,
                        headers=headers,
                        params=self._clean_params(params),
                    )
                if response.is_error:
                    return LMResponse(
                        response.status_code,
                        False,
                        f"HTTP {response.status_code}: {response.text[:500]}",
                        raw_xml=response.text,
                    )
                return parse_lm_response(response.text)

        except httpx.ConnectError as e:
            return LMResponse(
                status_code=0,
                success=False,
                message=f"Connection failed to {self.host}:{self.port}: {e}",
            )
        except httpx.TimeoutException as e:
            return LMResponse(
                status_code=0,
                success=False,
                message=f"Request timed out after {effective_timeout}s: {e}",
            )
        except Exception as e:
            return LMResponse(
                status_code=0,
                success=False,
                message=f"Unexpected error: {e}",
            )

    def _execute_v2(
        self,
        command: str,
        params: Optional[dict[str, Any]],
        timeout: Optional[float],
    ) -> LMResponse:
        """Execute a standard post-license APIv2 JSON request."""
        effective_timeout = timeout if timeout is not None else self.timeout
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=effective_timeout) as client:
                response = client.post(
                    f"{self._base_url}/accessv2",
                    headers={**self._get_headers(), "Content-Type": "application/json"},
                    json=self._api_v2_payload(command, params),
                )
                if response.is_error:
                    return LMResponse(
                        response.status_code,
                        False,
                        f"HTTP {response.status_code}: {response.text[:500]}",
                        raw_xml=response.text,
                    )
                return parse_lm_json_response(response.text, response.status_code)
        except httpx.ConnectError as e:
            return LMResponse(0, False, f"Connection failed to {self.host}:{self.port}: {e}")
        except httpx.TimeoutException as e:
            return LMResponse(0, False, f"Request timed out after {effective_timeout}s: {e}")
        except Exception as e:
            return LMResponse(0, False, f"Unexpected error: {e}")

    def get(self, command: str, **params: Any) -> LMResponse:
        """Shorthand for GET requests."""
        return self.execute(command, params=params if params else None)

    def post(
        self,
        command: str,
        params: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> LMResponse:
        """Shorthand for POST requests (file uploads, etc.)."""
        return self.execute(
            command,
            params=params,
            method="POST",
            data=data,
            content_type=content_type,
        )

    def test_connection(self) -> LMResponse:
        """Test connectivity to the LoadMaster."""
        return self.get("listapi")
