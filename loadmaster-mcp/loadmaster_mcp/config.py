"""
LoadMaster MCP Configuration

Loads connection settings from environment variables or a .env file.
"""

import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from .client import LoadMasterClient


# Load .env from multiple potential locations. The first file that exists
# wins; real environment variables already set always take precedence over
# anything in these files.
_ENV_SEARCH_PATHS = [
    Path.cwd() / ".env",
    Path(__file__).resolve().parent.parent.parent / ".env",  # markdown/
    Path(__file__).resolve().parent.parent.parent.parent / ".env",  # project root
    Path.home() / ".config" / "loadmaster" / ".env",
    Path.home() / ".secrets" / "loadmaster.env",
]


def _load_params_file() -> None:
    """Load the temp snapshot, then overlay non-empty ~/.secrets values.

    The params file uses shell-style KEY='value' lines and shares its
    credential names with license.params, so a single file can configure
    both the sample scripts and the MCP server. Existing environment
    variables are never overwritten; blank secret placeholders do not erase
    values gathered by the build wizard into the temp snapshot.
    """
    temp_path = Path(
        os.environ.get(
            "LM_PROJECT_PARAMS_FILE",
            Path.home() / "repos" / ".tmp" / "LoadMaster" / "loadmaster.params",
        )
    ).expanduser()
    secrets_path = Path(
        os.environ.get("LM_PARAMS_FILE", Path.home() / ".secrets" / "loadmaster.params")
    ).expanduser()

    # Secrets refresh the cached project values. Temp values are the fallback
    # when a secret key is absent/blank; explicit process env remains highest.
    for params_path in (secrets_path, temp_path):
        if not params_path.exists():
            continue
        for raw_line in params_path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not key or key in os.environ:
                continue
            try:
                words = shlex.split(raw_value, comments=True, posix=True)
            except ValueError:
                continue
            value = words[0] if words else ""
            if value:
                os.environ[key] = value


_load_params_file()

for env_path in _ENV_SEARCH_PATHS:
    if env_path.exists():
        load_dotenv(env_path, override=False)


@dataclass
class LMConfig:
    """LoadMaster connection configuration."""

    host: str
    port: int = 443
    username: str = "bal"
    password: str = ""
    api_key: str = ""
    verify_ssl: bool = False
    timeout: float = 30.0
    vm_name: str = ""

    @classmethod
    def from_env(cls) -> "LMConfig":
        """Load configuration from environment variables.

        Environment variables:
            LM_HOST: LoadMaster IP or hostname (required)
            LM_PORT: API port (default: 443)
            LM_USERNAME: API username (default: bal)
            LM_PASSWORD: API password
            LM_API_KEY: API key (alternative to username/password)
            LM_VERIFY_SSL: Verify SSL certificates (default: false)
            LM_TIMEOUT: Request timeout in seconds (default: 30)
            LM_VM_NAME: libvirt VM name for IP discovery (optional)

        Also reads ~/.secrets/loadmaster.params, or the path in
        LM_PARAMS_FILE, for credentials shared with the sample scripts.
        """
        host = os.environ.get("LM_HOST", "")
        if not host:
            # Try loading from api key file
            api_key_file = Path(__file__).resolve().parent.parent.parent.parent / "loadmaster_apikey"
            api_key = ""
            if api_key_file.exists():
                api_key = api_key_file.read_text().strip()

            return cls(
                host="",
                api_key=api_key,
            )

        return cls(
            host=host,
            port=int(os.environ.get("LM_PORT", "443")),
            username=os.environ.get("LM_USERNAME", "bal"),
            password=os.environ.get("LM_PASSWORD", ""),
            api_key=os.environ.get("LM_API_KEY", ""),
            verify_ssl=os.environ.get("LM_VERIFY_SSL", "false").lower() in ("true", "1", "yes"),
            timeout=float(os.environ.get("LM_TIMEOUT", "30")),
            vm_name=os.environ.get("LM_VM_NAME", ""),
        )

    @property
    def is_configured(self) -> bool:
        """Check if minimum connection details are available."""
        return bool(self.host)

    @property
    def has_credentials(self) -> bool:
        """Check if authentication credentials are configured."""
        return bool(self.api_key) or bool(self.username and self.password)


def get_client() -> Optional[LoadMasterClient]:
    """Get a configured LoadMaster client, or None if not configured.

    Returns None with a helpful message if LM_HOST is not set.
    """
    config = LMConfig.from_env()
    if not config.is_configured:
        return None

    return LoadMasterClient(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
        api_key=config.api_key,
        verify_ssl=config.verify_ssl,
        timeout=config.timeout,
    )


def require_client() -> LoadMasterClient:
    """Get a configured client, raising an error if not configured."""
    client = get_client()
    if client is None:
        raise ConnectionError(
            "LoadMaster not configured. Set environment variables:\n"
            "  LM_HOST=<loadmaster-ip>\n"
            "  LM_PORT=443  (optional, default 443)\n"
            "  LM_USERNAME=bal\n"
            "  LM_PASSWORD=<password>\n"
            "Or:\n"
            "  LM_API_KEY=<api-key>\n"
            "\n"
            "You can set these in a .env file in the project root."
        )
    return client


# Connection status helper for tools
def connection_status() -> str:
    """Return a human-readable connection status string."""
    config = LMConfig.from_env()
    if not config.is_configured:
        return (
            "NOT CONFIGURED - Set LM_HOST environment variable.\n"
            "Required: LM_HOST, LM_PASSWORD (or LM_API_KEY)\n"
            "Optional: LM_PORT (443), LM_USERNAME (bal), LM_VERIFY_SSL (false), LM_TIMEOUT (30)"
        )

    auth_method = "API Key" if config.api_key else f"Basic Auth ({config.username})"
    vm_line = f"\nVM Name: {config.vm_name}" if config.vm_name else ""
    return (
        f"Host: {config.host}:{config.port}\n"
        f"Auth: {auth_method}\n"
        f"SSL Verify: {config.verify_ssl}\n"
        f"Timeout: {config.timeout}s"
        f"{vm_line}"
    )
