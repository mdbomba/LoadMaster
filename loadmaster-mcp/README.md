# LoadMaster MCP Server

An MCP (Model Context Protocol) server that provides AI assistants with full management capabilities for Kemp LoadMaster appliances:

- **Documentation search** - Browse and search the complete LoadMaster REST API reference
- **Live querying** - Query the current state of a LoadMaster (VS, RS, parameters, stats)
- **Configuration management** - Create, modify, and delete virtual services, real servers, certificates, rules, and more

## Installation

### Prerequisites

- Python 3.10 or newer
- A licensed Kemp LoadMaster appliance (physical, virtual, or cloud)
- Network connectivity to the LoadMaster management interface

### Step 1: Clone the Repository

```bash
git clone https://github.com/mdbomba/LoadMaster.git
cd LoadMaster/loadmaster-mcp
```

### Step 2: Create Virtual Environment and Install

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install -e .
```

### Step 3: Configure LoadMaster Connection

```bash
cp .env.example .env
```

Edit `.env` with your LoadMaster details:

```bash
LM_HOST=10.0.0.14              # Your LoadMaster IP
LM_PORT=443                     # API port (default: 443)
LM_USERNAME=bal                 # API username (default: bal)
LM_PASSWORD=your-password       # API password
LM_VERIFY_SSL=false             # Set true if using valid TLS cert
LM_TIMEOUT=30                   # Request timeout in seconds
```

Alternatively, use an API key instead of username/password:
```bash
LM_API_KEY=your-api-key-here
```

### Step 4: Enable the MCP Server in Your AI Tool

#### OpenCode

Add to your `opencode.json` (or `~/.config/opencode/config.json`):

```json
{
  "mcp": {
    "loadmaster": {
      "type": "local",
      "command": ["/full/path/to/LoadMaster/loadmaster-mcp/.venv/bin/python", "-m", "loadmaster_mcp.server"],
      "enabled": true
    }
  }
}
```

#### Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "loadmaster": {
      "command": "/full/path/to/LoadMaster/loadmaster-mcp/.venv/bin/python",
      "args": ["-m", "loadmaster_mcp.server"],
      "env": {
        "LM_HOST": "10.0.0.14",
        "LM_PASSWORD": "your-password"
      }
    }
  }
}
```

#### Cursor / VS Code with Continue

Add to your MCP configuration:

```json
{
  "loadmaster": {
    "command": "/full/path/to/LoadMaster/loadmaster-mcp/.venv/bin/python",
    "args": ["-m", "loadmaster_mcp.server"]
  }
}
```

### Step 5: Verify Connection

Once your AI tool is configured and restarted, ask it to test the connection:

> "Test the LoadMaster connection and show me the license info"

The MCP server will attempt to reach your LoadMaster and return its status.

### Run Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite uses mocked HTTP clients only. Run a separate validation against a
non-production LoadMaster before deploying configuration changes to production.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LM_HOST` | Yes | - | LoadMaster IP or hostname |
| `LM_PORT` | No | 443 | API port |
| `LM_USERNAME` | No | bal | API username |
| `LM_PASSWORD` | Yes* | - | API password |
| `LM_API_KEY` | Yes* | - | API key (alternative to user/pass) |
| `LM_VERIFY_SSL` | No | false | Verify SSL certificates |
| `LM_TIMEOUT` | No | 30 | Request timeout (seconds) |

*One of `LM_PASSWORD` or `LM_API_KEY` is required for live tools.

The `.env` file is searched in: current directory, `loadmaster-mcp/`, project root, or `~/.config/loadmaster/`.

## API Interface Notes

The MCP server communicates with the LoadMaster using both API interfaces:

- **APIv2** (default) — JSON POST to `/accessv2` for all standard post-license queries and configuration. No URL size limits.
- **APIv1** (restricted fallback) — used for pre-license operations and binary uploads.

See `loadmaster-documents/loadmaster_api_knowledge.md` for full API architecture documentation.

## Available Tools (156 live management tools + 323 documented API endpoints)

The MCP server provides two types of capabilities. Documentation and sample resources are bundled into installed wheels and are also read directly from the repository during editable development:

1. **Live management tools** (156) — Direct actions on a connected LoadMaster (create VS, add RS, set parameters, etc.)
2. **Documentation search** — Access to 323 per-endpoint API reference docs that the AI can consult for parameter details, examples, and behavior notes

### Documentation Tools (7)

| Tool | Description |
|------|-------------|
| `list_categories` | List all documentation categories and doc counts |
| `list_docs_in_category` | List all documents in a specific category |
| `get_document` | Retrieve full content of a document by slug |
| `search_docs` | Full-text search across all documentation |
| `get_api_parameter` | Look up a specific API parameter by name |
| `get_sample_script` | Retrieve a sample script by filename |
| `list_sample_scripts` | List all available sample scripts |

### Connection & Query Tools (8)

| Tool | Description |
|------|-------------|
| `lm_test_connection` | Test connectivity to the LoadMaster |
| `lm_connection_info` | Show current connection configuration |
| `lm_get_parameter` | Get a single parameter value |
| `lm_get_all_parameters` | Get all parameters at once |
| `lm_list_virtual_services` | List all virtual services |
| `lm_show_virtual_service` | Get detailed VS configuration |
| `lm_show_real_server` | Get RS configuration |
| `lm_list_api` | List all API commands |

### System Management (13)

| Tool | Description |
|------|-------------|
| `lm_set_parameter` | Set any system parameter |
| `lm_reboot` | Reboot the LoadMaster |
| `lm_shutdown` | Shutdown the LoadMaster |
| `lm_backup` | Create configuration backup |
| `lm_restore` | Restore from backup |
| `lm_get_datetime` | Get date/time config |
| `lm_get_firmware_version` | Get firmware versions |
| `lm_install_patch` | Install firmware patch |
| `lm_rollback_patch` | Rollback firmware |
| `lm_install_addon` | Install add-on package |
| `lm_list_addons` | List installed add-ons |
| `lm_remove_addon` | Remove an add-on |
| `lm_get_statistics` | Get system statistics |

### Virtual Services (4)

| Tool | Description |
|------|-------------|
| `lm_add_virtual_service` | Create a new VS |
| `lm_modify_virtual_service` | Modify VS settings |
| `lm_delete_virtual_service` | Delete a VS |
| `lm_export_vs_template` | Export VS as template |

### Real Servers (5)

| Tool | Description |
|------|-------------|
| `lm_add_real_server` | Add RS to a VS |
| `lm_modify_real_server` | Modify RS settings |
| `lm_delete_real_server` | Remove RS from VS |
| `lm_enable_real_server` | Enable RS (bring into rotation) |
| `lm_disable_real_server` | Disable RS (take out of rotation) |

### Certificates (11)

| Tool | Description |
|------|-------------|
| `lm_list_certificates` | List all certificates |
| `lm_get_certificate` | Get certificate details |
| `lm_add_certificate` | Upload/install certificate |
| `lm_delete_certificate` | Delete certificate |
| `lm_add_intermediate_certificate` | Add intermediate CA cert |
| `lm_backup_certificates` | Backup all certificates |
| `lm_get_cipher_set` | Get cipher configuration |
| `lm_set_cipher_set` | Configure cipher set |
| `lm_list_le_certificates` | List Let's Encrypt / ACME certs |
| `lm_request_le_certificate` | Request LE / ACME certificate |
| `lm_renew_le_certificate` | Renew LE / ACME certificate |

> **ACME documentation (7.2.61+):** 14 new ACME endpoint docs are available via
> `get_document` (e.g., `certificates/access-addacmecert`). These replace the legacy
> Let's Encrypt commands and add DigiCert support.

### Content Rules (6)

| Tool | Description |
|------|-------------|
| `lm_list_rules` | List all content rules |
| `lm_get_rule` | Get rule details |
| `lm_add_rule` | Create content rule |
| `lm_modify_rule` | Modify content rule |
| `lm_delete_rule` | Delete content rule |
| `lm_assign_rule_to_vs` | Assign rule to VS |
| `lm_remove_rule_from_vs` | Remove rule from VS |

### Network (20)

Interfaces, routes, VLANs, VxLANs, bonds, DNS, hosts, SNMP management.

### High Availability (6)

HA mode, failover, Azure/AWS HA configuration.

### GEO/GSLB (17)

FQDN management, clusters, site mappings, custom locations, IP ranges, statistics.

### SSO & LDAP (10)

SSO domain CRUD, locked users, LDAP endpoint management.

### WAF (11)

Rule management, auto-update, custom rulesets, enable/disable per VS, OWASP rule management.

### VPN (8)

IPsec VPN connection CRUD, start/stop connections.

### Licensing (9)

EULA workflow, online/on-premise licensing, initial setup.

### Users & Security (11)

User CRUD, remote groups, API keys, WUI security settings.

### Documentation Coverage (323 API endpoints)

The MCP server's documentation tools (`get_document`, `search_docs`, `list_docs_in_category`)
provide access to per-endpoint reference docs covering all LoadMaster API commands. Key areas
documented beyond the live tools include:

| Area | Endpoints | Firmware |
|------|-----------|----------|
| ACME Certificates (Let's Encrypt + DigiCert) | 14 | 7.2.61+ |
| Kubernetes Ingress Controller | 10 | 7.2.61+ |
| OWASP Rule Management | 1 | 7.2.61+ |
| VS Duplication (`dupvs`) | 1 | 7.2.61+ |
| Reserved Ports | 2 | 7.2.61+ |
| GEO/GSLB (FQDN, clusters, DNSSEC, ACLs) | 65 | All |
| Rate Limiting / QoS | 20 | All |
| Diagnostics (ping, traceroute, tcpdump) | 14 | All |
| Access Lists (global + per-VS) | 10 | All |

Use `search_docs("kubernetes ingress")` or `get_document("virtual-services/access-dupvs")`
to access these docs.

## Content Priority (Documentation)

1. `loadmaster-markdown/` - Primary API reference (per-endpoint markdown files)
2. `loadmaster-documents/` - Supplemental documentation (tech notes, guides)
3. `loadmaster-sample-scripts/` - Sample scripts (bash, PowerShell)

## Document Slugs

Documents are identified by slug: `category/filename` (without `.md`).
Examples:
- `certificates/access-addcert`
- `system/access-get`
- `virtual-services/access-addvs`

Use `list_categories()` and `list_docs_in_category(category)` to discover slugs.

## Architecture

```
loadmaster_mcp/
├── __init__.py
├── server.py          # MCP server entry point + documentation tools
├── client.py          # HTTP client for LoadMaster REST API
├── config.py          # Configuration/env loading
└── tools/
    ├── __init__.py    # Live query tools (connection, get, list, show)
    ├── system.py      # System management (set, reboot, backup, etc.)
    ├── virtual_services.py  # VS CRUD
    ├── real_servers.py      # RS CRUD
    ├── certificates.py      # Certificate management
    ├── rules.py             # Content rules (L7)
    ├── network.py           # Interfaces, routes, VLANs, DNS
    ├── ha.py                # High Availability
    ├── geo.py               # GEO/GSLB
    ├── sso.py               # SSO domains & LDAP
    ├── waf.py               # Web Application Firewall
    ├── vpn.py               # IPsec VPN
    ├── licensing.py         # EULA & licensing
    └── users.py             # Users & security
```
