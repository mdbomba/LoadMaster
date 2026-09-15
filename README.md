# LoadMaster API Management Project

This project provides comprehensive documentation, automation scripts, and an AI-powered MCP server for managing Kemp LoadMaster appliances via their REST API.

Repository note:
- This repository is now named `LoadMaster` (renamed from `markdown`).

## What's Included

| Directory | Contents |
|-----------|----------|
| `loadmaster-markdown/` | 364 per-endpoint API reference docs with APIv1 and APIv2 examples |
| `loadmaster-documents/` | Knowledge base, workflows, error codes, troubleshooting, STIG tech note |
| `loadmaster-sample-scripts/` | Bash scripts (licensing, VS deployment, STIG hardening, monitoring), PowerShell SDK, parameter reference |
| `loadmaster-mcp/` | MCP server for AI-assisted LoadMaster management (156 tools) |

## Dual MCP Demo Runbook (Local Workspace)

If you are running both MCP servers from the parent workspace (`/home/chef/repos`), use:

- `../MCP_DEMO_RUNBOOK.md`

This runbook includes quick validation prompts for both:

1. `loadmaster` (Python MCP server in this repository)
2. `whatsup-gold-corpus` (Node.js MCP server in the sibling `WhatsUp_Gold` repository)

## Quick MCP Start (VS Code + Copilot)

From the parent workspace (`/home/chef/repos`):

1. Open `/home/chef/repos` in VS Code
2. Reload window (`Developer: Reload Window`)
3. Ensure both servers are configured in `/home/chef/repos/.vscode/mcp.json`
4. In Copilot Chat, run `Test the LoadMaster connection and show connection info.` then `Get parameter hamode.`

## Built With OpenCode

This project was built entirely using [OpenCode](https://opencode.ai) — an open source AI coding agent that runs in the terminal. OpenCode connected to the LoadMaster MCP server to license, configure, harden, and document the appliance in real-time.

### What is OpenCode?

OpenCode is a terminal-based AI coding assistant that supports 75+ LLM providers and can be extended with MCP (Model Context Protocol) servers to interact with external systems like the LoadMaster.

- **Website**: https://opencode.ai
- **GitHub**: https://github.com/anomalyco/opencode
- **Documentation**: https://opencode.ai/docs
- **Discord**: https://opencode.ai/discord

### Install OpenCode

```bash
# Easiest method (Linux/macOS)
curl -fsSL https://opencode.ai/install | bash

# Or via npm
npm install -g opencode-ai

# Or via Homebrew (macOS/Linux)
brew install anomalyco/tap/opencode

# Or via Chocolatey (Windows)
choco install opencode
```

Full installation docs: https://opencode.ai/docs/#install

### Using OpenCode for Free (No Token Cost)

OpenCode supports several options that cost nothing for AI tokens:

#### Option 1: GitHub Copilot (Included with GitHub Pro/Teams/Enterprise)

If you already have a GitHub Copilot subscription, you can use it with OpenCode at no additional cost:

```
/connect
```
Select **GitHub Copilot**, then authenticate via browser. Models like Claude Sonnet and GPT are available through your existing subscription.

#### Option 2: Free Models via OpenCode Zen

OpenCode Zen offers several free models (available for a limited time):

- **DeepSeek V4 Flash Free**
- **MiMo-V2.5 Free**
- **Nemotron 3 Ultra Free**
- **North Mini Code Free**
- **Big Pickle** (stealth model)

To use them:
1. Run `/connect` in OpenCode, select **OpenCode Zen**
2. Sign in at https://opencode.ai/auth and get an API key (billing info required but free models cost $0)
3. Run `/models` and select a free model

#### Option 3: Local Models (Ollama)

Run models locally with zero cost using [Ollama](https://ollama.com):

```json
// opencode.json
{
  "provider": {
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Ollama (local)",
      "options": { "baseURL": "http://localhost:11434/v1" },
      "models": {
        "qwen3-coder:30b": { "name": "Qwen3 Coder 30B" }
      }
    }
  }
}
```

### Configure OpenCode for This Project

After installing OpenCode, configure the LoadMaster MCP server:

```json
// opencode.json (in project root)
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "loadmaster": {
      "type": "local",
      "command": ["./loadmaster-mcp/.venv/bin/python", "-m", "loadmaster_mcp.server"],
      "enabled": true
    }
  }
}
```

Then set up the MCP server:

```bash
cd loadmaster-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env   # Edit with your LoadMaster IP and credentials
```

Now run `opencode` in the project root and you can manage your LoadMaster with natural language.

## What Can You Do With This?

With OpenCode + the LoadMaster MCP server, you can:

- License a fresh LoadMaster (EULA acceptance, online activation)
- Apply STIG security hardening (FIPS ciphers, session management, warning banners)
- Configure networking (interfaces, DNS, NTP, routes)
- Deploy application templates (Exchange 2019, Citrix, etc.)
- Create virtual services with content switching and real servers
- Manage certificates, WAF rules, SSO domains, VPN connections
- Query real-time statistics and health status

All through natural language conversation in your terminal.

## Test VM Defaults

For a test LoadMaster whose target management IPv4 address ends in `N`, use
libvirt VM name `N_vlmN` and appliance hostname `vlmN`. Create test appliances
from fresh vendor installation media only, never by cloning an existing
LoadMaster. The default test deployment uses 2 vCPUs, 2 GiB RAM, and two NICs.
Live project testing uses a fresh vendor Free LoadMaster image, never an
existing paid, trial, or production appliance.

An explicit request for a non-Free image overrides this default. Non-Free
images use the same Progress account credentials, but require a `trial` or
`paid` choice before building. The `trial` flow needs no Order ID. The `paid`
flow requires a valid Progress Order ID and stops before licensing when none is
provided.

The test-only initial `bal` password is `Kemp1fourall`. Change it as soon as
possible after the appliance is licensed; do not use it for non-test systems.
For a deployment that is not explicitly a test, the operator must supply a new
`bal` password before licensing begins, regardless of image or license type.

A test build is complete only after a locally signed management-WUI TLS
certificate has been generated, installed as `admincert`, and verified. The
certificate must cover `vlmN.demo.lab`, `vlmN`, `10.0.0.N`, and `10.1.0.N` for a
test appliance whose management address ends in `N`.

See `loadmaster-documents/TEST-LOADMASTER-RUNBOOK.md` for the validated
fresh-media KVM deployment, Free licensing, management-interface TLS
certificate workflow, and local source locations.

## License

This project is provided as-is for educational and operational use with Kemp LoadMaster appliances.
