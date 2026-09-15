"""
Kemp LoadMaster MCP Server

Provides tools for:
  - Searching and retrieving LoadMaster REST API documentation
  - Live querying and configuration of LoadMaster appliances
  - Managing virtual services, real servers, certificates, rules, etc.

Content priority: loadmaster-markdown > loadmaster-documents

Configuration:
  Set environment variables to connect to a LoadMaster:
    LM_HOST=<loadmaster-ip>
    LM_PORT=443
    LM_USERNAME=bal
    LM_PASSWORD=<password>
  Or use an API key:
    LM_API_KEY=<key>
"""

import os
import re
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# ── Paths ──────────────────────────────────────────────────────────────────────

_SERVER_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SERVER_DIR.parent.parent  # …/markdown/
_BUNDLED_RESOURCES = _SERVER_DIR / "resources"


def _resource_directory(name: str) -> Path:
    """Use repository resources during development and wheel resources when installed."""
    project_resource = _PROJECT_ROOT / name
    if project_resource.exists():
        return project_resource
    return _BUNDLED_RESOURCES / name

# Primary source (higher priority)
MARKDOWN_DIR = _resource_directory("loadmaster-markdown")
# Secondary source
DOCUMENTS_DIR = _resource_directory("loadmaster-documents")
# Sample scripts (supplemental)
SCRIPTS_DIR = _resource_directory("loadmaster-sample-scripts")

# ── Index construction ─────────────────────────────────────────────────────────

_docs_index: dict[str, dict] = {}  # slug -> {path, category, title, priority}


def _index_directory(base_dir: Path, priority: int) -> None:
    """Walk a directory tree and index all .md files."""
    if not base_dir.exists():
        return
    for md_file in sorted(base_dir.rglob("*.md")):
        rel = md_file.relative_to(base_dir)
        slug = str(rel.with_suffix(""))  # e.g. "certificates/access-addcert"
        # Only overwrite if this source has higher priority (lower number = higher)
        if slug not in _docs_index or priority < _docs_index[slug]["priority"]:
            # Derive a title from first heading or filename
            title = _extract_title(md_file)
            category = rel.parts[0] if len(rel.parts) > 1 else "general"
            _docs_index[slug] = {
                "path": md_file,
                "category": category,
                "title": title,
                "priority": priority,
            }


def _extract_title(md_file: Path) -> str:
    """Extract the first markdown heading from a file, or use the filename."""
    try:
        with open(md_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    return line.lstrip("#").strip()
    except OSError:
        pass
    return md_file.stem


def _build_index() -> None:
    """Build the full document index with priority ordering."""
    _docs_index.clear()
    _index_directory(MARKDOWN_DIR, priority=1)   # highest priority
    _index_directory(DOCUMENTS_DIR, priority=2)  # secondary


_build_index()

# ── Helpers ────────────────────────────────────────────────────────────────────


def _read_file(path: Path) -> str:
    """Read a file and return its content."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"Error reading file: {e}"


def _search_content(query: str, max_results: int = 20) -> list[dict]:
    """Search all indexed docs for a query string (case-insensitive)."""
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    results = []
    for slug, info in _docs_index.items():
        content = _read_file(info["path"])
        matches = pattern.findall(content)
        if matches:
            # Find first matching line for context
            context_lines = []
            for line in content.splitlines():
                if pattern.search(line):
                    context_lines.append(line.strip())
                    if len(context_lines) >= 3:
                        break
            results.append({
                "slug": slug,
                "title": info["title"],
                "category": info["category"],
                "match_count": len(matches),
                "context": context_lines,
            })
    # Sort by match count descending
    results.sort(key=lambda r: r["match_count"], reverse=True)
    return results[:max_results]


# ── MCP Server ─────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "LoadMaster",
    instructions=(
        "Kemp LoadMaster management server. Provides documentation search, "
        "live querying, and full configuration management of LoadMaster appliances. "
        "Use documentation tools (list_categories, search_docs, get_document) to "
        "understand the API, and lm_* tools to interact with a live LoadMaster. "
        "Always verify the current state before making changes."
    ),
)


@mcp.tool()
def list_categories() -> str:
    """List all available documentation categories and the number of docs in each."""
    categories: dict[str, int] = {}
    for info in _docs_index.values():
        cat = info["category"]
        categories[cat] = categories.get(cat, 0) + 1
    lines = ["# LoadMaster API Documentation Categories\n"]
    for cat in sorted(categories.keys()):
        lines.append(f"- **{cat}** ({categories[cat]} docs)")
    lines.append(f"\nTotal: {len(_docs_index)} documents indexed")
    return "\n".join(lines)


@mcp.tool()
def list_docs_in_category(category: str) -> str:
    """List all documents in a specific category.

    Args:
        category: The category name (e.g. 'certificates', 'virtual-services', 'system')
    """
    docs = [
        (slug, info)
        for slug, info in _docs_index.items()
        if info["category"] == category
    ]
    if not docs:
        available = sorted(set(i["category"] for i in _docs_index.values()))
        return (
            f"No documents found in category '{category}'.\n"
            f"Available categories: {', '.join(available)}"
        )
    docs.sort(key=lambda d: d[0])
    lines = [f"# Documents in '{category}'\n"]
    for slug, info in docs:
        lines.append(f"- **{info['title']}** — `{slug}`")
    return "\n".join(lines)


@mcp.tool()
def get_document(slug: str) -> str:
    """Retrieve the full content of a specific documentation file by its slug.

    Args:
        slug: The document identifier (e.g. 'certificates/access-addcert',
              'system/access-get', 'licensing/access-readeula')
    """
    info = _docs_index.get(slug)
    if not info:
        # Try partial match
        candidates = [s for s in _docs_index if slug in s]
        if candidates:
            suggestions = "\n".join(f"  - {c}" for c in candidates[:10])
            return f"Document '{slug}' not found. Did you mean:\n{suggestions}"
        return f"Document '{slug}' not found. Use list_categories() to browse available docs."
    return _read_file(info["path"])


@mcp.tool()
def search_docs(query: str, max_results: int = 20) -> str:
    """Search across all LoadMaster documentation for a keyword or phrase.

    Args:
        query: The search term (case-insensitive)
        max_results: Maximum number of results to return (default 20)
    """
    if not query.strip():
        return "Please provide a non-empty search query."
    results = _search_content(query, max_results)
    if not results:
        return f"No results found for '{query}'."
    lines = [f"# Search results for '{query}' ({len(results)} matches)\n"]
    for r in results:
        lines.append(f"## {r['title']} (`{r['slug']}`)")
        lines.append(f"Category: {r['category']} | Matches: {r['match_count']}")
        for ctx in r["context"]:
            lines.append(f"> {ctx}")
        lines.append("")
    return "\n".join(lines)


@mcp.tool()
def get_api_parameter(param_name: str) -> str:
    """Look up a specific LoadMaster API parameter by name.

    Searches the params-reference file and relevant documentation.

    Args:
        param_name: The parameter name (e.g. 'ntphost', 'sessioncontrol', 'WUITLSProtocols')
    """
    # Check params-reference.md first
    params_file = SCRIPTS_DIR / "params-reference.md"
    result_lines = []
    if params_file.exists():
        content = _read_file(params_file)
        pattern = re.compile(
            rf"^\|[^|]*{re.escape(param_name)}[^|]*\|",
            re.IGNORECASE | re.MULTILINE,
        )
        matches = pattern.findall(content)
        if matches:
            result_lines.append("# Parameter Reference\n")
            # Include table header
            header_match = re.search(r"^\| Parameter.*\|$\n\|[-| ]+\|$", content, re.MULTILINE)
            if header_match:
                result_lines.append(header_match.group())
            for m in matches:
                result_lines.append(m)
            result_lines.append("")

    # Also search docs for usage context
    doc_results = _search_content(param_name, max_results=5)
    if doc_results:
        result_lines.append("# Related Documentation\n")
        for r in doc_results:
            result_lines.append(f"- **{r['title']}** (`{r['slug']}`) — {r['match_count']} references")

    if not result_lines:
        return f"No information found for parameter '{param_name}'."
    return "\n".join(result_lines)


@mcp.tool()
def get_sample_script(script_name: str) -> str:
    """Retrieve a sample script from the loadmaster-sample-scripts collection.

    Args:
        script_name: The script filename (e.g. 'run_license.sh', '_common.sh',
                     'LM-STIG-Script_v3.ps1', 'licensing/access-readeula.sh')
    """
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        # List available scripts
        available = []
        if SCRIPTS_DIR.exists():
            for f in sorted(SCRIPTS_DIR.rglob("*")):
                if f.is_file() and not f.name.startswith("."):
                    available.append(str(f.relative_to(SCRIPTS_DIR)))
        suggestions = "\n".join(f"  - {a}" for a in available[:20])
        return f"Script '{script_name}' not found. Available scripts:\n{suggestions}"
    return _read_file(script_path)


@mcp.tool()
def list_sample_scripts() -> str:
    """List all available sample scripts in the loadmaster-sample-scripts collection."""
    if not SCRIPTS_DIR.exists():
        return "Sample scripts directory not found."
    scripts = []
    for f in sorted(SCRIPTS_DIR.rglob("*")):
        if f.is_file() and not f.name.startswith("."):
            rel = str(f.relative_to(SCRIPTS_DIR))
            size = f.stat().st_size
            scripts.append(f"- `{rel}` ({size} bytes)")
    if not scripts:
        return "No sample scripts found."
    lines = ["# LoadMaster Sample Scripts\n"] + scripts
    return "\n".join(lines)


# ── Entry point ────────────────────────────────────────────────────────────────

# Register all live LoadMaster management tools
from .tools import register as register_query_tools
from .tools.system import register as register_system_tools
from .tools.virtual_services import register as register_vs_tools
from .tools.real_servers import register as register_rs_tools
from .tools.certificates import register as register_cert_tools
from .tools.rules import register as register_rules_tools
from .tools.network import register as register_network_tools
from .tools.ha import register as register_ha_tools
from .tools.geo import register as register_geo_tools
from .tools.sso import register as register_sso_tools
from .tools.waf import register as register_waf_tools
from .tools.vpn import register as register_vpn_tools
from .tools.licensing import register as register_licensing_tools
from .tools.users import register as register_users_tools

register_query_tools(mcp)
register_system_tools(mcp)
register_vs_tools(mcp)
register_rs_tools(mcp)
register_cert_tools(mcp)
register_rules_tools(mcp)
register_network_tools(mcp)
register_ha_tools(mcp)
register_geo_tools(mcp)
register_sso_tools(mcp)
register_waf_tools(mcp)
register_vpn_tools(mcp)
register_licensing_tools(mcp)
register_users_tools(mcp)


def main():
    """Run the MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
