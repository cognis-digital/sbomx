"""SBOMX MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from sbomx.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-sbomx[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-sbomx[mcp]'")
        return 1
    app = FastMCP("sbomx")

    @app.tool()
    def sbomx_scan(target: str) -> str:
        """Generates a CycloneDX SBOM for mobile apps by unpacking native libs and bundled SDKs, then matches components against known-vuln and tracker/privacy databases.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
