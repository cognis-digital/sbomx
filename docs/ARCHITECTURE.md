# SBOMX — Architecture

> Generates a CycloneDX SBOM for mobile apps by unpacking native libs and bundled SDKs, then matches components against known-vuln and tracker/privacy databases.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `sbomx/core.py`.
- **score** ranks by severity.
- **MCP server** (`sbomx mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
