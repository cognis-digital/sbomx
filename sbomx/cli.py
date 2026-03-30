"""Command-line interface for SBOMX.

Examples
--------
  # Generate a CycloneDX SBOM (JSON) for an APK and write it to a file
  sbomx scan app.apk --format json -o app.cdx.json

  # Human-readable findings table; exit non-zero if vulns/trackers found
  sbomx scan app.ipa --format table

  # Scan an extracted bundle directory and fail CI on HIGH severity vulns
  sbomx scan ./unpacked_app --fail-on high

  # Use a manifest mapping lib->version to refine version-unknown components
  sbomx scan app.apk --manifest versions.json

Exit codes
----------
  0  clean (no findings, or findings below --fail-on threshold)
  1  findings at/above the fail threshold (default: any tracker or vuln)
  2  usage / runtime error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import scan, build_cyclonedx, ScanResult

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_manifest(path: Optional[str]) -> Optional[dict]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("manifest JSON must be an object mapping lib-key -> version")
    return {str(k): str(v) for k, v in data.items()}


def _render_table(result: ScanResult) -> str:
    lines: List[str] = []
    lines.append(f"Target: {result.target}")
    lines.append("")
    lines.append(f"Components ({len(result.components)}):")
    if result.components:
        wname = max(len(c.name) for c in result.components)
        for c in result.components:
            ver = c.version or "?"
            lines.append(f"  {c.name.ljust(wname)}  {ver:<10} {c.ecosystem:<10} {c.purl()}")
    else:
        lines.append("  (none detected)")
    lines.append("")

    vulns = result.vulnerabilities
    lines.append(f"Vulnerabilities ({len(vulns)}):")
    if vulns:
        for f in sorted(vulns, key=lambda x: -_SEV_ORDER.get(x.severity, 0)):
            note = "" if f.version_known else "  [version unknown - potential]"
            ver = f.component_version or "?"
            lines.append(f"  [{f.severity.upper():<8}] {f.id}  {f.component_name}@{ver}{note}")
            lines.append(f"             {f.summary}")
            if f.fixed_version:
                lines.append(f"             fix: upgrade to >= {f.fixed_version}")
    else:
        lines.append("  (none)")
    lines.append("")

    trackers = result.trackers
    lines.append(f"Trackers ({len(trackers)}):")
    if trackers:
        for f in trackers:
            cats = ", ".join(f.extra.get("categories", []))
            lines.append(f"  {f.id}  ({cats})")
    else:
        lines.append("  (none)")
    return "\n".join(lines)


def _max_severity(result: ScanResult) -> int:
    sev = 0
    for f in result.findings:
        sev = max(sev, _SEV_ORDER.get(f.severity, 0))
    return sev


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate a CycloneDX SBOM for mobile apps and match bundled "
                    "libraries against vulnerability and privacy-tracker databases.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    sc = sub.add_parser(
        "scan",
        help="scan an .apk/.ipa/zip or directory and produce an SBOM + findings",
        description="Scan a mobile app bundle or directory for bundled libraries, "
                    "vulnerabilities and trackers.",
    )
    sc.add_argument("target", help="path to .apk/.ipa/zip file or an extracted directory")
    sc.add_argument("--format", choices=["table", "json"], default="table",
                    help="output format (default: table). 'json' emits a CycloneDX 1.5 SBOM")
    sc.add_argument("-o", "--output", help="write output to this file instead of stdout")
    sc.add_argument("--manifest", help="JSON file mapping library key -> known version")
    sc.add_argument("--fail-on", choices=["never", "info", "low", "medium", "high", "critical"],
                    default="info",
                    help="exit non-zero when a finding at/above this severity exists "
                         "(default: info = any finding). Use 'never' to always exit 0")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        manifest = _load_manifest(args.manifest)
        result = scan(args.target, manifest)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        bom = build_cyclonedx(result, TOOL_NAME, TOOL_VERSION)
        output = json.dumps(bom, indent=2)
    else:
        output = _render_table(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"wrote {args.format} output to {args.output}", file=sys.stderr)
    else:
        print(output)

    if args.fail_on == "never":
        return 0
    threshold = _SEV_ORDER[args.fail_on]
    if result.findings and _max_severity(result) >= threshold:
        return 1
    return 0
