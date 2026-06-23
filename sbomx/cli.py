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
from . import feeds as feeds_mod
from .core import (
    scan, build_cyclonedx, build_sarif, build_csv, ScanResult,
    enrich_with_osv,
)

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
            kev = "  *** CISA KNOWN-EXPLOITED ***" if f.extra.get("kev") else ""
            ver = f.component_version or "?"
            lines.append(f"  [{f.severity.upper():<8}] {f.id}  {f.component_name}@{ver}{note}{kev}")
            lines.append(f"             {f.summary}")
            if f.extra.get("kev"):
                lines.append(f"             KEV: added {f.extra.get('kev_date_added','?')}"
                             f"  patch-by {f.extra.get('kev_due_date','?')}"
                             f"  ransomware={f.extra.get('kev_ransomware','Unknown')}")
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
    sc.add_argument("--format", choices=["table", "json", "sarif", "csv"], default="table",
                    help="output format (default: table). 'json' emits a CycloneDX 1.5 SBOM; "
                         "'sarif' emits a SARIF 2.1.0 log (GitHub code-scanning); "
                         "'csv' emits one row per finding")
    sc.add_argument("-o", "--output", help="write output to this file instead of stdout")
    sc.add_argument("--manifest", help="JSON file mapping library key -> known version")
    sc.add_argument("--fail-on", choices=["never", "info", "low", "medium", "high", "critical"],
                    default="info",
                    help="exit non-zero when a finding at/above this severity exists "
                         "(default: info = any finding). Use 'never' to always exit 0")
    sc.add_argument("--enrich-kev", action="store_true",
                    help="cross-reference each vuln finding against the CISA "
                         "Known-Exploited Vulnerabilities feed; flag + escalate "
                         "actively-exploited CVEs to critical")
    sc.add_argument("--offline", action="store_true",
                    help="with --enrich-kev, serve the KEV feed from the local "
                         "cache only (never touch the network) — air-gap mode")
    sc.add_argument("--enrich-osv", action="store_true",
                    help="cross-reference detected CycloneDX components against "
                         "the bundled 262k-record offline OSV vulnerability "
                         "database; append matched CVE/GHSA findings (fully "
                         "offline, no network)")
    sc.add_argument("--osv-max", type=int, default=25,
                    help="max OSV findings per component when --enrich-osv is set "
                         "(default: 25)")

    db = sub.add_parser(
        "db",
        help="query the bundled offline 262k-record OSV vulnerability database",
        description="Direct lookups against the bundled cognis_vulndb.jsonl.gz "
                    "(real OSV corpus across PyPI/npm/Go/Maven/RubyGems/crates.io/"
                    "NuGet). Fully offline — no network, no key.",
    )
    dsub = db.add_subparsers(dest="db_command")
    dsub.add_parser("count", help="print the number of vulnerabilities bundled")
    dc = dsub.add_parser("cve", help="look up a CVE/GHSA id")
    dc.add_argument("id", help="e.g. CVE-2021-44228 or GHSA-jfh8-c2jp-5v3q")
    dp = dsub.add_parser("package", help="look up advisories for a package")
    dp.add_argument("name", help="package name or maven group:artifact coordinate")
    dp.add_argument("--ecosystem", help="restrict to an OSV ecosystem (e.g. Maven)")
    dse = dsub.add_parser("search", help="substring search over advisory summaries")
    dse.add_argument("text")
    dse.add_argument("--limit", type=int, default=20)

    fe = sub.add_parser(
        "feeds",
        help="manage the bundled edge/air-gap vulnerability data feeds",
        description="Fetch, cache and serve the real public vulnerability feeds "
                    "sbomx consumes (CISA-KEV, OSV). Works offline from cache; "
                    "snapshots move the cache to an air-gapped enclave.",
    )
    fsub = fe.add_subparsers(dest="feeds_command")
    fsub.add_parser("list", help="list the feeds this tool consumes")
    fu = fsub.add_parser("update", help="fetch + cache a feed (online)")
    fu.add_argument("feed", choices=feeds_mod.RELEVANT_FEEDS)
    fg = fsub.add_parser("get", help="print a feed (cache if fresh/offline)")
    fg.add_argument("feed", choices=feeds_mod.RELEVANT_FEEDS)
    fg.add_argument("--offline", action="store_true",
                    help="serve from cache only; never touch the network")
    return p


def _run_feeds(args) -> int:
    cmd = getattr(args, "feeds_command", None)
    try:
        if cmd == "list":
            for f in feeds_mod.list_feeds():
                print(f"{f['id']:<10} {f.get('domain',''):<8} {f['name']}")
                print(f"           {f['url']}")
            return 0
        if cmd == "update":
            path = feeds_mod.update(args.feed)
            print(f"cached {args.feed} -> {path}", file=sys.stderr)
            return 0
        if cmd == "get":
            data = feeds_mod.get(args.feed, offline=args.offline)
            if isinstance(data, (dict, list)):
                print(json.dumps(data, indent=2))
            else:
                print(data)
            return 0
    except (FileNotFoundError, KeyError, ConnectionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("usage: sbomx feeds {list|update <feed>|get <feed> [--offline]}",
          file=sys.stderr)
    return 2


def _run_db(args) -> int:
    from .vulndb_local import VulnDB
    cmd = getattr(args, "db_command", None)
    db = VulnDB()
    try:
        if cmd == "count":
            print(db.count())
            return 0
        if cmd == "cve":
            recs = db.by_cve(args.id)
            print(json.dumps(recs, indent=2))
            return 0 if recs else 1
        if cmd == "package":
            recs = db.by_package(args.name, ecosystem=args.ecosystem)
            print(json.dumps(recs, indent=2))
            return 0 if recs else 1
        if cmd == "search":
            recs = db.search(args.text, limit=args.limit)
            print(json.dumps(recs, indent=2))
            return 0 if recs else 1
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("usage: sbomx db {count|cve <id>|package <name> [--ecosystem E]|"
          "search <text> [--limit N]}", file=sys.stderr)
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "feeds":
        return _run_feeds(args)

    if args.command == "db":
        return _run_db(args)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        manifest = _load_manifest(args.manifest)
        result = scan(args.target, manifest)
        if args.enrich_osv:
            n = enrich_with_osv(result, max_per_component=args.osv_max)
            print(f"OSV enrichment: {n} offline finding(s) added from the "
                  f"bundled vulnerability database", file=sys.stderr)
        if args.enrich_kev:
            n = feeds_mod.enrich_with_kev(result, offline=args.offline)
            print(f"KEV enrichment: {n} finding(s) flagged as known-exploited",
                  file=sys.stderr)
    except (ValueError, FileNotFoundError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        bom = build_cyclonedx(result, TOOL_NAME, TOOL_VERSION)
        output = json.dumps(bom, indent=2)
    elif args.format == "sarif":
        log = build_sarif(result, TOOL_NAME, TOOL_VERSION)
        output = json.dumps(log, indent=2)
    elif args.format == "csv":
        output = build_csv(result)
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
