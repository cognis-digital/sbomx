"""Core engine for SBOMX.

The job: given a mobile app bundle (.apk / .ipa, which are just zip files) or a
directory / list of file paths, identify the third-party libraries that are
bundled inside, then match them against:

  * VULN_DB    - known-vulnerable library versions (CVE-style entries)
  * TRACKER_DB - privacy/ad/analytics trackers (Exodus-style)

Detection is done by recognising well-known package paths and native lib names
that appear in real Android/iOS apps, e.g.:

  com/google/firebase/...        -> firebase
  com/facebook/react/...         -> react-native
  okhttp3/...                    -> okhttp
  lib/arm64-v8a/libsqlite.so     -> sqlite
  Frameworks/Alamofire.framework -> alamofire (iOS)

Versions are recovered where they appear in the path / manifest
(e.g. `okhttp-4.9.0.jar`, `Alamofire-5.4.0`) or from a provided manifest map.

Standard library only.
"""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Detection rules. Each rule maps a path *substring/prefix* to a canonical
# library key. Order matters only for reporting; matching is by `marker`.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rule:
    key: str          # canonical library key used to join with the DBs
    name: str         # human/CycloneDX component name
    marker: str       # path fragment that signals presence
    ecosystem: str    # maven | cocoapods | native | npm
    purl_type: str    # purl type, e.g. 'maven', 'cocoapods', 'generic'
    group: str = ""   # purl namespace / group


# Curated, real-world detection rules (Android + iOS + native).
DETECTION_RULES: List[_Rule] = [
    # --- Android / Java (maven) ---
    _Rule("firebase", "firebase-core", "com/google/firebase/", "maven", "maven", "com.google.firebase"),
    _Rule("play-services", "play-services-basement", "com/google/android/gms/", "maven", "maven", "com.google.android.gms"),
    _Rule("okhttp", "okhttp", "okhttp3/", "maven", "maven", "com.squareup.okhttp3"),
    _Rule("retrofit", "retrofit", "retrofit2/", "maven", "maven", "com.squareup.retrofit2"),
    _Rule("gson", "gson", "com/google/gson/", "maven", "maven", "com.google.code.gson"),
    _Rule("glide", "glide", "com/bumptech/glide/", "maven", "maven", "com.github.bumptech.glide"),
    _Rule("react-native", "react-native", "com/facebook/react/", "npm", "npm", ""),
    _Rule("flutter", "flutter", "io/flutter/", "maven", "maven", "io.flutter"),
    _Rule("exoplayer", "exoplayer", "com/google/android/exoplayer2/", "maven", "maven", "com.google.android.exoplayer"),
    # --- iOS / CocoaPods ---
    _Rule("alamofire", "Alamofire", "Alamofire.framework", "cocoapods", "cocoapods", ""),
    _Rule("afnetworking", "AFNetworking", "AFNetworking.framework", "cocoapods", "cocoapods", ""),
    _Rule("sdwebimage", "SDWebImage", "SDWebImage.framework", "cocoapods", "cocoapods", ""),
    _Rule("realm", "Realm", "Realm.framework", "cocoapods", "cocoapods", ""),
    # --- Native shared objects (generic) ---
    _Rule("sqlite", "sqlite", "libsqlite", "native", "generic", ""),
    _Rule("openssl", "openssl", "libssl", "native", "generic", ""),
    _Rule("openssl", "openssl", "libcrypto", "native", "generic", ""),
    _Rule("libpng", "libpng", "libpng", "native", "generic", ""),
    _Rule("libwebp", "libwebp", "libwebp", "native", "generic", ""),
    _Rule("zlib", "zlib", "libz.so", "native", "generic", ""),
    # --- Trackers (also surfaced as components) ---
    _Rule("crashlytics", "firebase-crashlytics", "com/google/firebase/crashlytics/", "maven", "maven", "com.google.firebase"),
    _Rule("facebook-ads", "facebook-audience-network", "com/facebook/ads/", "maven", "maven", ""),
    _Rule("appsflyer", "appsflyer", "com/appsflyer/", "maven", "maven", "com.appsflyer"),
    _Rule("adjust", "adjust-sdk", "com/adjust/sdk/", "maven", "maven", "com.adjust.sdk"),
    _Rule("mixpanel", "mixpanel", "com/mixpanel/android/", "maven", "maven", "com.mixpanel.android"),
    _Rule("flurry", "flurry", "com/flurry/", "maven", "maven", ""),
    _Rule("unity-ads", "unity-ads", "com/unity3d/ads/", "maven", "maven", ""),
    _Rule("applovin", "applovin", "com/applovin/", "maven", "maven", ""),
]

# ---------------------------------------------------------------------------
# Vulnerability DB: lib key -> list of advisories.
# `affected` is a list of (op, version) constraints ALL of which must hold.
# A None component version => advisory reported as 'version-unknown' (potential).
# ---------------------------------------------------------------------------

VULN_DB: Dict[str, List[dict]] = {
    "okhttp": [
        {"id": "CVE-2021-0341", "severity": "medium", "cwe": "CWE-295",
         "summary": "OkHttp improper certificate validation (hostname not verified).",
         "affected": [("<", "4.9.2")], "fixed": "4.9.2"},
    ],
    "openssl": [
        {"id": "CVE-2022-0778", "severity": "high", "cwe": "CWE-835",
         "summary": "BN_mod_sqrt infinite loop (DoS) when parsing certificates.",
         "affected": [(">=", "1.0.2"), ("<", "1.1.1n")], "fixed": "1.1.1n"},
        {"id": "CVE-2016-2107", "severity": "high", "cwe": "CWE-310",
         "summary": "Padding oracle in AES-NI CBC MAC check.",
         "affected": [("<", "1.0.2h")], "fixed": "1.0.2h"},
        {"id": "CVE-2014-0160", "severity": "high", "cwe": "CWE-125",
         "summary": "Heartbleed: TLS heartbeat over-read discloses process memory.",
         "affected": [(">=", "1.0.1"), ("<", "1.0.1g")], "fixed": "1.0.1g"},
    ],
    "libwebp": [
        {"id": "CVE-2023-4863", "severity": "critical", "cwe": "CWE-787",
         "summary": "Heap buffer overflow in WebP lossless (VP8L) decoding; "
                    "exploited in the wild via crafted .webp images.",
         "affected": [("<", "1.3.2")], "fixed": "1.3.2"},
    ],
    "sqlite": [
        {"id": "CVE-2019-8457", "severity": "high", "cwe": "CWE-125",
         "summary": "Heap out-of-bounds read in rtreenode().",
         "affected": [("<", "3.28.0")], "fixed": "3.28.0"},
    ],
    "libpng": [
        {"id": "CVE-2019-7317", "severity": "medium", "cwe": "CWE-416",
         "summary": "Use-after-free in png_image_free.",
         "affected": [("<", "1.6.37")], "fixed": "1.6.37"},
    ],
    "gson": [
        {"id": "CVE-2022-25647", "severity": "high", "cwe": "CWE-502",
         "summary": "Deserialization of untrusted data via writeReplace().",
         "affected": [("<", "2.8.9")], "fixed": "2.8.9"},
    ],
    "glide": [
        {"id": "CVE-2020-8771", "severity": "medium", "cwe": "CWE-345",
         "summary": "Glide accepts non-HTTPS image URLs by default (MITM).",
         "affected": [("<", "4.11.0")], "fixed": "4.11.0"},
    ],
    "realm": [
        {"id": "CVE-2020-24613", "severity": "medium", "cwe": "CWE-326",
         "summary": "Realm sync TLS certificate not validated in some configs.",
         "affected": [("<", "10.0.0")], "fixed": "10.0.0"},
    ],
    "zlib": [
        {"id": "CVE-2018-25032", "severity": "medium", "cwe": "CWE-787",
         "summary": "Memory corruption when compressing with many distance codes.",
         "affected": [("<", "1.2.12")], "fixed": "1.2.12"},
    ],
}

# ---------------------------------------------------------------------------
# Tracker DB: lib key -> tracker metadata (categories follow Exodus Privacy).
# ---------------------------------------------------------------------------

TRACKER_DB: Dict[str, dict] = {
    "crashlytics":   {"name": "Google Firebase Crashlytics", "categories": ["Crash reporting", "Analytics"]},
    "firebase":      {"name": "Google Firebase Analytics", "categories": ["Analytics"]},
    "facebook-ads":  {"name": "Facebook Audience Network", "categories": ["Advertisement", "Profiling"]},
    "appsflyer":     {"name": "AppsFlyer", "categories": ["Analytics", "Advertisement"]},
    "adjust":        {"name": "Adjust", "categories": ["Analytics", "Advertisement"]},
    "mixpanel":      {"name": "Mixpanel", "categories": ["Analytics"]},
    "flurry":        {"name": "Flurry", "categories": ["Analytics", "Advertisement"]},
    "unity-ads":     {"name": "Unity Ads", "categories": ["Advertisement"]},
    "applovin":      {"name": "AppLovin", "categories": ["Advertisement", "Profiling"]},
}

# Version captured from filenames like okhttp-4.9.0.jar, Alamofire-5.4.0,
# libsqlite-3.27.so, libssl.so.1.1, libpng16.so.1.6.34
_VERSION_RE = re.compile(r"[-_.](\d+(?:\.\d+){1,3}[a-z]?)")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Component:
    key: str
    name: str
    version: Optional[str]
    ecosystem: str
    purl_type: str
    group: str
    evidence: str  # path where it was detected

    def purl(self) -> str:
        ns = (self.group + "/") if self.group else ""
        ver = ("@" + self.version) if self.version else ""
        return f"pkg:{self.purl_type}/{ns}{self.name}{ver}"

    def bom_ref(self) -> str:
        return self.purl()


@dataclass
class Finding:
    kind: str            # 'vulnerability' | 'tracker'
    component_key: str
    component_name: str
    component_version: Optional[str]
    id: str              # CVE id or tracker name
    severity: str        # vuln severity, or 'info' for trackers
    summary: str
    fixed_version: Optional[str] = None
    version_known: bool = True
    extra: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    components: List[Component]
    findings: List[Finding]
    target: str

    @property
    def vulnerabilities(self) -> List[Finding]:
        return [f for f in self.findings if f.kind == "vulnerability"]

    @property
    def trackers(self) -> List[Finding]:
        return [f for f in self.findings if f.kind == "tracker"]


# ---------------------------------------------------------------------------
# Version comparison (PEP 440-ish; tolerant of trailing letters like 1.1.1n)
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> Tuple:
    parts: List[Tuple[int, str]] = []
    for chunk in v.split("."):
        m = re.match(r"(\d*)([a-zA-Z]*)", chunk)
        num = int(m.group(1)) if m and m.group(1) else 0
        suffix = m.group(2) if m else ""
        parts.append((num, suffix))
    return tuple(parts)


def _cmp_versions(a: str, b: str) -> int:
    pa, pb = _parse_version(a), _parse_version(b)
    n = max(len(pa), len(pb))
    pa += ((0, ""),) * (n - len(pa))
    pb += ((0, ""),) * (n - len(pb))
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


def _satisfies(version: str, op: str, target: str) -> bool:
    c = _cmp_versions(version, target)
    return {
        "<": c < 0, "<=": c <= 0, ">": c > 0,
        ">=": c >= 0, "==": c == 0, "!=": c != 0,
    }[op]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _extract_version(path: str) -> Optional[str]:
    base = os.path.basename(path)
    m = _VERSION_RE.search(base)
    return m.group(1) if m else None


def detect_components_from_paths(
    paths: Iterable[str],
    manifest: Optional[Dict[str, str]] = None,
) -> List[Component]:
    """Detect bundled libraries from an iterable of archive member paths.

    `manifest` optionally maps a library key to a known version string
    (overrides any version recovered from the path).
    """
    manifest = manifest or {}
    found: Dict[str, Component] = {}
    for path in paths:
        norm = path.replace("\\", "/")
        base = os.path.basename(norm)
        for rule in DETECTION_RULES:
            # match the package-path marker OR a versioned artifact like <key>-4.9.0.jar,
            # so a component's version is recovered even when only the jar carries it.
            if rule.marker in norm or re.match(re.escape(rule.key) + r"[-_]\d", base, re.I):
                version = manifest.get(rule.key) or _extract_version(norm)
                existing = found.get(rule.key)
                # Keep the first detection but upgrade if we learn a version.
                if existing is None:
                    found[rule.key] = Component(
                        key=rule.key, name=rule.name, version=version,
                        ecosystem=rule.ecosystem, purl_type=rule.purl_type,
                        group=rule.group, evidence=norm,
                    )
                elif existing.version is None and version is not None:
                    existing.version = version
                    existing.evidence = norm
    return sorted(found.values(), key=lambda c: c.name.lower())


def _iter_archive_paths(target: str) -> List[str]:
    if zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as zf:
            return zf.namelist()
    if os.path.isdir(target):
        out = []
        for root, _dirs, files in os.walk(target):
            for fn in files:
                full = os.path.join(root, fn)
                out.append(os.path.relpath(full, target))
        return out
    raise ValueError(f"target is neither a zip (.apk/.ipa) nor a directory: {target}")


def detect_components(target: str, manifest: Optional[Dict[str, str]] = None) -> List[Component]:
    """Detect components from an .apk/.ipa/zip file or a directory tree."""
    return detect_components_from_paths(_iter_archive_paths(target), manifest)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def match_findings(components: Iterable[Component]) -> List[Finding]:
    findings: List[Finding] = []
    for comp in components:
        # Vulnerabilities
        for adv in VULN_DB.get(comp.key, []):
            if comp.version is None:
                findings.append(Finding(
                    kind="vulnerability", component_key=comp.key,
                    component_name=comp.name, component_version=None,
                    id=adv["id"], severity=adv["severity"],
                    summary=adv["summary"], fixed_version=adv.get("fixed"),
                    version_known=False, extra={"cwe": adv.get("cwe")},
                ))
                continue
            if all(_satisfies(comp.version, op, ver) for op, ver in adv["affected"]):
                findings.append(Finding(
                    kind="vulnerability", component_key=comp.key,
                    component_name=comp.name, component_version=comp.version,
                    id=adv["id"], severity=adv["severity"],
                    summary=adv["summary"], fixed_version=adv.get("fixed"),
                    version_known=True, extra={"cwe": adv.get("cwe")},
                ))
        # Trackers
        tr = TRACKER_DB.get(comp.key)
        if tr:
            findings.append(Finding(
                kind="tracker", component_key=comp.key,
                component_name=comp.name, component_version=comp.version,
                id=tr["name"], severity="info",
                summary="Privacy tracker: " + ", ".join(tr["categories"]),
                extra={"categories": tr["categories"]},
            ))
    return findings


# ---------------------------------------------------------------------------
# CycloneDX 1.5 output
# ---------------------------------------------------------------------------

def _serial_number(target: str, components: List[Component]) -> str:
    h = hashlib.sha1()
    h.update(os.path.basename(target).encode("utf-8"))
    for c in components:
        h.update(c.purl().encode("utf-8"))
    digest = h.hexdigest()
    # RFC 4122 URN shape (deterministic, not random).
    return ("urn:uuid:" + digest[0:8] + "-" + digest[8:12] + "-5" + digest[13:16]
            + "-8" + digest[17:20] + "-" + digest[20:32])


def build_cyclonedx(result: ScanResult, tool_name: str, tool_version: str) -> dict:
    sev_to_cdx = {"high": "high", "medium": "medium", "low": "low", "critical": "critical"}
    components_json = []
    for c in result.components:
        entry = {
            "type": "library",
            "bom-ref": c.bom_ref(),
            "name": c.name,
            "purl": c.purl(),
            "properties": [
                {"name": "sbomx:ecosystem", "value": c.ecosystem},
                {"name": "sbomx:evidence", "value": c.evidence},
            ],
        }
        if c.version:
            entry["version"] = c.version
        if c.group:
            entry["group"] = c.group
        components_json.append(entry)

    vulns_json = []
    for f in result.vulnerabilities:
        vulns_json.append({
            "bom-ref": f"{f.id}/{f.component_key}",
            "id": f.id,
            "source": {"name": "sbomx-vulndb"},
            "ratings": [{"severity": sev_to_cdx.get(f.severity, "unknown")}],
            "cwes": ([int(f.extra["cwe"].split("-")[1])]
                     if f.extra.get("cwe") else []),
            "description": f.summary + ("" if f.version_known
                                        else " [version unknown - potential match]"),
            "recommendation": (f"Upgrade {f.component_name} to {f.fixed_version} or later."
                               if f.fixed_version else ""),
            "affects": [{"ref": next((c.bom_ref() for c in result.components
                                      if c.key == f.component_key), f.component_key)}],
        })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": _serial_number(result.target, result.components),
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "sbomx", "name": tool_name, "version": tool_version}],
            "component": {
                "type": "application",
                "name": os.path.basename(result.target),
                "bom-ref": "root-app",
            },
            "properties": [
                {"name": "sbomx:trackerCount", "value": str(len(result.trackers))},
                {"name": "sbomx:vulnCount", "value": str(len(result.vulnerabilities))},
            ],
        },
        "components": components_json,
        "vulnerabilities": vulns_json,
    }
    return bom


# ---------------------------------------------------------------------------
# SARIF 2.1.0 output (for GitHub code-scanning / any SARIF consumer)
# ---------------------------------------------------------------------------

# SARIF only has error/warning/note/none; map our severities onto them.
_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "warning",
    "info": "note",
}
# security-severity is a 0.0-10.0 string GitHub uses to bucket alerts.
_SECURITY_SEVERITY = {
    "critical": "9.5", "high": "8.0",
    "medium": "5.5", "low": "3.0", "info": "1.0",
}


def build_sarif(result: ScanResult, tool_name: str, tool_version: str) -> dict:
    """Render the scan result as a SARIF 2.1.0 log.

    Every vulnerability and tracker becomes a `result`. Each distinct finding
    id becomes a reusable `rule` in `tool.driver.rules`. Component evidence is
    used as the artifact location so code-scanning UIs can anchor the alert.
    """
    rules: List[dict] = []
    rule_index: Dict[str, int] = {}
    results_json: List[dict] = []

    evidence_by_key = {c.key: c.evidence for c in result.components}

    def _rule_for(rule_id: str, name: str, short: str, full: str,
                  severity: str, help_uri: Optional[str] = None,
                  cwe: Optional[str] = None) -> int:
        if rule_id in rule_index:
            return rule_index[rule_id]
        rule: dict = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": short},
            "fullDescription": {"text": full},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
            "properties": {
                "security-severity": _SECURITY_SEVERITY.get(severity, "1.0"),
                "tags": ["security"],
            },
        }
        if cwe:
            rule["properties"]["cwe"] = cwe
            rule["properties"]["tags"] = ["security", "external/cwe/" + cwe.lower()]
        if help_uri:
            rule["helpUri"] = help_uri
        rule_index[rule_id] = len(rules)
        rules.append(rule)
        return rule_index[rule_id]

    for f in result.findings:
        evidence = evidence_by_key.get(f.component_key, f.component_key)
        ver = f.component_version or "version-unknown"
        if f.kind == "vulnerability":
            cwe = f.extra.get("cwe")
            help_uri = ("https://nvd.nist.gov/vuln/detail/" + f.id
                        if f.id.startswith("CVE-") else None)
            idx = _rule_for(
                f.id, f.id, f.summary, f.summary, f.severity,
                help_uri=help_uri, cwe=cwe,
            )
            note = "" if f.version_known else " [version unknown - potential match]"
            msg = (f"{f.component_name}@{ver} is affected by {f.id}: {f.summary}{note}")
            if f.fixed_version:
                msg += f" Upgrade to >= {f.fixed_version}."
        else:  # tracker
            rule_id = "tracker/" + f.component_key
            cats = ", ".join(f.extra.get("categories", []))
            idx = _rule_for(
                rule_id, f.id, f"Privacy tracker: {f.id}",
                f"Bundled privacy/analytics tracker ({cats}).", "info",
            )
            msg = f"Privacy tracker '{f.id}' bundled ({cats})."

        results_json.append({
            "ruleId": f.id if f.kind == "vulnerability" else "tracker/" + f.component_key,
            "ruleIndex": idx,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": evidence, "uriBaseId": "SRCROOT"},
                }
            }],
            "partialFingerprints": {
                "sbomxFinding/v1": hashlib.sha1(
                    f"{f.kind}|{f.component_key}|{f.id}|{ver}".encode("utf-8")
                ).hexdigest(),
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/cognis-digital/sbomx",
                    "rules": rules,
                }
            },
            "originalUriBaseIds": {
                "SRCROOT": {"uri": "file:///", "description": {"text": os.path.basename(result.target)}}
            },
            "results": results_json,
            "properties": {
                "sbomx:componentCount": len(result.components),
                "sbomx:vulnCount": len(result.vulnerabilities),
                "sbomx:trackerCount": len(result.trackers),
            },
        }],
    }


# ---------------------------------------------------------------------------
# CSV output (one row per finding; spreadsheet / ticketing friendly)
# ---------------------------------------------------------------------------

def build_csv(result: ScanResult) -> str:
    """Render findings as CSV text (RFC-4180 quoting via csv module)."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([
        "kind", "id", "severity", "component", "version",
        "fixed_version", "version_known", "cwe", "summary", "evidence",
    ])
    evidence_by_key = {c.key: c.evidence for c in result.components}
    # Stable order: vulns first (by severity desc), then trackers.
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    ordered = sorted(
        result.findings,
        key=lambda f: (0 if f.kind == "vulnerability" else 1,
                       -sev_order.get(f.severity, 0), f.component_name, f.id),
    )
    for f in ordered:
        writer.writerow([
            f.kind, f.id, f.severity, f.component_name,
            f.component_version or "", f.fixed_version or "",
            "true" if f.version_known else "false",
            f.extra.get("cwe", "") or "",
            f.summary, evidence_by_key.get(f.component_key, ""),
        ])
    return buf.getvalue().rstrip("\n")


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------

def scan(target: str, manifest: Optional[Dict[str, str]] = None) -> ScanResult:
    """Scan a mobile app bundle / directory and return components + findings."""
    components = detect_components(target, manifest)
    findings = match_findings(components)
    return ScanResult(components=components, findings=findings, target=target)
