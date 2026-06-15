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
        if not chunk:
            parts.append((0, ""))
            continue
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
        # Versioned artifact filenames (libs/okhttp-4.9.0.jar) carry the
        # version that a class-path marker alone can't provide.
        base = os.path.basename(norm).lower()
        for rule in DETECTION_RULES:
            if rule.marker in norm or base.startswith(
                    (rule.key.lower() + "-", rule.name.lower() + "-")):
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
    if not os.path.exists(target):
        raise FileNotFoundError(f"target path does not exist: {target}")
    if os.path.isdir(target):
        out = []
        for root, _dirs, files in os.walk(target):
            for fn in files:
                full = os.path.join(root, fn)
                out.append(os.path.relpath(full, target))
        return out
    try:
        is_zip = zipfile.is_zipfile(target)
    except (OSError, IOError) as exc:
        raise ValueError(f"cannot read target file: {exc}") from exc
    if is_zip:
        try:
            with zipfile.ZipFile(target) as zf:
                return zf.namelist()
        except zipfile.BadZipFile as exc:
            raise ValueError(f"target is not a valid zip archive: {exc}") from exc
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


def _parse_cwe_int(cwe: Optional[str]) -> List[int]:
    """Return a list containing the integer CWE number, or empty list on bad input."""
    if not cwe:
        return []
    parts = cwe.split("-")
    if len(parts) < 2:
        return []
    try:
        return [int(parts[1])]
    except (ValueError, IndexError):
        return []


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
            "cwes": (_parse_cwe_int(f.extra.get("cwe"))),
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
# Top-level scan
# ---------------------------------------------------------------------------

TOOL_NAME = "sbomx"
TOOL_VERSION = "0.1.0"


def scan(target: str, manifest: Optional[Dict[str, str]] = None) -> ScanResult:
    """Scan a mobile app bundle / directory and return components + findings."""
    components = detect_components(target, manifest)
    findings = match_findings(components)
    return ScanResult(components=components, findings=findings, target=target)


def to_json(result: ScanResult) -> str:
    """Return the CycloneDX 1.5 SBOM for *result* as a JSON string."""
    import json
    bom = build_cyclonedx(result, TOOL_NAME, TOOL_VERSION)
    return json.dumps(bom, indent=2)
