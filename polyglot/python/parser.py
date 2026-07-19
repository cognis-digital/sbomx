import os
import re
import json
import zipfile
import tarfile
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path


@dataclass
class LibraryInfo:
    """Represents a native library found in the app."""
    path: str
    name: str = ""
    size: int = 0
    arch: str = "unknown"
    symbols: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class SDKInfo:
    """Represents a detected bundled SDK."""
    name: str
    version: str = ""
    path: str = ""
    signature: str = ""  # e.g., "firebase", "unity"
    known_vulns: List[Dict] = field(default_factory=list)


@dataclass
class ComponentMatch:
    """Result of matching a component against databases."""
    name: str
    version: str
    matches: List[Tuple[str, Dict]]  # (database_name, match_data)
    vuln_count: int = 0
    privacy_flags: List[str] = field(default_factory=list)


@dataclass
class CycloneDXComponent:
    """CycloneDX component representation."""
    name: str
    version: str
    type: str  # "library", "sdk", "framework"
    purl: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


class CycloneDXBuilder:
    """Builds a CycloneDX SBOM document."""
    
    def __init__(self):
        self.components: List[CycloneDXComponent] = []
        self.metadata: Dict = {
            "name": "sbomx-mobile-sbom",
            "version": "1.0",
            "timestamp": "",
            "components": [],
            "dependencies": [],
            "metadata": {},
            "authors": ["sbomx"],
        }
    
    def add_component(self, comp: CycloneDXComponent):
        self.components.append(comp)
    
    def build_document(self) -> str:
        """Build the final CycloneDX JSON document."""
        doc = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": self.metadata["metadata"],
            "components": [],
        }
        
        for comp in self.components:
            component = {
                "name": comp.name,
                "type": comp.type,
                "version": comp.version,
            }
            
            if comp.purl:
                component["purl"] = comp.purl
            
            if comp.hashes:
                component["hashes"] = [{"alg": k, "content": v} for k, v in comp.hashes.items()]
            
            if comp.dependencies:
                deps = []
                for dep in comp.dependencies:
                    parts = dep.split(":", 1)
                    if len(parts) == 2:
                        name, ver = parts
                        deps.append({
                            "name": name,
                            "version": ver,
                            "type": "library",
                        })
                component["dependencies"] = deps
            
            doc["components"].append(component)
        
        return json.dumps(doc, indent=2)


class LibraryAnalyzer:
    """Analyzes native libraries for symbols and dependencies."""
    
    def __init__(self):
        self.tools = {
            "nm": ["nm", "-g"],  # Get global symbols
            "strings": ["strings", "-n", "10"],  # Extract strings
            "otool": ["otool", "-l"],  # Mach-O load commands (iOS)
            "readelf": ["readelf", "-d"],  # ELF dynamic section (Android/Linux)
        }
    
    def analyze_file(self, path: str, arch: str = "") -> LibraryInfo:
        """Analyze a single library file."""
        info = LibraryInfo(path=path, size=os.path.getsize(path), arch=arch)
        
        try:
            # Try to extract name from filename
            basename = os.path.basename(path)
            if ".so." in basename:
                info.name = basename.split(".so.")[1].split(".")[0]
            elif ".a" in basename:
                info.name = basename.replace(".a", "")
            
            # Try to get symbols using nm
            for cmd, args in self.tools.items():
                if "nm" in cmd or "otool" in cmd:
                    try:
                        result = subprocess.run(
                            [*args, path], capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0 and result.stdout:
                            symbols = self._parse_nm_output(result.stdout)
                            info.symbols.extend(symbols[:100])  # Limit for performance
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        pass
            
            return info
        except Exception as e:
            print(f"Error analyzing {path}: {e}")
        
        return info
    
    def _parse_nm_output(self, output: str) -> List[str]:
        """Parse nm output to extract symbol names."""
        symbols = []
        for line in output.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].isalnum():
                # Format: "T _main" or "t main" - second part is the name
                symbol_name = parts[-1]
                if not symbol_name.startswith(('.', '_', 'L')):
                    symbols.append(symbol_name)
        return symbols


class SDKDetector:
    """Detects bundled SDKs and frameworks."""
    
    # Known SDK signatures and patterns
    SDK_PATTERNS = {
        "firebase": [r"com\.google\.android\.firebase", r"FirebaseSDK"],
        "unity": [r"UnityPlayer", r"UnityFramework"],
        "google_play_services": [r"com\.google\.android\.gms", r"GooglePlayServices"],
        "facebook_sdk": [r"com\.facebook\.sdk", r"FacebookSDK"],
        "twitter_ads": [r"com\.twitter\.adsdk", r"TwitterAdsSDK"],
        "admob": [r"com\.google\.android\.ads", r"AdMob"],
        "analytics": [r"com\.google\.android\.gms\.analytics", r"AnalyticsSDK"],
    }
    
    # Version patterns for common SDKs
    VERSION_PATTERNS = {
        "firebase": r"FIREBASE_VERSION=(\d+\.\d+\.\d+)",
        "unity": r"UNITY_VERSION=(\d+\.\d+\.\d+)",
        "google_play_services": r"GMS_VERSION=(\d+\.\d+\.\d+)",
    }
    
    def __init__(self):
        self.detected_sdks: List[SDKInfo] = []
    
    def scan_archive(self, archive_path: str) -> List[SDKInfo]:
        """Scan an app archive for bundled SDKs."""
        sdks = []
        
        # Open the archive (handles .ipa, .apk, .app, etc.)
        with zipfile.ZipFile(archive_path, 'r') as zf:
            names = zf.namelist()
            
            # Check file contents for SDK signatures
            for name in names:
                try:
                    content = zf.read(name).decode('utf-8', errors='ignore')
                    
                    for sdk_name, patterns in self.SDK_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, content):
                                version = self._extract_version(sdk_name, name, content)
                                
                                # Check for known vulnerabilities
                                vulns = self._check_known_vulns(sdk_name, version)
                                
                                sdk_info = SDKInfo(
                                    name=sdk_name,
                                    version=version or "",
                                    path=name,
                                    signature=sdk_name,
                                    known_vulns=vulns,
                                )
                                
                                # Avoid duplicates
                                if not any(s.name == sdk_name and s.version == version for s in sdks):
                                    sdks.append(sdk_info)
                except Exception:
                    continue
        
        return sdks
    
    def _extract_version(self, sdk_name: str, path: str, content: str) -> Optional[str]:
        """Extract version string from SDK."""
        pattern = self.VERSION_PATTERNS.get(sdk_name)
        if not pattern:
            # Try filename-based extraction
            match = re.search(rf'({sdk_name})/([\d.]+)', path, re.IGNORECASE)
            if match:
                return match.group(2)
        
        if pattern:
            match = re.search(pattern, content)
            if match:
                return match.group(1)
        
        # Fallback: try to find version in filename
        basename = os.path.basename(path)
        match = re.search(rf'({sdk_name})/([\d.]+)', basename, re.IGNORECASE)
        if match:
            return match.group(2)
        
        return None
    
    def _check_known_vulns(self, sdk_name: str, version: str) -> List[Dict]:
        """Check against known vulnerability database."""
        # In production, this would query a real CVE database
        # For now, return some example data
        
        vuln_db = {
            "firebase": [
                {"cve": "CVE-2023-12345", "version": "<7.29.0", "severity": "medium"},
                {"cve": "CVE-2023-67890", "version": "<8.1.0", "severity": "high"},
            ],
            "google_play_services": [
                {"cve": "CVE-2023-11111", "version": "<44.0.0", "severity": "medium"},
            ],
        }
        
        if sdk_name in vuln_db:
            results = []
            for vuln in vuln_db[sdk_name]:
                # Simple version comparison (production would use proper semver)
                if self._version_matches(vuln["version"], version):
                    results.append({**vuln, "sdk": sdk_name})
            
            return results
        
        return []
    
    def _version_matches(self, constraint: str, version: str) -> bool:
        """Check if version matches a constraint like '<7.29.0'."""
        if not version or not constraint:
            return False
        
        # Parse simple constraints
        match = re.match(r'<(\d+\.\d+)', constraint)
        if match:
            max_ver = match.group(1)
            try:
                current = tuple(map(int, version.split('.')[:2]))
                max_v = tuple(map(int, max_ver.split('.'))[:2])
                return current < max_v
            except ValueError:
                pass
        
        return False


class ComponentMatcher:
    """Matches components against external databases."""
    
    def __init__(self):
        self.matched_components: List[ComponentMatch] = []
        
        # Example privacy flags (iOS 14+ ATT, etc.)
        self.privacy_patterns = {
            "app_tracking_transparency": [r"ATT", r"AppTrackingTransparency"],
            "user_defaults_sync": [r"NSUserDefaultsSync"],
            "background_fetch": [r"BackgroundFetch"],
        }
    
    def match_component(self, sdk: SDKInfo) -> ComponentMatch:
        """Match an SDK against databases."""
        matches = []
        
        # Check vulnerability database (already done in SDKDetector, but we aggregate here)
        vuln_count = len(sdk.known_vulns)
        
        # Check privacy/behavioral patterns
        for pattern_name, patterns in self.privacy_patterns.items():
            if any(re.search(p, sdk.path, re.IGNORECASE):
                matches.append((pattern_name, {"flag": pattern_name}))
        
        return ComponentMatch(
            name=sdk.name,
            version=sdk.version,
            matches=matches,
            vuln_count=vuln_count,
            privacy_flags=[m[0] for m in matches if "tracking" not in m[0].lower()],
        )


class MobileAppParser:
    """Main parser class for mobile app SBOM generation."""
    
    def __init__(self):
        self.analyzer = LibraryAnalyzer()
        self.sdk_detector = SDKDetector()
        self.component_matcher = ComponentMatcher()
        self.cyclonedx_builder = CycloneDXBuilder()
        
        # App metadata
        self.app_info: Dict[str, Any] = {
            "bundle_id": "",
            "package_name": "",
            "display_name": "",
            "version": "",
            "build_number": "",
            "architectures": [],
        }
    
    def parse_archive(self, archive_path: str) -> Dict[str, Any]:
        """Parse a mobile app archive and generate SBOM data."""
        result = {
            "archive_path": archive_path,
            "app_info": self.app_info,
            "libraries": [],
            "sdks": [],
            "components": [],
            "sbom_json": "",
        }
        
        # Open the archive
        with zipfile.ZipFile(archive_path, 'r') as zf:
            names = zf.namelist()
            
            # Extract basic app info from manifest files
            self._extract_app_info(zf)
            
            # Find and analyze native libraries
            result["libraries"] = self._find_native_libraries(zf)
            
            # Detect bundled SDKs
            result["sdks"] = self.sdk_detector.scan_archive(archive_path)
            
            # Match components against databases
            for sdk in result["sdks"]:
                match_result = self.component_matcher.match_component(sdk)
                sdk._match_result = match_result
            
            # Build CycloneDX document
            result["sbom_json"] = self.cyclonedx_builder.build_document()
        
        return result
    
    def _extract_app_info(self, zf: zipfile.ZipFile):
        """Extract basic app metadata from manifest files."""
        # Try to find Info.plist (iOS) or AndroidManifest.xml (Android)
        for name in ["Info.plist", "AndroidManifest.xml"]:
            if name in zf.namelist():
                try:
                    content = zf.read(name).decode('utf-8', errors='ignore')
                    
                    # iOS: extract bundle identifier and version
                    match = re.search(r'<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>', content)
                    if match:
                        self.app_info["bundle_id"] = match.group(1).strip()
                    
                    match = re.search(r'<key>CFBundleVersion</key>\s*<string>([^<]+)</string>', content)
                    if match:
                        self.app_info["build_number"] = match.group(1).strip()
                    
                    # Android: extract package name and version
                    match = re.search(r'package="([^"]+)"', content)
                    if match:
                        self.app_info["package_name"] = match.group(1).strip()
                    
                    match = re.search(r'versionName="([^"]+)"', content)
                    if match:
                        self.app_info["version"] = match.group(1).strip()
                except Exception as e:
                    print(f"Error reading {name}: {e}")
    
    def _find_native_libraries(self, zf: zipfile.ZipFile) -> List[LibraryInfo]:
        """Find and analyze native libraries in the archive."""
        libraries = []
        
        # Common library extensions
        ext_patterns = [r'\.so\.', r'\.a$', r'\.dylib$']
        
        for name in zf.namelist():
            basename = os.path.basename(name)
            
            # Check if it's a native library
            is_lib = any(re.search(p, basename, re.IGNORECASE) for p in ext_patterns)
            
            if is_lib:
                # Determine architecture
                arch = self._detect_architecture(name, zf)
                
                # Analyze the library
                lib_info = self.analyzer.analyze_file(
                    name, 
                    arch=arch