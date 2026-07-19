# polyglot/python/core.py
"""
sbomx-core: Mobile App SBOM Generator with Vulnerability Matching.

Parses APK/IPA archives, extracts native libraries and SDKs, generates
CycloneDX 1.4 format, and matches against vulnerability/privacy databases.
"""

import os
import sys
import json
import zipfile
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, BinaryIO
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

CYCLONEDX_VERSION = "1.4"
DEFAULT_WORKERS = 4
MAX_APK_SIZE_MB = 200
NATIVE_LIB_EXTENSIONS = {'.jar', '.so', '.dylib', '.a', '.aar'}
SDK_PATTERNS = [
    r'com\.android\.sdk\.',
    r'meta\.android\.sdk\.',
    r'org\.jetbrains\.kotlin\.',
    r'io\.reactive\.rxjava\.',
    r'com\.squareup\.retrofit\.',
]


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class Component:
    """CycloneDX component representation."""
    name: str
    version: str
    group: str = ""
    type_: str = "library"  # library, application, framework, etc.
    description: str = ""
    purl: Optional[str] = None
    cpe: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    files: List[Dict] = field(default_factory=list)  # source file info


@dataclass
class VulnerabilityMatch:
    """A matched vulnerability record."""
    component_name: str
    component_version: str
    cve_id: str
    severity: str
    description: str
    references: List[str] = field(default_factory=list)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def normalize_cpe(name: str, version: str) -> Optional[str]:
    """Convert library name/version to CPE format."""
    # Normalize common patterns
    normalized_name = re.sub(r'[._-]', '.', name).lower()
    
    if not version:
        return None
    
    # Handle maven-style coordinates like com.example:lib:1.2.3
    parts = version.split(':')
    if len(parts) >= 2 and parts[0].startswith('com.') or parts[0].startswith('org.'):
        group, module = parts[0], ':'.join(parts[1:-1])
        return f"cpe:2.3:a:{group}:{module}:*:*:*:*:*:*:*:*"
    
    # Simple format
    return f"cpe:2.3:o:vendor:{normalized_name}:{version}:*:*:*:*:*:*:*"


def parse_maven_version(version_str: str) -> Tuple[str, str]:
    """Parse maven-style coordinate like com.example:lib:1.0.0."""
    parts = version_str.split(':')
    if len(parts) >= 3:
        return ':'.join(parts[1:-1]), parts[-1]
    return '', version_str


def calculate_file_hashes(filepath: str, chunk_size: int = 8192) -> Dict[str, str]:
    """Calculate SHA-256 and MD5 hashes for a file."""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)
        
        return {
            'sha-256': sha256_hash.hexdigest(),
            'md5': md5_hash.hexdigest()
        }
    except (IOError, OSError):
        return {}


def extract_apk_name_from_path(path: str) -> str:
    """Extract APK name from file path."""
    basename = os.path.basename(path)
    if basename.endswith('.zip'):
        # Handle fat APKs with multiple APKs inside
        match = re.search(r'([a-zA-Z0-9._-]+)\.apk', basename, re.IGNORECASE)
        return match.group(1) if match else 'app'
    return os.path.splitext(basename)[0]


# =============================================================================
# FILE SYSTEM SCANNER
# =============================================================================

class ApkScanner:
    """Scans APK/IPA archives for components and native libraries."""
    
    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.components: List[Component] = []
        self.native_libs: Dict[str, Component] = {}  # path -> component
        self.scripts: List[Dict] = []
        
    def scan(self) -> Tuple[List[Component], Dict[str, Component]]:
        """Scan the APK and return components plus native libs."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                self._scan_zip_contents(zf)
                
        except (zipfile.BadZipFile, IOError):
            # Try reading as regular file for fat APKs
            with open(self.apk_path, 'rb') as f:
                while True:
                    header = f.read(26)
                    if not header or header[:4] != b'PK\x03\x04':
                        break
                    
                    # Extract next APK name from fat APK structure
                    apk_name = extract_apk_name_from_path(self.apk_path)
                    
                    with zipfile.ZipFile(f, 'r') as zf:
                        self._scan_zip_contents(zf, apk_name=apk_name)
                        
                    f.seek(0)  # Reset for next iteration
                    
        return self.components, self.native_libs
    
    def _scan_zip_contents(self, zf: zipfile.ZipFile, apk_name: str = 'app'):
        """Scan ZIP contents for components."""
        
        # Scan all files
        for info in zf.infolist():
            filename = info.filename
            
            # Skip directories and non-code resources
            if not any(filename.endswith(ext) for ext in NATIVE_LIB_EXTENSIONS):
                continue
                
            try:
                content = zf.read(info.filename)
                
                # Determine component type
                if '.jar' in filename or '.aar' in filename:
                    comp_type = 'library'
                    name_parts = filename.split('/')[-1].replace('.', '_').split('_')
                    name = apk_name + '.'.join(name_parts[:-2]) if len(name_parts) > 2 else apk_name
                    
                elif '.so' in filename or '.dylib' in filename:
                    comp_type = 'framework'
                    name = f"{apk_name}_native_{filename.split('/')[-1].replace('.', '_')}"
                    
                elif '.a' in filename:
                    comp_type = 'library'
                    name = apk_name + '_' + filename.split('/')[-1].replace('.', '_').split('_')[0]
                    
                else:
                    continue
                
                # Extract version from filename or path
                version_match = re.search(r'[vV](\d+(?:\.\d+)*)', filename)
                version = version_match.group(1) if version_match else 'unknown'
                
                # Calculate hashes
                hashes = calculate_file_hashes(zf.filename, chunk_size=4096)
                
                component = Component(
                    name=name,
                    version=version,
                    type_=comp_type,
                    description=f"Extracted from {filename}",
                    purl=f"pkg:apk/{apk_name}/{name}@{version}",
                    hashes=hashes,
                    files=[{'path': filename}]
                )
                
                if comp_type == 'library' and not any(c.name == name for c in self.components):
                    self.components.append(component)
                    
            except (IOError, OSError):
                continue


# =============================================================================
# SDK DETECTION
# =============================================================================

class SdkDetector:
    """Detects bundled Android SDK components."""
    
    KNOWN_SDKS = {
        'androidx.core:core-ktx': ('AndroidX Core', '1.9.0'),
        'org.jetbrains.kotlin:kotlin-stdlib': ('Kotlin Stdlib', '1.8.20'),
        'com.squareup.retrofit2:retrofit': ('Retrofit', '2.9.0'),
    }
    
    @classmethod
    def detect_from_components(cls, components: List[Component]) -> Dict[str, Component]:
        """Filter and identify SDK components."""
        sdk_map = {}
        
        for comp in components:
            # Check against known patterns
            for pattern in SDK_PATTERNS:
                if re.search(pattern, comp.name):
                    sdk_name, default_version = cls.KNOWN_SDKS.get(
                        comp.purl or comp.name, 
                        (comp.name, 'unknown')
                    )
                    
                    component = Component(
                        name=sdk_name,
                        version=default_version,
                        type_='framework',
                        description=f"Android SDK: {sdk_name}",
                        purl=comp.purl,
                        cpe=normalize_cpe(sdk_name, default_version),
                        hashes=comp.hashes.copy() if comp.hashes else {},
                    )
                    
                    sdk_key = f"{sdk_name}:{default_version}"
                    if not any(c.name == sdk_key for c in sdk_map.values()):
                        sdk_map[sdk_key] = component
        
        return sdk_map


# =============================================================================
# CYCLONEDX BUILDER
# =============================================================================

class CycloneDxBuilder:
    """Builds CycloneDX 1.4 SBOM documents."""
    
    def __init__(self, components: List[Component]):
        self.components = components
    
    def build(self) -> str:
        """Generate CycloneDX JSON string."""
        
        # Deduplicate components by purl or name+version
        seen = set()
        unique_components = []
        
        for comp in self.components:
            key = (comp.name, comp.version, comp.purl)
            if key not in seen:
                seen.add(key)
                unique_components.append(comp)
        
        # Build CycloneDX document
        bom_doc = {
            'bomFormat': 'CycloneDX',
            'specVersion': {'major': 1, 'minor': 4},
            'version': 1,
            'metadata': {
                'component': {
                    'name': 'sbomx-generated-sbom',
                    'type': 'application',
                    'version': '1.0.0'
                }
            },
            'components': []
        }
        
        for comp in unique_components:
            bom_component = {
                'name': comp.name,
                'version': comp.version,
                'type': comp.type_,
                'description': comp.description,
            }
            
            if comp.purl:
                bom_component['purl'] = comp.purl
            
            if comp.cpe:
                bom_component['cpe'] = comp.cpe
            
            if comp.hashes:
                bom_component['hashes'] = comp.hashes
            
            # Convert files to proper format
            if comp.files:
                file_entries = []
                for f in comp.files:
                    file_entry = {
                        'name': os.path.basename(f.get('path', '')),
                    }
                    if f.get('path'):
                        file_entry['hashes'] = calculate_file_hashes(
                            f['path'], chunk_size=4096
                        )
                    file_entries.append(file_entry)
                bom_component['files'] = file_entries
            
            bom_doc['components'].append(bom_component)
        
        return json.dumps(bom_doc, indent=2, ensure_ascii=False)


# =============================================================================
# VULNERABILITY MATCHING
# =============================================================================

@dataclass
class VulnDatabase:
    """Base class for vulnerability databases."""
    
    name: str
    url: str
    
    def load(self) -> Dict[str, List[Dict]]:  # cve_id -> list of vulns
        raise NotImplementedError


class NvdVulnDb(VulnDatabase):
    """NVD (National Vulnerability Database) integration."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.name = "NVD"
        self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
    
    def load(self) -> Dict[str, List[Dict]]:
        """Load recent CVEs from NVD."""
        # In production, this would make HTTP requests
        # For demo, return sample data
        return {
            'CVE-2023-1234': [
                {
                    'cve_id': 'CVE-2023-1234',
                    'severity': 'HIGH',
                    'description': 'Remote code execution in vulnerable library',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2023-1234'],
                }
            ],
        }


class MavenVulnDb(VulnDatabase):
    """Maven Central vulnerability data."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.name = "Maven"
        self.url = "https://search.maven.org/solrsearch/select"
        
    def load(self) -> Dict[str, List[Dict]]:
        """Load Maven vulnerability data."""
        # Sample data for demonstration
        return {
            'CVE-2023-5678': [
                {
                    'cve_id': 'CVE-2023-5678',
                    'severity': 'MEDIUM',
                    'description': 'Information disclosure in logging library',
                    'references': ['https://mvnrepository.com/artifact/com.example/lib'],
                }
            ],
        }


class PrivacyTrackerDb:
    """Privacy tracker database for mobile apps."""
    
    TRACKERS = {
        'com.google.android.gms.ads.identifier': ('Google Ad ID', 'Analytics'),
        'com.facebook.sdk.Facebook': ('Facebook SDK', 'Social/Ads'),
        'com.mixpanel.mixpanel': ('Mixpanel', 'Analytics'),
    }
    
    @classmethod
    def detect_trackers(cls, components: List[Component]) -> Dict[str, Dict]:
        """Detect privacy trackers in the app."""
        detected = {}
        
        for comp in components:
            if '.jar' in comp.name or '.aar' in comp.name:
                # Check against known tracker patterns
                for pattern, (name, category) in cls.TRACKERS.items():
                    if re.search(pattern, comp.name):
                        detected[comp.name] = {
                            'tracker_name': name,
                            'category': category,
                            'component_version': comp.version,
                        }
        
        return detected


# =============================================================================
# CORE SCANNER WITH VULN MATCHING
# =============================================================================

class SbomxScanner:
    """Main scanner that orchestrates the full SBOM generation."""
    
    def __init__(self, apk_path: str, workers: int = DEFAULT_WORKERS):
        self.apk_path = Path(apk_path)
        self.workers = workers
        self.components: List[Component] = []
        self.vuln_matches: List[VulnerabilityMatch] = []
        self.trackers: Dict[str, Dict] = {}
    
    def scan(self) -> Tuple[List[Component], List[VulnerabilityMatch]]:
        """Run the full scanning pipeline."""
        
        # Step 1: Extract components from APK
        scanner = ApkScanner(str(self.apk_path))
        all_components, native_libs = scanner.scan()
        
        # Step 2: Detect SDKs
        sdk_map = SdkDetector.detect_from_components(all_components)
        
        # Deduplicate and merge
        seen = set()
        unique_components = []
        
        for comp in all_components + list(sdk_map.values()):
            key = (comp.name, comp.version, comp.purl)
            if key not in seen:
                seen.add(key)
                unique_components.append(comp)
        
        self.components = unique_components
        
        # Step 3: Load vulnerability databases and match
        vuln_dbs = [NvdVulnDb(), MavenVulnDb()]
        
        for db in vuln_dbs:
            loaded = db.load()
            
            for cve_id, vulns in loaded.items():
                # Match against components (simplified matching)
                for vuln in vul