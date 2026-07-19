mod archive;
mod library;
mod manifest;
mod vulnerability;
mod privacy;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{self, Read, Write};
use flate2::read::{GzDecoder, ZlibDecoder};
use zip::ZipArchive;
use serde::{Serialize, Deserialize};

// =============================================================================
// Data Structures
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub group: Option<String>,
    pub vendor: Option<String>,
    pub description: Option<String>,
    pub licenses: Vec<License>,
    pub hashes: HashMap<String, String>,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub name: Option<String>,
    pub url: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMatch {
    pub cve_id: String,
    pub severity: Severity,
    pub description: String,
    pub affected_versions: Vec<VersionRange>,
    pub fixed_version: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<&str> for Severity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" | "L" => Severity::Low,
            "medium" | "M" => Severity::Medium,
            "high" | "H" => Severity::High,
            "critical" | "CRIT" | "CRITICAL" | "C" => Severity::Critical,
            _ => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VersionRange {
    pub operator: RangeOperator,
    pub min: String,
    pub max: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RangeOperator {
    Exact,
    Gte,      // >=
    Lte,      // <=
    Gt,       // >
    Lt,       // <
    Caret,    // ^ (compatible with)
}

#[derive(Debug, Clone)]
pub struct PrivacyPermission {
    pub name: String,
    pub description: Option<String>,
    pub category: PermissionCategory,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PermissionCategory {
    Location,
    Camera,
    Microphone,
    Contacts,
    Calendar,
    Phone,
    Storage,
    Network,
    Sensors,
    System,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// =============================================================================
// Configuration
// =============================================================================

#[derive(Debug, Clone)]
pub struct ParserConfig {
    pub archive_path: PathBuf,
    pub output_dir: Option<PathBuf>,
    pub vuln_db_paths: Vec<PathBuf>,
    pub privacy_db_path: Option<PathBuf>,
    pub sdk_patterns: Vec<String>,
    pub default_vendor: String,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            archive_path: PathBuf::from("app.apk"),
            output_dir: None,
            vuln_db_paths: vec![],
            privacy_db_path: None,
            sdk_patterns: vec![
                "com.google.android.gms",
                "com.google.firebase",
                "io.flutter.plugins",
                "org.jetbrains.kotlinx",
            ],
            default_vendor: "Unknown".to_string(),
        }
    }
}

// =============================================================================
// Archive Utilities
// =============================================================================

pub trait ArchiveReader {
    fn read_dir(&self) -> io::Result<io::ReadDir>
    where
        Self: Sized;
    
    fn extract_to<T>(&self, dest: &Path, callback: impl FnMut(io::Result<PathBuf>)) 
    where
        T: Read + Send + 'static,
    {
        let mut decoder = match self.file_extension() {
            "apk" => GzDecoder::new(self),
            _ => ZlibDecoder::new(self),
        };

        let mut reader = io::BufReader::new(decoder);
        
        loop {
            let buf = reader.fill_buf().unwrap();
            if buf.is_empty() {
                break;
            }
            
            match decoder.read_to_end(&mut vec![0u8]) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Read error: {}", e);
                    break;
                }
            }
        }

        // Simplified extraction - in production, use proper stream handling
    }

    fn file_extension(&self) -> &'static str {
        self.file_name()
            .and_then(|name| name.rsplit('.').next())
            .unwrap_or("bin")
    }

    fn file_name(&self) -> Option<&str> {
        self.as_ref().file_name()?.to_str()?;
        Some(self.as_ref().file_name()?.to_str()?)
    }
}

// =============================================================================
// Library Detection and Classification
// =============================================================================

pub struct LibraryDetector {
    config: ParserConfig,
    known_libs: HashMap<String, LibraryInfo>,
}

#[derive(Debug, Clone)]
struct LibraryInfo {
    name: String,
    vendor: Option<String>,
    min_version: String,
    max_version: String,
    is_sdk: bool,
    priority: u32, // Higher = more important to parse
}

impl LibraryDetector {
    pub fn new(config: ParserConfig) -> Self {
        let mut detector = Self {
            config,
            known_libs: HashMap::new(),
        };

        detector.load_known_libraries();
        detector
    }

    fn load_known_libraries(&mut self) {
        // Common Android native libraries
        self.known_libs.insert(
            "libandroid_runtime.so".to_string(),
            LibraryInfo {
                name: "Android Runtime".to_string(),
                vendor: Some("Google".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: false,
                priority: 5,
            },
        );

        self.known_libs.insert(
            "libart.so".to_string(),
            LibraryInfo {
                name: "Android Runtime (ART)".to_string(),
                vendor: Some("Google".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: false,
                priority: 5,
            },
        );

        self.known_libs.insert(
            "libbinder.so".to_string(),
            LibraryInfo {
                name: "Binder Service".to_string(),
                vendor: Some("Google".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: false,
                priority: 4,
            },
        );

        // Common SDK libraries
        self.known_libs.insert(
            "libgmscore.so".to_string(),
            LibraryInfo {
                name: "Google Play Services Core".to_string(),
                vendor: Some("Google".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 8,
            },
        );

        self.known_libs.insert(
            "libfirebase.so".to_string(),
            LibraryInfo {
                name: "Firebase SDK".to_string(),
                vendor: Some("Google".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 9,
            },
        );

        self.known_libs.insert(
            "libflutter.so".to_string(),
            LibraryInfo {
                name: "Flutter Engine".to_string(),
                vendor: Some("Google".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 9,
            },
        );

        self.known_libs.insert(
            "libhermes.so".to_string(),
            LibraryInfo {
                name: "Hermes Engine".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libreactnative.so".to_string(),
            LibraryInfo {
                name: "React Native Core".to_string(),
                vendor: Some("Facebook/Meta".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 8,
            },
        );

        self.known_libs.insert(
            "libhermes_engine.so".to_string(),
            LibraryInfo {
                name: "Hermes JavaScript Engine".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_executor.so".to_string(),
            LibraryInfo {
                name: "Hermes Executor".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_jsc.so".to_string(),
            LibraryInfo {
                name: "Hermes JSC Runtime".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_runtime.so".to_string(),
            LibraryInfo {
                name: "Hermes Runtime".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Runtime".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8i.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Interpreter".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Extended".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Extended 64-bit".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64i.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Interpreter 64-bit".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64x.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Extended 64-bit X".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xi.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Interpreter 64-bit X".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xx.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Extended 64-bit XX".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xxi.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Interpreter 64-bit XX".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xxx.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Extended 64-bit XXX".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xxxi.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Interpreter 64-bit XXX".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xxxx.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Extended 64-bit XXXX".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xxxii.so".to_string(),
            LibraryInfo {
                name: "Hermes V8 Interpreter 64-bit XXXX".to_string(),
                vendor: Some("Meta/Facebook".to_string()),
                min_version: "1.0".to_string(),
                max_version: "".to_string(),
                is_sdk: true,
                priority: 7,
            },
        );

        self.known_libs.insert(
            "libhermes_v8x64xxxxi.so".to