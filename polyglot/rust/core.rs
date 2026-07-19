use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a parsed ELF library from the app archive.
#[derive(Debug, Clone)]
pub struct NativeLibrary {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub path_in_archive: PathBuf,
    pub dependencies: Vec<String>,
}

/// Represents a component extracted from the app.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub group: Option<String>,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub licenses: Vec<String>,
    pub purl: Option<String>,
}

/// Configuration for the SBOM generation process.
#[derive(Debug, Clone)]
pub struct SbomConfig {
    pub output_path: PathBuf,
    pub vuln_db_paths: Vec<PathBuf>,
    pub tracker_db_paths: Vec<PathBuf>,
    pub privacy_db_paths: Vec<PathBuf>,
}

impl Default for SbomConfig {
    fn default() -> Self {
        Self {
            output_path: PathBuf::from("sbom.json"),
            vuln_db_paths: vec![PathBuf::from("./vulns/cves.json")],
            tracker_db_paths: vec![],
            privacy_db_paths: vec![],
        }
    }
}

/// ELF header constants for Android native libraries.
const ELF_MAGIC: &[u8] = b"\x7fELF";
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;

/// Parse an ELF file header to extract library metadata.
pub fn parse_elf_header(path: &Path) -> Result<NativeLibrary, String> {
    let mut buffer = [0u8; 54]; // Minimum for parsing essential fields
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Failed to open ELF: {}", e)),
    };

    if file.read_exact(&mut buffer).is_err() {
        return Err("ELF header too small".to_string());
    }

    // Verify magic number
    let magic = &buffer[0..4];
    if magic != ELF_MAGIC {
        return Err(format!("Not a valid ELF: {:?}", magic));
    }

    let e_ident = &buffer[0..16];
    let ei_class = u8::from(e_ident[4]); // 2 = 32-bit, 4 = 64-bit
    let ei_data = u8::from(e_ident[5]); // 1 = little endian

    if ei_class == 4 {
        return Err("Only 32-bit ELF supported for simplicity".to_string());
    }

    let e_type = u16::from_le_bytes([e_ident[16], e_ident[17]]);
    let e_machine = u16::from_le_bytes([e_ident[18], e_ident[19]]);
    
    // Extract architecture from machine type
    let arch_map: HashMap<u16, &str> = [
        (0x002c, "arm"),      // ARM
        (0x0030, "armhf"),    // ARM hard-float
        (0x003e, "aarch64"),  // AArch64
        (0x0101, "i386"),     // Intel 80386
        (0x002d, "mips"),     // MIPS
    ];

    let arch = match e_machine {
        0x002c | 0x0030 => "arm",
        0x003e => "aarch64",
        0x0101 => "i386",
        _ => "unknown",
    };

    // Parse program headers to find library dependencies
    let e_phoff = u32::from_le_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]);
    let e_phentsize = u16::from_le_bytes([buffer[40], buffer[41]]);
    let e_phnum = u16::from_le_bytes([buffer[42], buffer[43]]);

    let mut deps: Vec<String> = vec![];

    if e_type == ET_EXEC || e_type == ET_DYN {
        for i in 0..e_phnum as usize {
            let offset = e_phoff + (i * e_phentsize as u32) as usize;
            if offset >= buffer.len() {
                break;
            }

            let p_type = u32::from_le_bytes([buffer[offset], buffer[offset+1], 
                                              buffer[offset+2], buffer[offset+3]]);
            
            // PT_INTERP contains the interpreter (usually /system/bin/app_process)
            if p_type == PT_INTERP {
                continue;
            }

            let p_offset = u64::from_le_bytes([buffer[offset+8], buffer[offset+9], 
                                                buffer[offset+10], buffer[offset+11],
                                                buffer[offset+12], buffer[offset+13],
                                                buffer[offset+14], buffer[offset+15]]);
            let p_filesz = u64::from_le_bytes([buffer[offset+28], buffer[offset+29], 
                                                buffer[offset+30], buffer[offset+31],
                                                buffer[offset+32], buffer[offset+33],
                                                buffer[offset+34], buffer[offset+35]]);

            if p_type == PT_LOAD && p_filesz > 0 {
                let interp_offset = e_phoff + (e_phentsize as u32) as usize;
                let mut interp_buf = [0u8; 64];
                
                if interp_offset < buffer.len() {
                    let interp_len = std::cmp::min(64, buffer[interp_offset..].len());
                    let interp_path: String = buffer[interp_offset..interp_offset+interp_len]
                        .iter().filter(|b| **b > 0).map(|&b| b as char)
                        .collect();
                    
                    if !interp_path.is_empty() && interp_path != "/" {
                        // Extract shared library dependencies from interpreter path
                        let lib_name = Path::new(&interp_path)
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown");
                        
                        deps.push(lib_name.to_string());
                    }
                }
            }
        }
    }

    // Extract version from filename if available
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let version = extract_version_from_filename(filename);

    Ok(NativeLibrary {
        name: Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string(),
        version,
        arch: arch.to_string(),
        path_in_archive: path.to_path_buf(),
        dependencies: deps,
    })
}

fn extract_version_from_filename(filename: &str) -> String {
    // Try to extract version from patterns like "libfoo.so.1.2.3" or "libfoo.so.1"
    if let Some(pos) = filename.rfind('.') {
        let after_dot = &filename[pos + 1..];
        
        // Check if it looks like a version number (contains digits and dots/hyphens)
        if after_dot.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '_') {
            return after_dot.to_string();
        }
    }

    // Default: use filename without extension
    let stem = Path::new(filename).file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if !stem.is_empty() && stem != "lib" {
        return stem.to_string();
    }

    "unknown".to_string()
}

/// Parse Android manifest to extract Gradle dependencies.
pub fn parse_android_manifest(manifest_path: &Path) -> Result<Vec<ComponentInfo>, String> {
    let content = fs::read_to_string(manifest_path).map_err(|e| format!("Read error: {}", e))?;

    // Simple regex-based parsing for common AndroidX/Gradle patterns
    let mut components: Vec<ComponentInfo> = vec![];

    // Pattern 1: AndroidX dependencies (implementation, apiOnly, etc.)
    if let Some(androidx_matches) = content.match_indices("androidx.") {
        let start = androidx_matches.0;
        let end = content[start..].find(']').unwrap_or(content.len());
        
        let snippet = &content[start..start + end];
        // Extract group and name from "group:artifact" format
        if let Some(colon_pos) = snippet.find(':') {
            let group = snippet[..colon_pos].trim();
            let artifact = snippet[colon_pos + 1..end - 2].trim();
            
            components.push(ComponentInfo {
                group: Some(group.to_string()),
                name: artifact.to_string(),
                version: "unknown".to_string(), // Would need more parsing for exact version
                description: None,
                licenses: vec!["Apache-2.0".to_string()],
                purl: format!("androidx/{}", artifact),
            });
        }
    }

    // Pattern 2: Gradle dependencies in build.gradle files
    if let Some(gradle_matches) = content.match_indices("implementation \"") {
        let start = gradle_matches.0;
        let end = content[start..].find('"').unwrap_or(content.len());
        
        let snippet = &content[start + 15..start + end]; // Skip "implementation \""
        
        if let Some(colon_pos) = snippet.find(':') {
            let group = snippet[..colon_pos].trim();
            let artifact = snippet[colon_pos + 1..end - 2].trim();
            
            components.push(ComponentInfo {
                group: Some(group.to_string()),
                name: artifact.to_string(),
                version: "unknown".to_string(),
                description: None,
                licenses: vec!["Apache-2.0".to_string()],
                purl: format!("gradle/{}", artifact),
            });
        }
    }

    // Pattern 3: Common Android SDK components with known versions
    let sdk_components = [
        ("androidx.core:core-ktx", "1.9.0"),
        ("androidx.appcompat:appcompat", "1.6.1"),
        ("com.google.android.material:material", "1.8.0"),
        ("org.jetbrains.kotlin:kotlin-stdlib", "1.9.0"),
    ];

    for (name, version) in sdk_components.iter() {
        if content.contains(name) && !content.contains(&format!("{}\"", name)) {
            components.push(ComponentInfo {
                group: Some("androidx".to_string()),
                name: name.replace(':', '/').replace('.', '_').to_string(),
                version: version.to_string(),
                description: None,
                licenses: vec!["Apache-2.0".to_string()],
                purl: format!("androidx/{}", name),
            });
        }
    }

    Ok(components)
}

/// Parse iOS bundle to extract framework and library information.
pub fn parse_ios_bundle(bundle_path: &Path) -> Result<Vec<NativeLibrary>, String> {
    let mut libraries = vec![];

    // Check for Mach-O headers in the app directory
    if bundle_path.exists() {
        let entries = fs::read_dir(bundle_path)?;
        
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.extension().map_or(false, |e| e == "dylib") ||
               path.extension().map_or(false, |e| e == "framework") {
                
                // Try to parse as Mach-O (simplified)
                match parse_macho_header(&path) {
                    Ok(lib) => libraries.push(lib),
                    Err(_) => {}
                }
            } else if path.is_file() && path.extension().map_or(false, |e| e == "tbd") {
                // Thin Binary Description file
                let content = fs::read_to_string(&path)?;
                
                for line in content.lines() {
                    if let Some(lib_name) = line.strip_prefix("lib:") {
                        libraries.push(NativeLibrary {
                            name: lib_name.to_string(),
                            version: "unknown".to_string(),
                            arch: "universal".to_string(),
                            path_in_archive: path,
                            dependencies: vec![],
                        });
                    }
                }
            }
        }
    }

    Ok(libraries)
}

fn parse_macho_header(path: &Path) -> Result<NativeLibrary, String> {
    let mut buffer = [0u8; 26]; // Minimum Mach-O header
    
    if let Ok(mut file) = File::open(path) {
        if file.read_exact(&mut buffer).is_ok() {
            // Check magic number (32-bit: 0xfeedface, 64-bit: 0xfeedfacf)
            let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
            
            if magic == 0xfeedface || magic == 0xfeedfacf {
                // Valid Mach-O header
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                
                let version = extract_macho_version(filename);
                
                Ok(NativeLibrary {
                    name: Path::new(path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    version,
                    arch: "universal".to_string(), // Simplified for now
                    path_in_archive: path.to_path_buf(),
                    dependencies: vec![],
                })
            } else {
                Ok(NativeLibrary {
                    name: filename.to_string(),
                    version: "unknown".to_string(),
                    arch: "universal".to_string(),
                    path_in_archive: path.to_path_buf(),
                    dependencies: vec![],
                })
            }
        } else {
            Err("Failed to read Mach-O header".into())
        }
    } else {
        Err(format!("Failed to open file: {:?}", path.display()))
    }
}

fn extract_macho_version(filename: &str) -> String {
    // Try to extract version from filename patterns
    if let Some(pos) = filename.rfind('.') {
        let after_dot = &filename[pos + 1..];
        
        if after_dot.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '_') {
            return after_dot.to_string();
        }
    }

    "unknown".to_string()
}

/// Main analysis function that orchestrates the SBOM generation.
pub fn analyze_app(
    app_path: &Path,
    config: &SbomConfig,
) -> Result<SbomResult, String> {
    let mut components = Vec::new();
    let mut libraries = Vec::new();

    // 1. Parse APK/IPA structure
    if app_path.extension().map_or(false, |e| e == "apk") || 
       app_path.extension().map_or(false, |e| e == "ipa") {
        
        // Extract native libraries from the archive
        let extracted_dir = PathBuf::from(format!("{}.extracted", app_path.file_name()
            .unwrap_or_default()));
        
        if fs::create_dir_all(&extracted_dir).is_ok() {
            // For APK, extract lib directory
            let lib_dir = extracted_dir.join("lib");
            
            if lib_dir.exists() {
                for arch in ["armeabi-v7a", "arm64-v8a", "x86_64"] {
                    let arch_libs = lib_dir.join(arch);
                    
                    if arch_libs.exists() {
                        for entry in fs::read_dir(&arch_libs).unwrap_or_default().flatten() {
                            if let Ok(lib_path) = entry.path() {
                                if let Ok(lib) = parse_elf_header(&lib_path) {
                                    libraries.push(lib);
                                }
                            }
                        }
                    }
                }
            }