#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <filesystem>
#include <cstring>

namespace fs = std::filesystem;

// ============================================================================
// Data Structures
// ============================================================================

struct Component {
    std::string name;
    std::string version;
    std::string hash;
    std::string source;
    std::string type; // "native", "sdk", "framework"
    
    bool operator<(const Component& other) const {
        if (name != other.name) return name < other.name;
        return version < other.version;
    }
};

struct Vulnerability {
    std::string cve_id;
    double cvss_score;
    std::string affected_version_min;
    std::string affected_version_max;
    std::string description;
    std::string fix_version;
    
    bool affects(const Component& comp) const {
        if (comp.name != name()) return false;
        
        auto min = parseVersion(affected_version_min);
        auto max = parseVersion(affected_version_max);
        auto curr = parseVersion(comp.version);
        
        // Check if current version falls within affected range
        return !min.empty() && !max.empty() && 
               (curr >= min || min.empty()) && 
               (curr <= max || max.empty());
    }
    
private:
    static Component name() { return {cve_id, "0.0", "", "", ""}; }
    
    double parseVersion(const std::string& v) const {
        try {
            // Simple version parser - handles X.Y.Z format
            size_t dot1 = v.find('.');
            if (dot1 == std::string::npos || dot1 + 1 >= v.size()) return 0.0;
            
            double major = std::stod(v.substr(0, dot1));
            size_t dot2 = v.find('.', dot1 + 1);
            if (dot2 != std::string::npos) {
                double minor = std::stod(v.substr(dot1 + 1, dot2 - dot1 - 1));
                return major * 100.0 + minor;
            }
            return major;
        } catch (...) {
            return 0.0;
        }
    }
};

struct PrivacyEntry {
    std::string permission;
    std::string data_type;
    std::string purpose;
    bool is_critical;
    
    static const std::vector<std::string> CRITICAL_PERMISSIONS = {
        "READ_CONTACTS", "READ_SMS", "RECEIVE_SMS", 
        "CAMERA", "MICROPHONE", "LOCATION_ALWAYS"
    };
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), 
                   [](unsigned char c){ return std::tolower(c); });
    return result;
}

// Simple SHA256 implementation for library identification
class SHA256 {
public:
    static std::string compute(const std::string& data) {
        // Fallback to simple hash if full SHA256 is too verbose
        // In production, use OpenSSL or boost::uuid
        size_t h = 0;
        for (char c : data) {
            h = ((h << 5) + h) ^ static_cast<unsigned char>(c);
        }
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(16) << h;
        return ss.str();
    }
};

// ============================================================================
// Archive Extractor
// ============================================================================

class ArchiveExtractor {
public:
    static bool extractNativeLibs(const fs::path& appPath, 
                                   const fs::path& outputDir) {
        try {
            // Common native library locations in Android apps
            std::vector<fs::path> searchPaths = {
                outputDir / "lib",
                outputDir / "libs",
                outputDir / "arm64-v8a",
                outputDir / "armeabi-v7a"
            };
            
            for (const auto& path : searchPaths) {
                if (fs::exists(path)) {
                    // Find .so files
                    for (auto& entry : fs::directory_iterator(path)) {
                        if (entry.is_regular_file()) {
                            std::string ext = toLower(entry.path().extension());
                            if (ext == ".so") {
                                Component comp;
                                comp.name = entry.path().stem();
                                comp.type = "native";
                                comp.hash = SHA256::compute(
                                    entry.path().string() + 
                                    entry.file_size().to_string());
                                
                                // Extract version from filename if present
                                std::string verStr;
                                auto pos = entry.path().stem().find('.');
                                if (pos != std::string::npos) {
                                    verStr = entry.path().stem().substr(pos + 1);
                                    comp.version = "0." + verStr;
                                } else {
                                    comp.version = "unknown";
                                }
                                
                                // Add to components list
                                return true; 
                            }
                        }
                    }
                }
            }
        } catch (...) {
            std::cerr << "Warning: Error extracting native libs" << std::endl;
        }
        
        return false;
    }
    
    static bool extractSDKs(const fs::path& appPath, 
                           const fs::path& outputDir) {
        try {
            // Look for common SDK directories
            std::vector<std::string> sdkDirs = {
                "com.google.android.gms",  // Google Play Services
                "com.facebook.android",    // Facebook SDK
                "com.mixpanel.android",    // Mixpanel
                "com.segment.analytics"    // Segment
            };
            
            for (const auto& dirName : sdkDirs) {
                fs::path searchPath = outputDir / dirName;
                if (fs::exists(searchPath)) {
                    Component comp;
                    comp.name = dirName;
                    comp.type = "sdk";
                    comp.version = "unknown";
                    
                    // Try to find version file or manifest
                    auto verFile = searchPath / "version.txt";
                    auto manifest = searchPath / "AndroidManifest.xml";
                    
                    if (fs::exists(verFile)) {
                        std::string content;
                        for (auto& line : fs::directory_iterator(verFile)) {
                            content += trim(line.path().load_string());
                        }
                        comp.version = extractVersion(content);
                    } else if (fs::exists(manifest)) {
                        comp.version = "1.0"; // Default for manifest-based SDKs
                    }
                    
                    return true;
                }
            }
        } catch (...) {
            std::cerr << "Warning: Error extracting SDKs" << std::endl;
        }
        
        return false;
    }
    
private:
    static std::string extractVersion(const std::string& content) {
        // Look for common version patterns
        std::regex verRegex(R"(version\s*=\s*["']?(\d+\.\d+[\.\d]*)["']?)");
        std::smatch match;
        
        if (std::regex_search(content, match, verRegex)) {
            return match[1].str();
        }
        
        // Fallback: search for any version-like string
        std::regex fallback(R"(\d+\.\d+[\.\d]*)");
        auto it = std::sregex_iterator(content.begin(), content.end(), fallback);
        if (it != std::sregex_iterator()) {
            return (*it).str();
        }
        
        return "unknown";
    }
};

// ============================================================================
// Vulnerability Matcher
// ============================================================================

class VulnerabilityMatcher {
public:
    // Sample vulnerability database - in production, load from file/API
    static std::vector<Vulnerability> getKnownVulns() {
        return {
            {{"CVE-2023-12345", 7.5, "1.0.0", "2.5.0", 
               "Remote code execution in vulnerable library", "2.6.0"}},
            {{"CVE-2023-98765", 4.2, "3.0.0", "4.0.0",
               "Information disclosure vulnerability", "4.1.0"}},
            {{"CVE-2023-11111", 8.1, "0.9.0", "1.5.0",
               "Denial of service via crafted input", "1.6.0"}}
        };
    }
    
    static std::vector<Vulnerability> matchComponents(
            const std::vector<Component>& components) {
        
        auto knownVulns = getKnownVulns();
        std::vector<Vulnerability> found;
        
        for (const auto& vuln : knownVulns) {
            // Check if any component is affected
            for (const auto& comp : components) {
                if (vuln.affects(comp)) {
                    // Avoid duplicates
                    bool exists = false;
                    for (auto& f : found) {
                        if (f.cve_id == vuln.cve_id) {
                            exists = true;
                            break;
                        }
                    }
                    
                    if (!exists) {
                        found.push_back(vuln);
                    }
                }
            }
        }
        
        return found;
    }
};

// ============================================================================
// Privacy Tracker
// ============================================================================

class PrivacyTracker {
public:
    static std::vector<PrivacyEntry> getKnownPermissions() {
        // Sample privacy-sensitive permissions
        return {
            {"READ_CONTACTS", "contact_data", "Social features", true},
            {"READ_SMS", "sms_content", "Messaging features", true},
            {"CAMERA", "image_data", "Photo capture", false},
            {"LOCATION_ALWAYS", "geolocation", "Location services", true}
        };
    }
    
    static std::vector<PrivacyEntry> matchPermissions(
            const std::string& manifestPath) {
        
        auto knownPerms = getKnownPermissions();
        std::vector<PrivacyEntry> found;
        
        try {
            if (!fs::exists(manifestPath)) {
                return found;
            }
            
            // Simple pattern matching for permissions
            std::regex permRegex(R"(permission\s+(READ_CONTACTS|READ_SMS|CAMERA|"MICROPHONE)"");");
            std::smatch match;
            
            while (std::regex_search(manifestPath, match, permRegex)) {
                std::string perm = match[1].str();
                
                // Find matching known permission
                for (auto& entry : knownPerms) {
                    if (entry.permission == perm || 
                        entry.permission.find(perm) != std::string::npos) {
                        
                        PrivacyEntry foundEntry;
                        foundEntry.permission = perm;
                        foundEntry.is_critical = entry.is_critical;
                        
                        // Determine data type and purpose from known list
                        for (const auto& k : knownPerms) {
                            if (k.permission == perm) {
                                foundEntry.data_type = k.data_type;
                                foundEntry.purpose = k.purpose;
                                break;
                            }
                        }
                        
                        found.push_back(foundEntry);
                    }
                }
            }
        } catch (...) {
            // Continue even if parsing fails
        }
        
        return found;
    }
};

// ============================================================================
// SBOM Generator (CycloneDX 1.4)
// ============================================================================

class CycloneDXGenerator {
public:
    static std::string generate(const std::vector<Component>& components,
                                const std::vector<Vulnerability>& vulns,
                                const std::vector<PrivacyEntry>& privacies) {
        
        // Build component list JSON
        std::stringstream compJson;
        compJson << "  <components>";
        for (const auto& comp : components) {
            compJson << "\n    <component>\n";
            compJson << "      <name>" << escape(comp.name) << "</name>\n";
            compJson << "      <version>" << escape(comp.version) << "</version>\n";
            compJson << "      <type>library</type>\n";
            if (!comp.hash.empty()) {
                compJson << "      <hash><sha256>" << escape(comp.hash) 
                         << "</sha256></hash>\n";
            }
            compJson << "    </component>";
        }
        compJson << "\n  </components>";
        
        // Build vulnerabilities JSON
        std::stringstream vulnJson;
        vulnJson << "  <dependencies>";
        for (const auto& vuln : vulns) {
            vulnJson << "\n    <dependency>\n";
            vulnJson << "      <refType>component</refType>\n";
            vulnJson << "      <name>" << escape(vuln.cve_id) << "</name>\n";
            vulnJson << "      <version>" << std::fixed << std::setprecision(1) 
                     << vuln.cvss_score << "</version>\n";
            vulnJson << "    </dependency>";
        }
        vulnJson << "\n  </dependencies>";
        
        // Build privacy JSON
        std::stringstream privJson;
        privJson << "  <privacy>\"<privacies>";
        for (const auto& priv : privacies) {
            privJson << "\n    <permission>\n";
            privJson << "      <name>" << escape(priv.permission) 
                     << "</name>\n";
            privJson << "      <type>\"" << escape(priv.data_type) 
                     << "\"</type>\n";
            privJson << "      <critical>" << (priv.is_critical ? "true" : "false") 
                     << "</critical>\n";
            privJson << "    </permission>";
        }
        privJson << "\n  </privacy>\"";
        
        // Build complete SBOM JSON
        std::stringstream sbom;
        sbom << "{\n";
        sbom << "  \"$schema\": \"http://cyclonedx.org/schema/bom-1.4.json\",\n";
        sbom << "  \"metadata\": {\n";
        sbom << "    \"tools\": [\n";
        sbom << "      {\"name\": \"sbomx\", \"version\": \"1.0.0\"}\n";
        sbom << "    ]\n";
        sbom << "  },\n";
        sbom << "  \"components\": [\n" << compJson.str() << "\n    ],\n";
        sbom << "  \"vulnerabilities\": [\n" << vulnJson.str() << "\n    ]\n";
        sbom << "}" << std::endl;
        
        return sbom.str();
    }
    
private:
    static std::string escape(const std::string& str) {
        std::string result = "\"" + str + "\"";
        // Escape special JSON characters
        for (char c : result) {
            if (c == '"') result.insert(result.end(), "\\\"");
            else if (c == '\\') result.insert(result.end(), "\\\\");
            else if (c == '\n') result.insert(result.end(), "\\n");
            else if (c == '\r') result.insert(result.end(), "\\r");
            else if (c == '\t') result.insert(result.end(), "\\t");
        }
        return result;
    }
};

// ============================================================================
// Main Entry Point with Demo
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "=== sbomx Core Module ===" << std::endl;
    std::cout