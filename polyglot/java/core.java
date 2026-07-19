package polyglot.java.core;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Core SBOMX engine for mobile app analysis.
 * Unpacks archives, parses components, matches vulnerabilities, tracks privacy.
 */
public class SbomxCore {

    // Configuration constants
    private static final int MAX_ARCHIVE_SIZE = 500 * 1024 * 1024; // 500MB
    private static final int BUFFER_SIZE = 8192;
    private static final String DEFAULT_VULN_DB_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /**
     * Main entry point for SBOM generation.
     */
    public record SbomResult(
        List<Component> components,
        List<VulnerabilityMatch> vulnerabilities,
        PrivacyReport privacy,
        Instant timestamp
    ) {}

    /**
     * Represents a software component found in the app.
     */
    public record Component(
        String name,
        String version,
        String group,
        String type, // "library", "sdk", "native-lib"
        Map<String, Object> metadata
    ) {}

    /**
     * Represents a vulnerability match for a component.
     */
    public record VulnerabilityMatch(
        Component component,
        String cveId,
        int cvssScore,
        String severity, // "LOW", "MEDIUM", "HIGH", "CRITICAL"
        Instant publishedDate,
        String description
    ) {}

    /**
     * Represents privacy findings from the app.
     */
    public record PrivacyReport(
        List<String> permissions,
        Map<String, Integer> dataPoints, // key: data type, value: count
        List<PrivacyEndpoint> endpoints,
        Instant scanTime
    ) {
        public static class PrivacyEndpoint {
            public record Info(String path, String method, String description) {}
            
            public static PrivacyEndpoint fromPath(String path, String method) {
                return new PrivacyEndpoint(path, method, null);
            }
        }
    }

    /**
     * Main SBOMX Core Engine.
     */
    public class SbomxEngine {
        
        private final Path appPath;
        private final HttpClient httpClient = HttpClient.newHttpClient();
        private final Map<String, Component> componentCache = new ConcurrentHashMap<>();
        private final List<VulnerabilityMatch> vulnMatches = new ArrayList<>();

        public SbomxEngine(Path appPath) {
            this.appPath = appPath;
        }

        /**
         * Main analysis pipeline. Returns complete SBOM result.
         */
        public SbomResult analyze() throws IOException, InterruptedException {
            Instant start = Instant.now();
            
            // Step 1: Extract and parse components
            List<Component> components = extractComponents();
            
            // Step 2: Match against vulnerability databases
            List<VulnerabilityMatch> vulnerabilities = matchVulnerabilities(components);
            
            // Step 3: Analyze privacy aspects
            PrivacyReport privacy = analyzePrivacy();

            return new SbomResult(components, vulnerabilities, privacy, start);
        }

        /**
         * Extract components from mobile app archives.
         */
        private List<Component> extractComponents() throws IOException {
            List<Component> components = new ArrayList<>();
            
            // Try to detect archive type and extract
            if (isApk(appPath)) {
                extractAndParseApk(components);
            } else if (isIpa(appPath)) {
                extractAndParseIpa(components);
            } else {
                // Assume it's a directory with extracted files
                scanDirectoryForComponents(components);
            }

            return components;
        }

        /**
         * Detect if path is an APK file.
         */
        private boolean isApk(Path path) {
            String lower = path.getFileName().toString().toLowerCase();
            return lower.endsWith(".apk") || 
                   (path.getParent() != null && 
                    path.getParent().getFileName().toString().equals("classes.dex"));
        }

        /**
         * Detect if path is an IPA file.
         */
        private boolean isIpa(Path path) {
            String lower = path.getFileName().toString().toLowerCase();
            return lower.endsWith(".ipa") || 
                   (path.getParent() != null && 
                    path.getParent().getFileName().toString().equals("Payload"));
        }

        /**
         * Extract and parse APK contents.
         */
        private void extractAndParseApk(List<Component> components) throws IOException {
            // Create temporary extraction directory
            Path tempDir = Files.createTempDirectory("sbomx-apk-");
            
            try (ZipFile zip = new ZipFile(appPath.toFile())) {
                // Parse AndroidManifest.xml for permissions and metadata
                parseAndroidManifest(zip, components);
                
                // Scan lib directories for native libraries
                scanLibDirectories(zip, components);
                
                // Check for bundled SDKs
                checkBundledSdks(zip, components);
            } finally {
                Files.walk(tempDir)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> Files.deleteIfExists(path));
            }
        }

        /**
         * Parse AndroidManifest.xml for permissions and metadata.
         */
        private void parseAndroidManifest(ZipFile zip, List<Component> components) throws IOException {
            String manifestPath = "AndroidManifest.xml";
            
            if (zip.getEntry(manifestPath) == null) {
                return;
            }

            try (InputStream is = zip.getInputStream(zip.getEntry(manifestPath));
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                
                // Parse permissions using regex
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("<uses-permission")) {
                        Pattern pattern = Pattern.compile(
                            "<uses-permission[^>]*name=\"([^\"]+)\"[^>]*>"
                        );
                        Matcher matcher = pattern.matcher(line);
                        while (matcher.find()) {
                            components.add(new Component(
                                matcher.group(1),
                                "1.0", // Android permission versions are implicit
                                "android.permission",
                                "permission"
                            ));
                        }
                    }
                }
            }
        }

        /**
         * Scan lib directories for native libraries and SDKs.
         */
        private void scanLibDirectories(ZipFile zip, List<Component> components) throws IOException {
            String[] libPaths = {"lib/", "libs/"};
            
            for (String path : libPaths) {
                if (zip.getEntry(path + "armeabi-v7a/libc++.so") != null ||
                    zip.getEntry(path + "arm64-v8a/libc++.so") != null) {
                    
                    // Found native libs, scan for bundled SDKs
                    checkForBundledSdksInLib(zip, components);
                }
            }
        }

        /**
         * Check for common bundled SDKs in lib directories.
         */
        private void checkForBundledSdks(ZipFile zip, List<Component> components) throws IOException {
            // Common bundled SDK patterns
            String[][] sdkPatterns = {
                {"lib/", "com.google.android.gms"},      // Google Play Services
                {"lib/", "com.facebook.sdk"},            // Facebook SDK
                {"lib/", "com.twitter.android.sdk"},     // Twitter SDK
                {"lib/", "io.fabric.sdk"},               // Fabric/Flurry
                {"lib/", "com.mixpanel.android.sdk"}     // Mixpanel
            };

            for (String[] pattern : sdkPatterns) {
                String searchPath = pattern[0] + pattern[1];
                
                if (zip.getEntry(searchPath) != null ||
                    zip.getEntry("classes.dex") != null && 
                    isLikelySdk(zip, "classes.dex")) {
                    
                    components.add(new Component(
                        pattern[1],
                        detectSdkVersion(zip),
                        "",
                        "sdk"
                    ));
                }
            }
        }

        /**
         * Detect version from SDK class files.
         */
        private String detectSdkVersion(ZipFile zip) {
            // Try to read version from manifest or build config
            try (InputStream is = zip.getInputStream(zip.getEntry("AndroidManifest.xml"))) {
                if (is != null) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                    StringBuilder sb = new StringBuilder();
                    
                    while ((sb.append(reader.readLine()).append('\n').length() < 5000)) {
                        // Look for version patterns
                        String line = sb.toString().toLowerCase();
                        if (line.contains("sdkversion") || 
                            line.contains("buildconfig")) {
                            return "detected";
                        }
                    }
                }
            } catch (IOException e) {
                return "unknown";
            }
            
            return "unknown";
        }

        /**
         * Check if a class file is likely from an SDK.
         */
        private boolean isLikelySdk(ZipFile zip, String className) throws IOException {
            try (InputStream is = zip.getInputStream(zip.getEntry(className))) {
                if (is != null) {
                    byte[] buffer = new byte[1024];
                    int bytesRead = is.read(buffer);
                    
                    // Check for SDK-specific class names
                    String content = new String(buffer, 0, bytesRead);
                    return content.contains("com.google") || 
                           content.contains("com.facebook") ||
                           content.contains("io.fabric");
                }
            }
            
            return false;
        }

        /**
         * Check for bundled SDKs in lib directories.
         */
        private void checkForBundledSdksInLib(ZipFile zip, List<Component> components) throws IOException {
            // Look for common SDK jar files
            String[][] sdkJars = {
                {"lib/", "classes.jar"},
                {"lib/", "google-play-services.jar"},
                {"lib/", "facebook-sdk.jar"}
            };

            for (String[] jar : sdkJars) {
                if (zip.getEntry(jar[0] + jar[1]) != null) {
                    components.add(new Component(
                        jar[1].replace(".jar", ""),
                        "bundled",
                        "",
                        "sdk"
                    ));
                }
            }
        }

        /**
         * Scan directory for components (when already extracted).
         */
        private void scanDirectoryForComponents(List<Component> components) throws IOException {
            // Look for common SDK directories
            String[][] sdkDirs = {
                {"lib", "com.google.android.gms"},
                {"lib", "com.facebook.sdk"},
                {"libs", "classes.jar"}
            };

            for (String[] dir : sdkDirs) {
                Path libPath = appPath.resolve(dir[0]);
                
                if (Files.exists(libPath)) {
                    // Scan for jar files
                    Files.walk(libPath)
                        .filter(p -> p.getFileName().toString().endsWith(".jar"))
                        .forEach(jarPath -> {
                            String name = jarPath.getFileName().toString();
                            components.add(new Component(
                                name.replace(".jar", ""),
                                "bundled",
                                "",
                                "sdk"
                            ));
                        });
                }
            }
        }

        /**
         * Match components against vulnerability databases.
         */
        private List<VulnerabilityMatch> matchVulnerabilities(List<Component> components) {
            List<VulnerabilityMatch> matches = new ArrayList<>();
            
            // Known vulnerable versions (simplified database)
            Map<String, Map<String, VulnerabilityInfo>> vulnDb = buildVulnDatabase();
            
            for (Component comp : components) {
                if (!comp.group().isEmpty()) {
                    String key = comp.group() + ":" + comp.version();
                    
                    // Check against known vulnerabilities
                    if (vulnDb.containsKey(key)) {
                        Map<String, VulnerabilityInfo> groupVulns = vulnDb.get(key);
                        
                        for (String cve : groupVulns.keySet()) {
                            matches.add(new VulnerabilityMatch(
                                comp,
                                cve,
                                groupVulns.get(cve).cvssScore,
                                groupVulns.get(cve).severity,
                                groupVulns.get(cve).publishedDate,
                                groupVulns.get(cve).description
                            ));
                        }
                    }
                }
            }

            return matches;
        }

        /**
         * Build in-memory vulnerability database.
         */
        private Map<String, Map<String, VulnerabilityInfo>> buildVulnDatabase() {
            Map<String, Map<String, VulnerabilityInfo>> db = new HashMap<>();
            
            // Example vulnerable components (real data would be fetched from NVD)
            db.put("com.google.android.gms:18.0.0", 
                Map.of(
                    "CVE-2023-12345",
                    new VulnerabilityInfo(7.5, "HIGH", Instant.parse("2023-06-15T00:00:00Z"),
                        "Potential DoS in Google Play Services")
                ));

            db.put("com.facebook.sdk:14.0.0",
                Map.of(
                    "CVE-2023-98765",
                    new VulnerabilityInfo(6.8, "MEDIUM", Instant.parse("2023-08-20T00:00:00Z"),
                        "Information disclosure in Facebook SDK")
                ));

            return db;
        }

        /**
         * Helper class for vulnerability metadata.
         */
        private static record VulnerabilityInfo(
            int cvssScore,
            String severity,
            Instant publishedDate,
            String description
        ) {}

        /**
         * Analyze privacy aspects of the app.
         */
        private PrivacyReport analyzePrivacy() throws IOException {
            List<String> permissions = new ArrayList<>();
            Map<String, Integer> dataPoints = new HashMap<>();
            List<Privacy.PrivacyEndpoint> endpoints = new ArrayList<>();

            // Parse manifest for permissions
            if (isApk(appPath)) {
                try (ZipFile zip = new ZipFile(appPath.toFile())) {
                    String manifestContent = getManifestContent(zip);
                    
                    // Extract permissions
                    Pattern permPattern = Pattern.compile(
                        "<uses-permission[^>]*name=\"([^\"]+)\"[^>]*>"
                    );
                    Matcher matcher = permPattern.matcher(manifestContent);
                    while (matcher.find()) {
                        permissions.add(matcher.group(1));
                    }

                    // Extract data collection endpoints
                    extractDataEndpoints(zip, endpoints);
                }
            }

            return new PrivacyReport(
                permissions,
                dataPoints,
                endpoints,
                Instant.now()
            );
        }

        /**
         * Get AndroidManifest.xml content.
         */
        private String getManifestContent(ZipFile zip) throws IOException {
            try (InputStream is = zip.getInputStream(zip.getEntry("AndroidManifest.xml"))) {
                return new String(is.readAllBytes());
            }
        }

        /**
         * Extract data collection endpoints from manifest.
         */
        private void extractDataEndpoints(ZipFile zip, List<Privacy.PrivacyEndpoint> endpoints) throws IOException {
            try (InputStream is = zip.getInputStream(zip.getEntry("AndroidManifest.xml"))) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
                
                // Look for network activity indicators
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("<uses-permission") && 
                        (line.contains("INTERNET") || line.contains("ACCESS_NETWORK_STATE"))) {
                        
                        endpoints.add(Privacy.PrivacyEndpoint.fromPath(
                            "network",
                            "general"
                        ));
                    }
                    
                    // Look for specific data collection patterns
                    if (line.contains("<meta-data") && 
                        line.contains("android:name=\"com.google.android.gms.ads\"")) {
                        
                        endpoints.add(Privacy.PrivacyEndpoint.fromPath(
                            "ads",
                            "google-ads"
                        ));
                    }
                }
            }
        }

        /**
         * Check if path is an IPA file.
         */
        private boolean isIpa(Path path) {
            String lower = path.getFileName().toString().toLowerCase();
            return lower.endsWith(".ipa") || 
                   (path.getParent() != null && 
                    path.getParent().getFileName().toString().equals("Payload"));
        }

        /**
         * Extract and parse IPA contents.
         */
        private void extractAndParseIpa(List<Component> components)