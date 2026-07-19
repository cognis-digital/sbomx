using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace sbomx.core
{
    // =====================================================================
    // Result<T> - Functional error handling pattern
    // =====================================================================
    internal static class ResultExtensions
    {
        public static async Task<Result<T>> MapAsync<T, U>(this Result<T> result, Func<T, Task<U>> func)
        {
            if (result.IsError) return Result.Error(result.Error);
            var value = await func(result.Value).ConfigureAwait(false);
            return Result.Ok(value);
        }

        public static async Task<Result<T>> MapAsync<T, U>(this Result<T> result, Func<T, U> func)
        {
            if (result.IsError) return Result.Error(result.Error);
            var value = func(result.Value);
            return Result.Ok(value);
        }

        public static T UnwrapOrThrow<T>(this Result<T> result, string errorMessage = null)
        {
            if (result.IsError) throw new InvalidOperationException(errorMessage ?? $"Result was error: {result.Error}");
            return result.Value;
        }
    }

    internal record struct Result<T>(T Value, bool IsError = false, string? Error = null);

    // =====================================================================
    // Configuration and Constants
    // =====================================================================
    internal static class Config
    {
        public const int DefaultMaxThreads = 4;
        public const int ApkManifestTimeoutMs = 5000;
        public const string CycloneDxSchemaVersion = "1.6";
        
        // Known SDK signatures (hash -> component info)
        internal static readonly Dictionary<string, SdkInfo> KnownSdks = new()
        {
            { 
                "com.android.sdk:core", 
                new SdkInfo("Android SDK Core", "28.0.3", "https://developer.android.com/sdk")
            },
            {
                "org.jetbrains.kotlin:kotlin-stdlib",
                new SdkInfo("Kotlin Stdlib", "1.9.20", "https://kotlinlang.org/")
            }
        };

        // Known library signatures for native matching
        internal static readonly Dictionary<string, LibraryInfo> KnownLibraries = new()
        {
            { 
                "libcurl.so", 
                new LibraryInfo("libcurl", "7.84.0", "https://curl.se/", 12345) // CVE-2023-XXXXX
            },
            {
                "libsqlite3.so",
                new LibraryInfo("SQLite", "3.44.0", "https://www.sqlite.org/", 67890)
            }
        };

        public static int GetMaxThreads() => Environment.ProcessorCount > DefaultMaxThreads 
            ? DefaultMaxThreads 
            : Environment.ProcessorCount;
    }

    // =====================================================================
    // Data Models - Immutable Records
    // =====================================================================
    internal record SdkInfo(string Name, string Version, string Url);

    internal record LibraryInfo(
        string Name, 
        string Version, 
        string Url, 
        int? KnownCveId = null
    );

    internal record NativeLibrary(
        string Path,
        string HashMd5,
        string? MatchedName,
        string? MatchedVersion,
        LibraryInfo? MatchedLib
    );

    internal record SdkComponent(
        string Name,
        string Version,
        string Group = "",
        string Url = ""
    );

    // =====================================================================
    // APK/IPA Archive Handler
    // =====================================================================
    internal static class ArchiveHandler
    {
        public static async Task<Result<ArchiveInfo>> ExtractMetadataAsync(
            string archivePath, 
            CancellationToken ct)
        {
            try
            {
                var extension = Path.GetExtension(archivePath).ToLowerInvariant();
                
                if (extension == ".apk")
                    return await ExtractApkMetadataAsync(archivePath, ct);
                else if (extension == ".ipa")
                    return await ExtractIpaMetadataAsync(archivePath, ct);
                else
                    return Result.Error($"Unsupported archive format: {extension}");
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                return Result.Error(ex.Message);
            }
        }

        private static async Task<Result<ArchiveInfo>> ExtractApkMetadataAsync(
            string path, 
            CancellationToken ct)
        {
            var manifestPath = Path.Combine(path, "AndroidManifest.xml");
            
            if (!File.Exists(manifestPath))
                return Result.Error("No AndroidManifest.xml found in APK");

            try
            {
                using var reader = new StreamReader(manifestPath);
                var content = await reader.ReadToEndAsync(ct).ConfigureAwait(false);
                
                // Parse manifest - simplified for self-contained demo
                var appData = ParseAndroidManifest(content);
                
                if (string.IsNullOrEmpty(appData.PackageName))
                    return Result.Error("Empty or invalid package name in manifest");

                ct.ThrowIfCancellationRequested();

                return Result.Ok(new ArchiveInfo(
                    Path.GetFileName(path),
                    "apk",
                    appData.PackageName,
                    appData.DisplayName ?? path,
                    appData.VersionName,
                    content
                ));
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                return Result.Error($"Manifest parse error: {ex.Message}");
            }
        }

        private static async Task<Result<ArchiveInfo>> ExtractIpaMetadataAsync(
            string path, 
            CancellationToken ct)
        {
            // IPA is ZIP-based with plist metadata
            var infoPlistPath = Path.Combine(path, "Payload", $"{Path.GetFileNameWithoutExtension(path)}.app", "Info.plist");
            
            if (!File.Exists(infoPlistPath))
                return Result.Error("No Info.plist found in IPA");

            try
            {
                using var reader = new StreamReader(infoPlistPath);
                var content = await reader.ReadToEndAsync(ct).ConfigureAwait(false);
                
                // Simplified plist parsing - extract CFBundleIdentifier and CFBundleShortVersionString
                var appData = ParseInfoPlist(content);
                
                if (string.IsNullOrEmpty(appData.BundleId))
                    return Result.Error("Empty or invalid bundle ID in Info.plist");

                ct.ThrowIfCancellationRequested();

                return Result.Ok(new ArchiveInfo(
                    Path.GetFileName(path),
                    "ipa",
                    appData.BundleId,
                    appData.DisplayName ?? path,
                    appData.Version,
                    content
                ));
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                return Result.Error($"Plist parse error: {ex.Message}");
            }
        }

        private static AndroidManifestData ParseAndroidManifest(string xml)
        {
            var data = new AndroidManifestData();

            // Extract package name
            var pkgMatch = System.Text.RegularExpressions.Regex.Match(xml, 
                @"<manifest\s+[^>]*package=""([^""]+)""");
            if (pkgMatch.Success)
                data.PackageName = pkgMatch.Groups[1].Value;

            // Extract display name
            var nameMatch = System.Text.RegularExpressions.Regex.Match(xml, 
                @"<string\s+name=""com\.android\.title""[^>]*>([^<]+)</string>");
            if (nameMatch.Success)
                data.DisplayName = nameMatch.Groups[1].Value;

            // Extract version
            var verNameMatch = System.Text.RegularExpressions.Regex.Match(xml, 
                @"<string\s+name=""com\.android\.version""[^>]*>([^<]+)</string>");
            if (verNameMatch.Success)
                data.VersionName = verNameMatch.Groups[1].Value;

            return data;
        }

        private static AppPlistData ParseInfoPlist(string plist)
        {
            var data = new AppPlistData();

            // Extract bundle ID
            var idMatch = System.Text.RegularExpressions.Regex.Match(plist, 
                @"<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>");
            if (idMatch.Success)
                data.BundleId = idMatch.Groups[1].Value;

            // Extract display name
            var displayNameMatch = System.Text.RegularExpressions.Regex.Match(plist, 
                @"<key>CFBundleDisplayName</key>\s*<string>([^<]+)</string>");
            if (displayNameMatch.Success)
                data.DisplayName = displayNameMatch.Groups[1].Value;

            // Extract version
            var verMatch = System.Text.RegularExpressions.Regex.Match(plist, 
                @"<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>");
            if (verMatch.Success)
                data.Version = verMatch.Groups[1].Value;

            return data;
        }

        public static async Task<Result<List<string>>> ExtractNativeLibrariesAsync(
            string archivePath, 
            ArchiveInfo info, 
            CancellationToken ct)
        {
            var libs = new List<NativeLibrary>();
            
            // APK: extract from lib/armeabi-v7a/, lib/arm64-v8a/, etc.
            if (info.Format == "apk")
            {
                var archDirs = new[] 
                { 
                    "lib/arm64-v8a", 
                    "lib/armeabi-v7a", 
                    "lib/x86_64", 
                    "lib/x86" 
                };

                foreach (var arch in archDirs)
                {
                    var libDir = Path.Combine(archivePath, arch);
                    if (!Directory.Exists(libDir)) continue;

                    ct.ThrowIfCancellationRequested();

                    foreach (var file in Directory.GetFiles(libDir, "*.so"))
                    {
                        var hash = ComputeFileHash(file, "MD5");
                        
                        // Try to match against known libraries
                        var matchedInfo = MatchKnownLibrary(file);
                        
                        libs.Add(new NativeLibrary(
                            Path.GetFileName(file),
                            hash,
                            matchedInfo?.Name,
                            matchedInfo?.Version,
                            matchedInfo
                        ));
                    }
                }
            }

            // IPA: extract from Payload/<app>.app/Frameworks/ or similar
            if (info.Format == "ipa")
            {
                var payloadPath = Path.Combine(archivePath, "Payload");
                if (!Directory.Exists(payloadPath)) return libs;

                foreach (var appDir in Directory.EnumerateDirectories(payloadPath))
                {
                    var frameworksDir = Path.Combine(appDir, "Frameworks");
                    if (!Directory.Exists(frameworksDir)) continue;

                    ct.ThrowIfCancellationRequested();

                    foreach (var file in Directory.GetFiles(frameworksDir, "*.dylib"))
                    {
                        var hash = ComputeFileHash(file, "MD5");
                        
                        // IPA dylibs are harder to match - use filename as fallback
                        var matchedInfo = MatchKnownLibrary(file);
                        
                        libs.Add(new NativeLibrary(
                            Path.GetFileName(file),
                            hash,
                            matchedInfo?.Name,
                            matchedInfo?.Version,
                            matchedInfo
                        ));
                    }
                }
            }

            return Result.Ok(libs);
        }

        private static string ComputeFileHash(string path, string algorithm)
        {
            using var sha = algorithm switch
            {
                "MD5" => System.Security.Cryptography.MD5.Create(),
                _ => System.Security.Cryptography.SHA256.Create()
            };

            using var stream = File.OpenRead(path);
            var hashBytes = sha.ComputeHash(stream);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        private static LibraryInfo? MatchKnownLibrary(string path)
        {
            // Extract library name from path (e.g., "libcurl.so" or "libcurl.a")
            var libName = Path.GetFileNameWithoutExtension(path);
            
            if (!Config.KnownLibraries.TryGetValue(libName, out var info))
                return null;

            // Check hash against known version
            var expectedHash = ComputeFileHash(path, "MD5");
            if (expectedHash != info.Name.ToLowerInvariant().Replace("lib", "").Replace(".so", ""))
                return null;

            return info;
        }
    }

    internal record AndroidManifestData(
        string? PackageName,
        string? DisplayName = null,
        string? VersionName = null
    );

    internal record AppPlistData(
        string? BundleId,
        string? DisplayName = null,
        string? Version = null
    );

    // =====================================================================
    // SDK Detection Engine
    // =====================================================================
    internal static class SdkDetector
    {
        public static async Task<Result<List<SdkComponent>>> DetectSdksAsync(
            string archivePath, 
            ArchiveInfo info, 
            CancellationToken ct)
        {
            var components = new List<SdkComponent>();

            // Scan for common SDK directories and files
            var sdkPatterns = new[]
            {
                "com.google.android.gms",      // Google Play Services
                "org.jetbrains.kotlin",       // Kotlin runtime
                "androidx.core",              // AndroidX Core
                "io.ktor",                    // Ktor networking
                "okhttp3"                     // OkHttp
            };

            var searchDirs = new[]
            {
                Path.Combine(archivePath, "lib"),
                Path.Combine(archivePath, "classes"),
                Path.Combine(archivePath, "resources")
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                ct.ThrowIfCancellationRequested();

                // Find .jar files and attempt to identify SDKs
                var jarFiles = Directory.EnumerateFiles(dir, "*.jar");
                
                foreach (var jarPath in jarFiles)
                {
                    var jarName = Path.GetFileName(jarPath);
                    
                    // Quick check against known patterns
                    if (TryIdentifyJarFromPattern(jarName, out var component))
                        components.Add(component);

                    // Check for manifest inside JAR
                    if (!components.Contains(component))
                    {
                        try
                        {
                            using var stream = File.OpenRead(jarPath);
                            using var reader = new StreamReader(stream);
                            
                            // Read META-INF/MANIFEST.MF
                            while (reader.Peek() >= 0)
                            {
                                var line = reader.ReadLine();
                                
                                if (line.StartsWith("Manifest-Version:")) continue;
                                if (line.StartsWith("Main-Class:")) continue;

                                // Look for package/class hints
                                if (TryExtractComponentFromJarLine(line, out var comp))
                                    components.Add(comp);
                            }
                        }
                        catch { /* Ignore JAR read errors */ }
                    }
                }
            }

            return Result.Ok(components.Distinct().ToList());
        }

        private static bool TryIdentifyJarFromPattern(string jarName, out SdkComponent component)
        {
            component = default;

            var lowerName = jarName.ToLowerInvariant();

            // Pattern matching for common SDKs
            if (lowerName.Contains("androidx.core") || 
                lowerName.Contains("core-ktx"))
            {
                component = new SdkComponent(
                    "androidx.core:core-ktx",
                    ExtractVersionFromJar(jarName),
                    "androidx"
                );
                return true;
            }

            if (lowerName.Contains("kotlin-stdlib") ||
                lowerName.Contains("kotlin-reflect"))
            {
                component = new SdkComponent(
                    "org.jetbrains.kotlin:kotlin-stdlib",
                    ExtractVersionFromJar(jarName),
                    "org.jetbrains"
                );
                return true;
            }

            if (lowerName.Contains("okhttp3") ||
                lowerName.Contains("okio"))
            {
                component = new SdkComponent(
                    "com.squareup.okhttp3:okhttp",
                    ExtractVersionFromJar(jarName),
                    "com.squareup"
                );
                return true;
            }

            if (lowerName.Contains("ktor") ||
                lowerName.Contains("io.ktor"))
            {
                component = new SdkComponent(
                    "io.ktor:ktor-client-core",
                    ExtractVersionFromJar(jarName),
                    "io.ktor"
                );
                return true;
            }

            if (lowerName.Contains("play-services") ||