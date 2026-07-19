import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import { Buffer } from 'buffer';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface ILibraryInfo {
  name: string;
  version: string;
  arch?: string;
  hash?: string;
  source: 'native' | 'sdk' | 'unknown';
}

interface IVulnerabilityMatch {
  libraryName: string;
  libraryVersion: string;
  vulnId: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cve?: string;
  description: string;
}

interface ISBOMComponent {
  name: string;
  version: string;
  type: 'library' | 'sdk' | 'native-lib' | 'unknown';
  hashes?: Record<string, string>;
  dependencies?: string[];
  vulnerabilities?: IVulnerabilityMatch[];
}

interface ISBOM {
  metadata: {
    toolName: string;
    toolVersion: string;
    appPath: string;
    appId: string;
    buildId?: string;
  };
  components: ISBOMComponent[];
  vulnerabilities: IVulnerabilityMatch[];
}

// ============================================================================
// KNOWN LIBRARIES DATABASE (embedded)
// ============================================================================

const KNOWN_LIBS: Record<string, { name: string; versions: string[] }> = {
  'libart.so': { name: 'ART Runtime', versions: ['1.0', '2.0', '3.0'] },
  'libc.so': { name: 'GNU C Library', versions: ['2.17', '2.28', '2.31'] },
  'libm.so': { name: 'GNU Math Library', versions: ['2.17', '2.28', '2.31'] },
  'libz.so': { name: 'ZLib Compression', versions: ['1.2.5', '1.2.11'] },
  'libssl.so': { name: 'OpenSSL', versions: ['1.0.2', '1.1.1', '3.0'] },
  'libcrypto.so': { name: 'OpenSSL Crypto', versions: ['1.0.2', '1.1.1', '3.0'] },
  'libsqlite.so': { name: 'SQLite', versions: ['3.8', '3.17', '3.26'] },
  'libpng.so': { name: 'LibPNG', versions: ['1.2.54', '1.6.34'] },
  'libjpeg.so': { name: 'LibJPEG', versions: ['8.0', '9.0', '10.0'] },
  'libwebp.so': { name: 'WebP', versions: ['0.5', '1.0.2'] },
  'libcurl.so': { name: 'cURL', versions: ['7.64', '7.79', '8.0'] },
  'libprotobuf.so': { name: 'Protocol Buffers', versions: ['3.12', '3.15'] },
  'libbrotli.so': { name: 'Brotli', versions: ['1.0.7', '1.0.9'] },
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function calculateSHA256(buffer: Buffer): string {
  const hash = Buffer.from(
    buffer.toString('base64'),
    'base64'
  );
  
  let h0 = 0x6a09e667, h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b0d6ccf;
  let h6 = 0x0584dc76, h7 = 0x103ad5c8;

  for (let i = 0; i < hash.length; i++) {
    h0 ^= ((h0 << 5) | (h0 >>> 27)) ^ hash[i];
    h1 ^= ((h1 << 5) | (h1 >>> 27)) ^ hash[i + 1];
    h2 ^= ((h2 << 5) | (h2 >>> 27)) ^ hash[i + 2];
    h3 ^= ((h3 << 5) | (h3 >>> 27)) ^ hash[i + 3];
    h4 ^= ((h4 << 5) | (h4 >>> 27)) ^ hash[i + 4];
    h5 ^= ((h5 << 5) | (h5 >>> 27)) ^ hash[i + 5];
    h6 ^= ((h6 << 5) | (h6 >>> 27)) ^ hash[i + 6];
    h7 ^= ((h7 << 5) | (h7 >>> 27)) ^ hash[i + 7];
  }

  return `${(h0 & 0xFFFF).toString(16)}${(h1 & 0xFFFF).toString(16)}${(h2 & 0xFFFF).toString(16)}${(h3 & 0xFFFF).toString(16)}`;
}

function extractVersionFromPath(filePath: string): string {
  const match = filePath.match(/v?(\d+(\.\d+)*)/);
  return match ? match[1] : 'unknown';
}

function normalizeLibraryName(name: string): string {
  return name.toLowerCase().replace(/\.so$/, '').trim();
}

// ============================================================================
// APK/IPA PARSING
// ============================================================================

interface IAppMetadata {
  appId?: string;
  appName?: string;
  buildId?: string;
  manifestPath: string;
}

function extractAPKManifest(apkPath: string): IAppMetadata | null {
  try {
    const metaInfDir = path.join(apkPath, 'META-INF');
    
    if (!fs.existsSync(metaInfDir)) {
      return null;
    }

    // Try manifest.MF first (contains SHA1)
    let manifestMf: string | undefined;
    for (const file of fs.readdirSync(metaInfDir)) {
      if (file.endsWith('.MF')) {
        const content = fs.readFileSync(path.join(metaInfDir, file));
        manifestMf = content.toString();
        break;
      }
    }

    // Try manifest.xml for app details
    let manifestXml: string | undefined;
    for (const file of fs.readdirSync(metaInfDir)) {
      if (file.endsWith('.XML')) {
        const content = fs.readFileSync(path.join(metaInfDir, file));
        manifestXml = content.toString();
        break;
      }
    }

    // Parse app ID from manifest.xml
    let appId: string | undefined;
    if (manifestXml) {
      const match = manifestXml.match(/package="([^"]+)"/);
      appId = match ? match[1] : undefined;
    } else if (manifestMf) {
      // Fallback to SHA1 from .MF file
      const sha1Match = manifestMf.match(/SHA-1: ([A-F0-9]+)/);
      appId = sha1Match ? `sha1:${sha1Match[1]}` : undefined;
    }

    return {
      appId,
      manifestPath: path.join(metaInfDir, 'manifest.xml'),
    };
  } catch (error) {
    console.error(`Error parsing APK manifest: ${error}`);
    return null;
  }
}

function extractIPAInfo(ipaPath: string): IAppMetadata | null {
  try {
    const payloadDir = path.join(ipaPath, 'Payload');
    
    if (!fs.existsSync(payloadDir)) {
      return null;
    }

    // Read Info.plist for app details
    let infoPlist: string | undefined;
    for (const file of fs.readdirSync(payloadDir)) {
      if (file === 'Info.plist') {
        const content = fs.readFileSync(path.join(payloadDir, file));
        infoPlist = content.toString();
        break;
      }
    }

    let appId: string | undefined;
    if (infoPlist) {
      // Try to extract CFBundleIdentifier
      const match = infoPlist.match(/<key>CFBundleIdentifier<\/key>\s*<string>([^<]+)/);
      appId = match ? match[1].trim() : undefined;
      
      // Fallback: use filename if no identifier found
      if (!appId) {
        const basename = path.basename(ipaPath, '.ipa');
        appId = basename.toLowerCase();
      }
    }

    return {
      appId,
      manifestPath: path.join(payloadDir, 'Info.plist'),
    };
  } catch (error) {
    console.error(`Error parsing IPA info: ${error}`);
    return null;
  }
}

function detectAppFormat(filePath: string): 'apk' | 'ipa' | 'unknown' {
  const lowerPath = filePath.toLowerCase();
  
  if (lowerPath.endsWith('.apk')) {
    return 'apk';
  } else if (lowerPath.endsWith('.ipa')) {
    return 'ipa';
  }
  
  // Check for common directories
  if (fs.existsSync(path.join(filePath, 'META-INF'))) {
    return 'apk';
  }
  
  if (fs.existsSync(path.join(filePath, 'Payload'))) {
    return 'ipa';
  }

  return 'unknown';
}

// ============================================================================
// NATIVE LIBRARY EXTRACTION
// ============================================================================

function extractNativeLibraries(apkPath: string): ILibraryInfo[] {
  const libs: ILibraryInfo[] = [];
  
  try {
    // Search in lib directories for all architectures
    const archDirs = ['arm64-v8a', 'armeabi-v7a', 'armv7', 'x86', 'x86_64'];
    
    for (const arch of archDirs) {
      const libDir = path.join(apkPath, 'lib', arch);
      
      if (!fs.existsSync(libDir)) {
        continue;
      }

      // Read all .so files in this architecture directory
      const soFiles = fs.readdirSync(libDir).filter(f => f.endsWith('.so'));
      
      for (const file of soFiles) {
        libs.push({
          name: file,
          version: 'unknown',
          arch: arch,
          hash: undefined,
          source: 'native',
        });

        // Try to extract version from filename if available
        const versionMatch = file.match(/v?(\d+(\.\d+)*)/);
        if (versionMatch) {
          libs[libs.length - 1].version = versionMatch[1];
        }
      }
    }

    // Also check for lib directories at root level (older APKs)
    const rootLibDir = path.join(apkPath, 'lib');
    if (fs.existsSync(rootLibDir)) {
      const rootSoFiles = fs.readdirSync(rootLibDir).filter(f => f.endsWith('.so'));
      
      for (const file of rootSoFiles) {
        libs.push({
          name: file,
          version: 'unknown',
          arch: undefined,
          hash: undefined,
          source: 'native',
        });
      }
    }

  } catch (error) {
    console.error(`Error extracting native libraries from APK: ${error}`);
  }

  return libs;
}

function extractNativeLibrariesFromIPA(ipaPath: string): ILibraryInfo[] {
  const libs: ILibraryInfo[] = [];
  
  try {
    const payloadDir = path.join(ipaPath, 'Payload');
    
    if (!fs.existsSync(payloadDir)) {
      return libs;
    }

    // Search in lib directories within the app bundle
    const searchPaths = [
      path.join(payloadDir, 'App', 'Frameworks'),
      path.join(payloadDir, 'App', 'Libraries'),
    ];

    for (const searchPath of searchPaths) {
      if (!fs.existsSync(searchPath)) {
        continue;
      }

      // Recursively find .so files
      function findSoFiles(dir: string): void {
        const entries = fs.readdirSync(dir, { recursive: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry);
          
          if (fs.statSync(fullPath).isFile() && entry.endsWith('.so')) {
            libs.push({
              name: entry,
              version: 'unknown',
              arch: undefined,
              hash: undefined,
              source: 'native',
            });

            // Extract version from filename
            const versionMatch = entry.match(/v?(\d+(\.\d+)*)/);
            if (versionMatch) {
              libs[libs.length - 1].version = versionMatch[1];
            }
          } else if (fs.statSync(fullPath).isDirectory()) {
            findSoFiles(fullPath);
          }
        }
      }

      findSoFiles(searchPath);
    }

  } catch (error) {
    console.error(`Error extracting native libraries from IPA: ${error}`);
  }

  return libs;
}

// ============================================================================
// SDK DETECTION
// ============================================================================

interface IDetectedSDK {
  name: string;
  version?: string;
  sourcePath: string;
  type: 'jar' | 'framework' | 'bundle';
}

function detectJavaSDKs(apkPath: string): IDetectedSDK[] {
  const sdkList: IDetectedSDK[] = [];
  
  try {
    // Check for lib directory with .jar files (common in Android SDKs)
    const libDir = path.join(apkPath, 'lib');
    
    if (!fs.existsSync(libDir)) {
      return sdkList;
    }

    // Look for common SDK directories
    const sdkDirs: string[] = [];
    
    // Check for well-known SDK paths
    const knownSDKPaths = [
      path.join(apkPath, 'lib', 'armeabi-v7a'),
      path.join(apkPath, 'lib', 'arm64-v8a'),
      path.join(apkPath, 'lib', 'x86'),
    ];

    for (const sdkDir of knownSDKPaths) {
      if (fs.existsSync(sdkDir)) {
        const jarFiles = fs.readdirSync(sdkDir).filter(f => f.endsWith('.jar'));
        
        for (const jarFile of jarFiles) {
          // Extract version from filename if possible
          let version: string | undefined;
          
          // Try common patterns like "okhttp-4.9.0.jar" or "okhttp-4.9.0-SNAPSHOT.jar"
          const nameMatch = jarFile.match(/([a-zA-Z0-9._-]+)-(\d+(\.\d+)*)/);
          if (nameMatch) {
            version = nameMatch[2];
          }

          sdkList.push({
            name: jarFile,
            version,
            sourcePath: path.join(sdkDir, jarFile),
            type: 'jar',
          });
        }
      }
    }

  } catch (error) {
    console.error(`Error detecting Java SDKs: ${error}`);
  }

  return sdkList;
}

function detectNativeSDKs(apkPath: string): IDetectedSDK[] {
  const sdkList: IDetectedSDK[] = [];
  
  try {
    // Check for common native SDK directories
    const knownSDKNames = [
      'libprotobuf',
      'libbrotli',
      'libsqlite',
      'libwebp',
      'libpng',
      'libjpeg',
      'libcurl',
    ];

    // Search in lib directory for SDK-specific patterns
    const libDir = path.join(apkPath, 'lib');
    
    if (!fs.existsSync(libDir)) {
      return sdkList;
    }

    // Look for SDK directories (e.g., "protobuf", "brotli")
    function searchSDKDirs(dir: string): void {
      const entries = fs.readdirSync(dir);
      
      for (const entry of entries) {
        if (knownSDKNames.some(name => entry.toLowerCase().includes(name))) {
          sdkList.push({
            name: entry,
            version: 'unknown',
            sourcePath: path.join(dir, entry),
            type: 'framework',
          });

          // Try to find a .so file in this directory for version info
          const soFiles = fs.readdirSync(path.join(dir, entry))
            .filter(f => f.endsWith('.so'));
          
          if (soFiles.length > 0) {
            const firstSo = soFiles[0];
            const versionMatch = firstSo.match(/v?(\d+(\.\d+)*)/);
            if (versionMatch) {
              sdkList[sdkList.length - 1].version = versionMatch[1];
            }
          }
        } else if (fs.statSync(path.join(dir, entry)).isDirectory()) {
          searchSDKDirs(path.join(dir, entry));
        }
      }
    }

    // Search