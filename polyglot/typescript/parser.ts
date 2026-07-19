import * as fs from 'fs';
import * as path from 'path';
import * as archiver from 'archiver';
import { Readable } from 'stream';

// ============================================================================
// TYPE DEFINITIONS - CycloneDX BOM Structure
// ============================================================================

export interface Component {
  name: string;
  version?: string;
  group?: string;
  type: 'library' | 'application' | 'framework' | 'sdk' | 'file';
  scope: 'required' | 'optional' | 'dev';
  hash?: string;
  purl?: string;
}

export interface Dependency {
  ref: Component;
  dependsOn: Component[];
  dependencyOf: Component[];
}

export interface Vulnerability {
  id: string;
  version: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  fixVersion?: string;
  cveId?: string;
}

export interface PrivacyIssue {
  id: string;
  category: 'COLLECTION' | 'SHARING' | 'TRACKING' | 'PERMISSION';
  severity: 'INFO' | 'NOTICE' | 'WARNING' | 'CRITICAL';
  description: string;
  affectedComponent?: Component;
}

export interface SBOMResult {
  bom: CycloneDXBom;
  components: Map<string, Component>;
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
  privacyIssues: PrivacyIssue[];
  metadata: ParsedMetadata;
  summary: SummaryStats;
}

export interface CycloneDXBom {
  specVersion: string;
  version: number;
  components: Component[];
  dependencies?: Dependency[];
  services?: any[];
  meta?: MetaInfo;
  tools?: Tool[];
}

export interface MetaInfo {
  timestamp: string;
  authors: Author[];
  licenses?: License[];
  suppliers?: Supplier[];
  manufacturers?: Manufacturer[];
  relationships?: Relationship[];
}

export interface Author {
  name: string;
  email?: string;
  website?: string;
}

export interface License {
  id: string;
  url?: string;
  name?: string;
  text?: string;
}

export interface Supplier {
  name: string;
  url?: string;
  email?: string;
}

export interface Manufacturer {
  name: string;
  url?: string;
  email?: string;
}

export interface Relationship {
  relatedTo: Component;
  type: 'contains' | 'distributes' | 'dependsOn';
  direction: 'forward' | 'reverse';
}

export interface Tool {
  name: string;
  version: string;
  vendor?: string;
}

export interface ParsedMetadata {
  appName: string;
  appVersion: string;
  buildNumber: string;
  bundleId: string;
  packageName: string;
  archiverTool: string;
  extractedPath: string;
  timestamp: Date;
}

export interface SummaryStats {
  totalComponents: number;
  totalDependencies: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  criticalPrivacyIssues: number;
  warningPrivacyIssues: number;
}

// ============================================================================
// KNOWN LIBRARY PATTERNS - Mobile SDK Detection Database
// ============================================================================

interface LibraryPattern {
  name: string;
  versionRegex: RegExp;
  type: Component['type'];
  group?: string;
  purlTemplate?: string;
  commonNames: string[];
}

const LIBRARY_PATTERNS: LibraryPattern[] = [
  // Android NDK / Native Libraries
  {
    name: 'libandroid',
    versionRegex: /\d+(\.\d+)?/,
    type: 'library',
    group: 'org.android.ndk',
    commonNames: ['libandroid.so', 'libandroid.a'],
  },
  {
    name: 'libsqlite',
    versionRegex: /\d+(\.\d+)?/,
    type: 'library',
    group: 'org.sqlite',
    commonNames: ['libsqlite3.so', 'libsqlite.a'],
  },
  
  // iOS Frameworks
  {
    name: 'UIKit',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'framework',
    group: 'com.apple.UIKit',
    commonNames: ['UIKit.framework', 'UIKit'],
  },
  {
    name: 'Foundation',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'framework',
    group: 'com.apple.Foundation',
    commonNames: ['Foundation.framework', 'Foundation'],
  },
  
  // Popular Mobile SDKs - Android
  {
    name: 'AndroidX-AppCompat',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'androidx.appcompat',
    purlTemplate: 'pkg:maven/androidx.appcompat/appcompat@${version}',
  },
  {
    name: 'AndroidX-Core',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'androidx.core',
    purlTemplate: 'pkg:maven/androidx.core/core@${version}',
  },
  {
    name: 'Gson',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'library',
    group: 'com.google.code.gson',
    purlTemplate: 'pkg:maven/com.google.code.gson/gson@${version}',
  },
  {
    name: 'OkHttp',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'library',
    group: 'com.squareup.okhttp3',
    purlTemplate: 'pkg:maven/com.squareup.okhttp3/okhttp@${version}',
  },
  {
    name: 'Retrofit',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.squareup.retrofit2',
    purlTemplate: 'pkg:maven/com.squareup.retrofit2/retrofit@${version}',
  },
  
  // Popular Mobile SDKs - iOS / Cross-platform
  {
    name: 'Realm',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'io.realm',
    purlTemplate: 'pkg:maven/io.realm/realm@${version}',
  },
  {
    name: 'Firebase',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.google.firebase',
    purlTemplate: 'pkg:maven/com.google.firebase/firebase@${version}',
  },
  {
    name: 'Google-Ads-Mob',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.google.ads.mediation',
    purlTemplate: 'pkg:maven/com.google.ads.mediation/ads-mob@${version}',
  },
  {
    name: 'Unity-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.unity',
    purlTemplate: 'pkg:maven/com.unity/unity-sdk@${version}',
  },
  {
    name: 'Unreal-Engine',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.epic.unreal',
    purlTemplate: 'pkg:maven/com.epic.unreal/unreal-engine@${version}',
  },
  
  // Cross-platform frameworks
  {
    name: 'React-Native',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'framework',
    group: 'facebook.react',
    purlTemplate: 'pkg:npm/react-native@${version}',
  },
  {
    name: 'Flutter',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'flutter',
    purlTemplate: 'pkg:flutter/flutter@${version}',
  },
  {
    name: 'Xamarin-Frameworks',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'framework',
    group: 'xamarin',
    commonNames: ['Mono.Runtime.dll', 'Xamarin.iOS.dll'],
  },
  
  // Analytics & Tracking SDKs
  {
    name: 'Google-Analytics-Firebase',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.google.firebase.analytics',
    purlTemplate: 'pkg:maven/com.google.firebase/firebase-analytics@${version}',
  },
  {
    name: 'Mixpanel-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.mixpanel',
    purlTemplate: 'pkg:maven/com.mixpanel/mixpanel@${version}',
  },
  {
    name: 'Amplitude-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.amplitude',
    purlTemplate: 'pkg:maven/com.amplitude/amplitude@${version}',
  },
  
  // Ad SDKs
  {
    name: 'AdMob-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.google.ads.mediation.admob',
    purlTemplate: 'pkg:maven/com.google.ads.mediation/admob@${version}',
  },
  {
    name: 'AppLovin-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.applovin',
    purlTemplate: 'pkg:maven/com.applovin/applovin@${version}',
  },
  
  // Payment SDKs
  {
    name: 'Stripe-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.stripe',
    purlTemplate: 'pkg:maven/com.stripe/stripe@${version}',
  },
  {
    name: 'PayPal-SDK',
    versionRegex: /(\d+\.\d+(\.\d+)?)/,
    type: 'sdk',
    group: 'com.paypal.sdk',
    purlTemplate: 'pkg:maven/com.paypal.sdk/paypal@${version}',
  },
];

// ============================================================================
// PARSERS - Extract Metadata from Various Sources
// ============================================================================

class MetadataParser {
  private static readonly APP_NAME_REGEX = /(?:Application|App)\s*Name\s*[:=]\s*["']?([^"'\n]+)["']?/i;
  private static readonly VERSION_REGEX = /(?:Version|Ver)\s*[:=]\s*["']?(\d+(\.\d+)?)/i;
  private static readonly BUILD_NUMBER_REGEX = /(?:Build|Bld)\s*Number\s*[:=]\s*["']?([^"'\n]+)["']?/i;
  private static readonly BUNDLE_ID_REGEX = /(?:Bundle|CFBundle)\s*Identifier\s*[:=]\s*["']?([^"'\n]+)["']?/i;
  private static readonly PACKAGE_NAME_REGEX = /(?:Package|pkg)\s*Name\s*[:=]\s*["']?([^"'\n]+)["']?/i;

  public static async parseManifest(
    manifestPath: string,
    archiverTool: string
  ): Promise<ParsedMetadata> {
    const content = await fs.promises.readFile(manifestPath, 'utf-8');
    
    // Extract app metadata from manifest
    const appNameMatch = this.APP_NAME_REGEX.exec(content);
    const appVersionMatch = this.VERSION_REGEX.exec(content);
    const buildNumberMatch = this.BUILD_NUMBER_REGEX.exec(content);
    const bundleIdMatch = this.BUNDLE_ID_REGEX.exec(content);
    const packageNameMatch = this.PACKAGE_NAME_REGEX.exec(content);

    return {
      appName: appNameMatch?.[1] || 'Unknown',
      appVersion: appVersionMatch?.[1] || '0.0.0',
      buildNumber: buildNumberMatch?.[1] || '0',
      bundleId: bundleIdMatch?.[1] || 'unknown.bundle.id',
      packageName: packageNameMatch?.[1] || 'unknown.package.name',
      archiverTool,
      extractedPath: path.dirname(manifestPath),
      timestamp: new Date(),
    };
  }

  public static parseArchiveMetadata(
    archiveStream: Readable,
    filename: string
  ): Promise<ParsedMetadata> {
    return this.parseManifestFromStream(archiveStream);
  }

  private static async parseManifestFromStream(
    stream: Readable
  ): Promise<ParsedMetadata> {
    const chunks: Buffer[] = [];
    
    for await (const chunk of stream) {
      chunks.push(chunk as Buffer);
    }
    
    const content = Buffer.concat(chunks).toString('utf-8');
    return this.parseManifest(content, 'Unknown Archiver', '/tmp/extracted');
  }

  private static async parseManifest(
    content: string,
    archiverTool: string,
    extractedPath: string
  ): Promise<ParsedMetadata> {
    const appNameMatch = this.APP_NAME_REGEX.exec(content);
    const appVersionMatch = this.VERSION_REGEX.exec(content);
    const buildNumberMatch = this.BUILD_NUMBER_REGEX.exec(content);
    const bundleIdMatch = this.BUNDLE_ID_REGEX.exec(content);
    const packageNameMatch = this.PACKAGE_NAME_REGEX.exec(content);

    return {
      appName: appNameMatch?.[1] || 'Unknown',
      appVersion: appVersionMatch?.[1] || '0.0.0',
      buildNumber: buildNumberMatch?.[1] || '0',
      bundleId: bundleIdMatch?.[1] || 'unknown.bundle.id',
      packageName: packageNameMatch?.[1] || 'unknown.package.name',
      archiverTool,
      extractedPath,
      timestamp: new Date(),
    };
  }
}

// ============================================================================
// COMPONENT PARSER - Detect and Classify Libraries
// ============================================================================

class ComponentParser {
  private static readonly LIBRARY_CACHE = new Map<string, Component>();

  public static async parseDirectory(
    directoryPath: string,
    archiverTool: string,
    extractedPath: string
  ): Promise<SBOMResult> {
    const componentsMap = new Map<string, Component>();
    let totalDependencies = 0;

    // Scan for manifest files first
    const manifests = await this.findManifests(directoryPath);
    
    if (manifests.length > 0) {
      const metadata = await MetadataParser.parseManifest(
        manifests[0],
        archiverTool,
        extractedPath
      );
      
      // Parse each manifest for dependencies
      for (const manifest of manifests) {
        totalDependencies += await this.parseManifestDependencies(manifest);
      }
    }

    // Scan for library files and detect known patterns
    const libFiles = await fs.promises.readdir(directoryPath, { withFileTypes: true });
    
    for (const entry of libFiles) {
      if (entry.isFile()) {
        const filePath = path.join(directoryPath, entry.name);
        
        // Check against library patterns
        let matchedComponent: Component | undefined;
        
        for (const pattern of LIBRARY_PATTERNS) {
          if (pattern.commonNames.some(n => entry.name.includes(n))) {
            const versionMatch = pattern.versionRegex.exec(entry.name);
            
            if (versionMatch && versionMatch[1]) {
              const version = versionMatch[1];
              
              // Check cache first
              const cacheKey = `${entry.name}:${version}`;
              if (componentsMap.has(cacheKey)) {
                continue;
              }

              matchedComponent = this.createComponent(
                pattern,
                entry.name,
                version,
                'required'
              );
              
              componentsMap.set(cacheKey, matchedComponent);
              break;
            }
          }
        }

        // If no pattern match, create a generic file component
        if (!matchedComponent) {
          const hash = await this.computeFileHash(filePath);
          
          matchedComponent = this.createGenericComponent(
            entry.name,
            'file',
            hash,
            'required'
          );
          
          componentsMap.set(entry.name, matchedComponent);
        }
      }
    }

    // Convert map to array and build dependencies
    const componentsArray = Array.from(componentsMap.values());
    
    return {
      bom: this.buildBOM(componentsArray),