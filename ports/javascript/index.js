#!/usr/bin/env node
// JavaScript / Node port of the sbomx mobile-SBOM scanner.
//
// Mirrors the Python reference (sbomx/core.py): walk an extracted app
// directory (or explicit member paths), detect bundled third-party libraries
// by their well-known package-path markers, and emit a JSON SBOM summary with
// the same component shape. Defensive / offline only — reads paths, no network.
import { readdirSync, statSync } from "fs";
import { join, basename, relative } from "path";

export const RULES = [
  ["firebase", "firebase-core", "com/google/firebase/", "maven", "maven", "com.google.firebase"],
  ["okhttp", "okhttp", "okhttp3/", "maven", "maven", "com.squareup.okhttp3"],
  ["retrofit", "retrofit", "retrofit2/", "maven", "maven", "com.squareup.retrofit2"],
  ["gson", "gson", "com/google/gson/", "maven", "maven", "com.google.code.gson"],
  ["glide", "glide", "com/bumptech/glide/", "maven", "maven", "com.github.bumptech.glide"],
  ["react-native", "react-native", "com/facebook/react/", "npm", "npm", ""],
  ["flutter", "flutter", "io/flutter/", "maven", "maven", "io.flutter"],
  ["alamofire", "Alamofire", "Alamofire.framework", "cocoapods", "cocoapods", ""],
  ["afnetworking", "AFNetworking", "AFNetworking.framework", "cocoapods", "cocoapods", ""],
  ["sqlite", "sqlite", "libsqlite", "native", "generic", ""],
  ["openssl", "openssl", "libssl", "native", "generic", ""],
  ["openssl", "openssl", "libcrypto", "native", "generic", ""],
  ["libwebp", "libwebp", "libwebp", "native", "generic", ""],
  ["libpng", "libpng", "libpng", "native", "generic", ""],
  ["zlib", "zlib", "libz.so", "native", "generic", ""],
  ["crashlytics", "firebase-crashlytics", "com/google/firebase/crashlytics/", "maven", "maven", "com.google.firebase"],
  ["appsflyer", "appsflyer", "com/appsflyer/", "maven", "maven", "com.appsflyer"],
  ["adjust", "adjust-sdk", "com/adjust/sdk/", "maven", "maven", "com.adjust.sdk"],
];

const VER_RE = /[-_.](\d+(?:\.\d+){1,3}[a-z]?)/;

function extractVersion(path) {
  const m = VER_RE.exec(basename(path));
  return m ? m[1] : null;
}

function purl([, name, , , purlType, group], version) {
  const ns = group ? group + "/" : "";
  const v = version ? "@" + version : "";
  return `pkg:${purlType}/${ns}${name}${v}`;
}

export function detect(paths) {
  const found = new Map();
  for (const p of paths) {
    const norm = p.replace(/\\/g, "/");
    const base = basename(norm).toLowerCase();
    for (const rule of RULES) {
      const [key, name, marker, eco] = rule;
      const versioned = base.startsWith(key.toLowerCase() + "-") ||
                        base.startsWith(key.toLowerCase() + "_");
      if (norm.includes(marker) || versioned) {
        const version = extractVersion(norm);
        const existing = found.get(key);
        if (!existing) {
          found.set(key, { name, version, ecosystem: eco, purl: purl(rule, version), evidence: norm });
        } else if (existing.version == null && version != null) {
          existing.version = version;
          existing.purl = purl(rule, version);
          existing.evidence = norm;
        }
      }
    }
  }
  return [...found.values()].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

function walk(p, root) {
  try {
    if (statSync(p).isDirectory()) {
      return readdirSync(p).flatMap((f) => walk(join(p, f), root));
    }
    return [relative(root, p)];
  } catch {
    return [];
  }
}

export function scan(target) {
  let paths;
  try {
    paths = statSync(target).isDirectory() ? walk(target, target) : [target];
  } catch {
    paths = [target];
  }
  const components = detect(paths);
  return { tool: "sbomx", port: "javascript", components, count: components.length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(JSON.stringify(scan(process.argv[2] || "."), null, 2));
}
