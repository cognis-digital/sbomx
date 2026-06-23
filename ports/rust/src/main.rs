// Rust port of the sbomx mobile-SBOM scanner — fast, single static binary, std-only.
//
// Mirrors the Python reference (sbomx/core.py): walk an extracted app directory
// (or explicit member paths), detect bundled third-party libraries by their
// well-known package-path markers, and print a JSON SBOM summary with the same
// component shape. Defensive / offline only — reads paths, never the network.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

struct Rule {
    key: &'static str,
    name: &'static str,
    marker: &'static str,
    ecosystem: &'static str,
    purl_type: &'static str,
    group: &'static str,
}

fn rules() -> Vec<Rule> {
    macro_rules! r {
        ($k:expr,$n:expr,$m:expr,$e:expr,$p:expr,$g:expr) => {
            Rule { key: $k, name: $n, marker: $m, ecosystem: $e, purl_type: $p, group: $g }
        };
    }
    vec![
        r!("firebase", "firebase-core", "com/google/firebase/", "maven", "maven", "com.google.firebase"),
        r!("okhttp", "okhttp", "okhttp3/", "maven", "maven", "com.squareup.okhttp3"),
        r!("retrofit", "retrofit", "retrofit2/", "maven", "maven", "com.squareup.retrofit2"),
        r!("gson", "gson", "com/google/gson/", "maven", "maven", "com.google.code.gson"),
        r!("glide", "glide", "com/bumptech/glide/", "maven", "maven", "com.github.bumptech.glide"),
        r!("react-native", "react-native", "com/facebook/react/", "npm", "npm", ""),
        r!("flutter", "flutter", "io/flutter/", "maven", "maven", "io.flutter"),
        r!("alamofire", "Alamofire", "Alamofire.framework", "cocoapods", "cocoapods", ""),
        r!("afnetworking", "AFNetworking", "AFNetworking.framework", "cocoapods", "cocoapods", ""),
        r!("sqlite", "sqlite", "libsqlite", "native", "generic", ""),
        r!("openssl", "openssl", "libssl", "native", "generic", ""),
        r!("openssl", "openssl", "libcrypto", "native", "generic", ""),
        r!("libwebp", "libwebp", "libwebp", "native", "generic", ""),
        r!("libpng", "libpng", "libpng", "native", "generic", ""),
        r!("zlib", "zlib", "libz.so", "native", "generic", ""),
        r!("crashlytics", "firebase-crashlytics", "com/google/firebase/crashlytics/", "maven", "maven", "com.google.firebase"),
        r!("appsflyer", "appsflyer", "com/appsflyer/", "maven", "maven", "com.appsflyer"),
        r!("adjust", "adjust-sdk", "com/adjust/sdk/", "maven", "maven", "com.adjust.sdk"),
    ]
}

#[derive(Clone)]
struct Component {
    name: String,
    version: Option<String>,
    ecosystem: String,
    purl: String,
    evidence: String,
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// Extract a version like 4.9.0 / 1.1.1k from a filename's [-_.]NNN sequence.
fn extract_version(path: &str) -> Option<String> {
    let base = base_name(path);
    let bytes: Vec<char> = base.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(bytes[i], '-' | '_' | '.') && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == '.' || bytes[j].is_ascii_lowercase()) {
                j += 1;
            }
            let cand: String = bytes[start..j].iter().collect();
            if cand.contains('.') && cand.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                let trimmed = cand.trim_end_matches('.').to_string();
                if trimmed.contains('.') {
                    return Some(trimmed);
                }
            }
        }
        i += 1;
    }
    None
}

fn purl(r: &Rule, version: &Option<String>) -> String {
    let ns = if r.group.is_empty() { String::new() } else { format!("{}/", r.group) };
    let v = version.as_ref().map(|x| format!("@{}", x)).unwrap_or_default();
    format!("pkg:{}/{}{}{}", r.purl_type, ns, r.name, v)
}

fn detect(paths: &[String]) -> Vec<Component> {
    let rs = rules();
    let mut found: BTreeMap<&str, Component> = BTreeMap::new();
    for p in paths {
        let norm = p.replace('\\', "/");
        let base = base_name(&norm).to_lowercase();
        for r in &rs {
            let versioned = base.starts_with(&format!("{}-", r.key.to_lowercase()))
                || base.starts_with(&format!("{}_", r.key.to_lowercase()));
            if norm.contains(r.marker) || versioned {
                let version = extract_version(&norm);
                match found.get_mut(r.key) {
                    None => {
                        found.insert(r.key, Component {
                            name: r.name.to_string(),
                            version: version.clone(),
                            ecosystem: r.ecosystem.to_string(),
                            purl: purl(r, &version),
                            evidence: norm.clone(),
                        });
                    }
                    Some(c) if c.version.is_none() && version.is_some() => {
                        c.version = version.clone();
                        c.purl = purl(r, &version);
                        c.evidence = norm.clone();
                    }
                    _ => {}
                }
            }
        }
    }
    let mut out: Vec<Component> = found.into_values().collect();
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().to_string());
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let target = env::args().nth(1).unwrap_or_else(|| ".".into());
    let paths: Vec<String> = if Path::new(&target).is_dir() {
        let mut v = Vec::new();
        walk(Path::new(&target), Path::new(&target), &mut v);
        v
    } else {
        env::args().skip(1).collect()
    };
    let comps = detect(&paths);
    let mut items = Vec::new();
    for c in &comps {
        let ver = c.version.as_ref()
            .map(|v| format!("\"version\":\"{}\",", json_escape(v)))
            .unwrap_or_default();
        items.push(format!(
            "{{\"name\":\"{}\",{}\"ecosystem\":\"{}\",\"purl\":\"{}\",\"evidence\":\"{}\"}}",
            json_escape(&c.name), ver, json_escape(&c.ecosystem),
            json_escape(&c.purl), json_escape(&c.evidence)
        ));
    }
    println!(
        "{{\"tool\":\"sbomx\",\"port\":\"rust\",\"count\":{},\"components\":[{}]}}",
        comps.len(), items.join(",")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_okhttp_with_version() {
        let comps = detect(&[
            "libs/okhttp-4.9.0.jar".into(),
            "okhttp3/OkHttpClient.class".into(),
        ]);
        let ok = comps.iter().find(|c| c.name == "okhttp").expect("okhttp detected");
        assert_eq!(ok.version.as_deref(), Some("4.9.0"));
        assert_eq!(ok.purl, "pkg:maven/com.squareup.okhttp3/okhttp@4.9.0");
    }

    #[test]
    fn detects_native_openssl() {
        let comps = detect(&["lib/arm64-v8a/libssl.so.1.1.1k".into()]);
        assert!(comps.iter().any(|c| c.name == "openssl"));
    }

    #[test]
    fn no_false_positive() {
        let comps = detect(&["AndroidManifest.xml".into(), "classes.dex".into()]);
        assert!(comps.is_empty());
    }

    #[test]
    fn sorted_by_name() {
        let comps = detect(&["okhttp3/X.class".into(), "com/google/gson/Gson.class".into()]);
        assert!(comps.len() >= 2);
        assert!(comps[0].name <= comps[1].name);
    }
}
