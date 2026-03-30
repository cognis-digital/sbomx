# Demo 01 - Basic mobile-app SBOM + findings

## What this shows

SBOMX scanning a *simulated* Android app bundle. Real `.apk`/`.ipa` files are
just ZIP archives; this demo ships a small `sample-app.apk` (a real zip) whose
entries mimic the file layout of a real app: bundled Java packages, native
`.so` libraries, and an iOS-style framework folder.

The bundled entries deliberately include:

- `okhttp3/...` carried in `libs/okhttp-4.9.0.jar` -> **okhttp 4.9.0**
  (vulnerable: `CVE-2021-0341`, fixed in 4.9.2)
- `lib/arm64-v8a/libssl.so.1.1.1k` -> **openssl 1.1.1k**
  (vulnerable: `CVE-2022-0778`, fixed in 1.1.1n)
- `lib/arm64-v8a/libsqlite-3.27.0.so` -> **sqlite 3.27.0**
  (vulnerable: `CVE-2019-8457`, fixed in 3.28.0)
- `com/google/firebase/crashlytics/...` -> **Crashlytics tracker**
- `com/appsflyer/...` -> **AppsFlyer tracker**
- `okhttp3` plus benign `com/google/gson/` at a safe version path

## How to run

```sh
# Human-readable findings
python -m sbomx scan demos/01-basic/sample-app.apk --format table

# CycloneDX 1.5 SBOM (JSON) for CI / piping
python -m sbomx scan demos/01-basic/sample-app.apk --format json -o app.cdx.json
```

## Expected result

- Components detected include `okhttp`, `openssl`, `sqlite`, `gson`,
  `firebase-crashlytics`, `appsflyer`.
- **3 vulnerabilities**: `CVE-2021-0341` (okhttp), `CVE-2022-0778` (openssl),
  `CVE-2019-8457` (sqlite).
- **2 trackers**: Google Firebase Crashlytics, AppsFlyer.
- Because findings exist, the CLI exits with code **1** (default `--fail-on info`),
  so a CI gate would fail. Add `--fail-on high` to gate only on high-severity
  vulns, or `--fail-on never` to always pass.
