# Demo 07 - Stripped build + version manifest resolution

## Where this came from

A vendor ships a stripped/obfuscated release APK where native libraries carry no
version in their filenames (`libssl.so`, `libsqlite.so`). SBOMX detects the
*components* but cannot recover their *versions* from the path, so advisories are
reported as **potential** ("version unknown") matches.

The build team then supplies the exact shipped versions in `versions.json`, which
SBOMX uses to turn potential matches into precise findings.

`versions.json`:

```json
{ "openssl": "1.0.2g", "sqlite": "3.25.0", "okhttp": "4.9.1" }
```

## How to run

```sh
python demos/07-manifest-resolve/make_sample.py

# 1) Without the manifest: 4 POTENTIAL findings (version unknown)
python -m sbomx scan demos/07-manifest-resolve/stripped.apk

# 2) With the manifest: same 4 findings, now version-pinned and confirmed
python -m sbomx scan demos/07-manifest-resolve/stripped.apk \
    --manifest demos/07-manifest-resolve/versions.json
```

## Expected result

- Without manifest: **4 vulnerabilities** marked `[version unknown - potential]`
  (openssl x2, sqlite, okhttp).
- With manifest: the same 4 advisories, now resolved against openssl 1.0.2g,
  sqlite 3.25.0, okhttp 4.9.1 — note `CVE-2016-2107` (openssl < 1.0.2h) confirms
  precisely because the version is now known.
- Exit code **1** in both modes.

## How to act

Adopt a `versions.json` manifest in CI for any obfuscated/stripped build so the
SBOM reflects confirmed (not merely potential) advisories.
