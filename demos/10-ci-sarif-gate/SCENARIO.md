# Demo 10 - CI gate with SARIF upload (GitHub code-scanning)

## Where this came from

A CI pipeline unpacks the app into a directory (`extracted_app/`) and runs SBOMX
as a release gate. It uploads the SARIF report to GitHub code-scanning so alerts
appear inline in the Security tab, and fails the job only on HIGH+ findings.

This demo ships an **extracted directory** (not a zip) to show that SBOMX scans
either form. The tree contains:

- `okhttp3/OkHttpClient.class` with no version -> okhttp **potential** (MEDIUM)
- `libs/gson-2.8.5.jar` -> **gson 2.8.5** (`CVE-2022-25647`, HIGH; fixed 2.8.9)
- `lib/arm64-v8a/libsqlite-3.26.0.so` -> **sqlite 3.26.0** (`CVE-2019-8457`, HIGH)
- Firebase Crashlytics + Analytics trackers

## How to run

```sh
# 1) Emit SARIF for code-scanning (always exit 0 so the upload step still runs)
python -m sbomx scan demos/10-ci-sarif-gate/extracted_app \
    --format sarif --fail-on never -o sbomx.sarif.json

# 2) Separately, gate the build on HIGH severity
python -m sbomx scan demos/10-ci-sarif-gate/extracted_app --fail-on high
echo "gate exit: $?"     # 1 -> blocked (gson + sqlite are HIGH)
```

In GitHub Actions:

```yaml
- run: python -m sbomx scan ./extracted_app --format sarif --fail-on never -o sbomx.sarif.json
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: sbomx.sarif.json }
- run: python -m sbomx scan ./extracted_app --fail-on high   # gate the build
```

## Expected result

- SARIF 2.1.0 log: `version` `2.1.0`, **5 results** (2 HIGH `error`, 1 MEDIUM
  `warning`, 2 tracker `note`), each with a `ruleId`, `partialFingerprints`, and
  an artifact location.
- The HIGH gate exits **1** (gson + sqlite).

## How to act

Fix the two HIGH advisories (gson >= 2.8.9, sqlite >= 3.28.0). The SARIF upload
de-duplicates alerts across runs via `partialFingerprints`, so resolved findings
auto-close in the Security tab.
