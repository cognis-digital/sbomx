# Demo 06 - Clean release candidate (gate passes)

## Where this came from

The release-engineering team has already remediated every flagged dependency and
rebuilt the app. This is the "green" case: SBOMX still produces a full component
inventory (SBOM), but every library is at/above its fixed version, so there are
**zero** vulnerability findings and the CI gate passes.

The bundle ships all libraries at safe versions:

- okhttp 4.9.2, gson 2.8.9, Glide 4.11.0 (all == fix)
- openssl 1.1.1n, sqlite 3.28.0 (both == fix)
- zlib 1.2.13 (> fix 1.2.12)

## How to run

```sh
python demos/06-clean-release/make_sample.py
python -m sbomx scan demos/06-clean-release/release.apk --fail-on high
echo "exit code: $?"     # 0 -> release gate passes
```

## Expected result

- **6 components** inventoried.
- **0 vulnerabilities**, **0 trackers**.
- Exit code **0** even with `--fail-on high` (and with the stricter default).

## How to act

Nothing to fix. Archive the SBOM as the release artifact:

```sh
python -m sbomx scan demos/06-clean-release/release.apk --format json -o release.cdx.json
```
