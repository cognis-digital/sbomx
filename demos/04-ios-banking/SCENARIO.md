# Demo 04 - iOS banking app (.ipa) framework audit

## Where this came from

A security team performs a pre-release audit of a retail banking iOS app before
submitting it to the App Store. They have the signed `.ipa` (which is just a ZIP
laid out under `Payload/AcmeBank.app/`). They want an SBOM of the bundled
CocoaPods frameworks and native crypto, plus any known-vulnerable versions.

The bundle ships:

- `Frameworks/Alamofire.framework`, `AFNetworking.framework`, `SDWebImage.framework`
  (inventory components, no advisory in this DB)
- `Frameworks/Realm.framework/Realm-9.8.0` -> **Realm 9.8.0**
  (`CVE-2020-24613`, MEDIUM — Realm sync TLS cert not validated; fixed 10.0.0)
- `Frameworks/libssl.so.1.1.1k` -> **openssl 1.1.1k**
  (`CVE-2022-0778`, HIGH — DoS parsing certificates; fixed 1.1.1n)

## How to run

```sh
python demos/04-ios-banking/make_sample.py          # (re)build banking.ipa
python -m sbomx scan demos/04-ios-banking/banking.ipa --format table
```

## Expected result

- **5 components** inventoried (Alamofire, AFNetworking, SDWebImage, Realm, openssl).
- **2 vulnerabilities**: `CVE-2022-0778` (HIGH, openssl) and `CVE-2020-24613`
  (MEDIUM, Realm).
- No trackers.
- Exit code **1** (findings exist, default `--fail-on info`).

## How to act

Bump the bundled OpenSSL to >= 1.1.1n and the Realm SDK to >= 10.0.0, then
re-scan. For the App Store privacy nutrition label, export the SBOM:

```sh
python -m sbomx scan demos/04-ios-banking/banking.ipa --format json -o banking.cdx.json
```
