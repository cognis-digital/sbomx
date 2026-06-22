# Demo 05 - React Native e-commerce app, privacy + vuln review

## Where this came from

A privacy officer reviews a React Native shopping app (`shop.apk`) before a GDPR
data-mapping exercise. They need (a) which marketing/analytics SDKs ship inside
the binary and (b) any vulnerable networking/image libraries.

The bundle ships:

- React Native runtime (`com/facebook/react/...`, `libreactnativejni.so`)
- `okhttp-4.9.0.jar` -> **okhttp 4.9.0** (`CVE-2021-0341`, MEDIUM; fixed 4.9.2)
- `glide-4.10.0.jar` -> **Glide 4.10.0** (`CVE-2020-8771`, MEDIUM; fixed 4.11.0)
- Trackers: **Adjust**, **Mixpanel**, **Firebase Analytics**

## How to run

```sh
python demos/05-react-native-ecommerce/make_sample.py
python -m sbomx scan demos/05-react-native-ecommerce/shop.apk --format table

# Hand the tracker/vuln list to the ticketing system as CSV:
python -m sbomx scan demos/05-react-native-ecommerce/shop.apk --format csv -o shop-findings.csv
```

## Expected result

- **6 components** (react-native, okhttp, glide, adjust-sdk, mixpanel, firebase-core).
- **2 vulnerabilities** (`CVE-2021-0341`, `CVE-2020-8771`, both MEDIUM).
- **3 trackers** (Adjust, Mixpanel, Google Firebase Analytics).
- Exit code **1**.

## How to act

Document the three trackers in the app's data-flow inventory and privacy policy,
and upgrade okhttp (>= 4.9.2) and Glide (>= 4.11.0). Gate the build on HIGH only
with `--fail-on high` if these MEDIUMs are accepted risk for now.
