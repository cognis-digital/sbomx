# Demo 09 - Flutter app native-dependency audit

## Where this came from

A team audits a Flutter Android app (`flutter.apk`). Flutter ships a native
engine plus any plugin native code; here the bundle carries older OpenSSL and
SQLite builds with documented advisories, alongside a Firebase analytics tracker.

The bundle ships:

- Flutter engine (`io/flutter/...`, `libflutter.so`)
- `libcrypto.so.1.0.2g` -> **openssl 1.0.2g**
  (`CVE-2022-0778` HIGH; and `CVE-2016-2107` HIGH, padding oracle < 1.0.2h)
- `libsqlite-3.20.0.so` -> **sqlite 3.20.0** (`CVE-2019-8457`, HIGH; fixed 3.28.0)
- Firebase Analytics tracker

## How to run

```sh
python demos/09-flutter-app/make_sample.py
python -m sbomx scan demos/09-flutter-app/flutter.apk --format table
python -m sbomx scan demos/09-flutter-app/flutter.apk --fail-on high; echo "exit: $?"
```

## Expected result

- **4 components** (flutter, openssl, sqlite, firebase-core).
- **3 vulnerabilities**, all HIGH (`CVE-2022-0778`, `CVE-2016-2107`, `CVE-2019-8457`).
- **1 tracker** (Firebase Analytics).
- Exit code **1** with `--fail-on high`.

## How to act

This build is blocked by a HIGH gate. Upgrade the native OpenSSL (>= 1.1.1n) and
SQLite (>= 3.28.0) used by the Flutter engine/plugins and re-scan.
