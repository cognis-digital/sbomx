# Demo 03 - Mixed severities & a selective CI gate

## Where this came from

A typical app mid-development: one HIGH-severity native lib, one MEDIUM-severity
Java lib, and one analytics tracker. Shows how `--fail-on high` blocks only on
the HIGH issue while still reporting the MEDIUM and the tracker.

The bundle ships:

- `okhttp-4.9.0.jar` -> **okhttp 4.9.0** (`CVE-2021-0341`, MEDIUM; fixed 4.9.2)
- `libsqlite-3.27.0.so` -> **sqlite 3.27.0** (`CVE-2019-8457`, HIGH; fixed 3.28.0)
- Mixpanel tracker

## How to run

```sh
python demos/03-mixed/make_sample.py
python -m sbomx scan demos/03-mixed/mixed.apk --format table

# Gate on HIGH only:
python -m sbomx scan demos/03-mixed/mixed.apk --fail-on high; echo "exit: $?"   # 1
# Gate on CRITICAL only (this app has none):
python -m sbomx scan demos/03-mixed/mixed.apk --fail-on critical; echo "exit: $?" # 0
```

## Expected result

- **3 components** (okhttp, sqlite, mixpanel).
- **2 vulnerabilities** (1 HIGH sqlite, 1 MEDIUM okhttp), **1 tracker** (Mixpanel).
- `--fail-on high` -> exit **1**; `--fail-on critical` -> exit **0**.
