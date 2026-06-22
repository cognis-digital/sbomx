# Demo 02 - Clean baseline (no third-party libs)

## Where this came from

A minimal first-party Android app with no bundled SDKs or native libraries.
This is the simplest "all clear" baseline.

## How to run

```sh
python demos/02-clean/make_sample.py
python -m sbomx scan demos/02-clean/clean.apk
echo "exit: $?"     # 0 -> nothing detected
```

## Expected result

- **0 components**, **0 vulnerabilities**, **0 trackers**.
- Exit code **0**.
