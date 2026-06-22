"""(Re)generate demos/09-flutter-app/flutter.apk.

A Flutter Android app. The Flutter engine bundles native libs; this fixture
ships an older openssl and sqlite (both with advisories) alongside the Flutter
runtime and a Firebase analytics tracker.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.flutter'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    # Flutter engine (inventory component).
    "io/flutter/embedding/engine/FlutterEngine.class": b"CAFEBABE flutter\n",
    "lib/arm64-v8a/libflutter.so": b"\x7fELF flutter\n",
    "assets/flutter_assets/AssetManifest.json": b"{}\n",
    # Native crypto + db at vulnerable versions:
    "lib/arm64-v8a/libcrypto.so.1.0.2g": b"\x7fELF openssl\n",   # CVE-2016-2107 etc.
    "lib/arm64-v8a/libsqlite-3.20.0.so": b"\x7fELF sqlite\n",    # CVE-2019-8457
    # Firebase analytics tracker.
    "com/google/firebase/analytics/FirebaseAnalytics.class": b"CAFEBABE fb\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "flutter.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
