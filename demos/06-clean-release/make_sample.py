"""(Re)generate demos/06-clean-release/release.apk.

A release-candidate Android build where every bundled library has been bumped
to a version at/above its fix. SBOMX still inventories the components, but
produces ZERO vulnerability findings, so `--fail-on high` exits 0 and the
release gate passes. (Trackers, if any, are reported as info only.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.clean'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    # All at/above the fixed versions in SBOMX's VULN_DB:
    "libs/okhttp-4.9.2.jar": b"PK okhttp\n",          # fix 4.9.2
    "okhttp3/OkHttpClient.class": b"CAFEBABE\n",
    "libs/gson-2.8.9.jar": b"PK gson\n",              # fix 2.8.9
    "com/google/gson/Gson.class": b"CAFEBABE\n",
    "libs/glide-4.11.0.jar": b"PK glide\n",           # fix 4.11.0
    "com/bumptech/glide/Glide.class": b"CAFEBABE\n",
    "lib/arm64-v8a/libssl.so.1.1.1n": b"\x7fELF\n",   # openssl fix 1.1.1n
    "lib/arm64-v8a/libsqlite-3.28.0.so": b"\x7fELF\n",  # sqlite fix 3.28.0
    "lib/arm64-v8a/libz.so.1.2.13": b"\x7fELF\n",     # zlib >= 1.2.12
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "release.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
