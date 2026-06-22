"""(Re)generate demos/03-mixed/mixed.apk.

A realistic mixed app: mostly fine, but one HIGH-severity native lib and one
MEDIUM-severity Java lib, plus a single analytics tracker. Demonstrates how
`--fail-on high` blocks only on the HIGH issue while the MEDIUM is reported but
does not fail the gate.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.mixed'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    # MEDIUM: okhttp 4.9.0 < 4.9.2 -> CVE-2021-0341
    "libs/okhttp-4.9.0.jar": b"PK okhttp\n",
    "okhttp3/OkHttpClient.class": b"CAFEBABE okhttp\n",
    # HIGH: sqlite 3.27.0 < 3.28.0 -> CVE-2019-8457
    "lib/arm64-v8a/libsqlite-3.27.0.so": b"\x7fELF sqlite\n",
    # one tracker
    "com/mixpanel/android/mpmetrics/MixpanelAPI.class": b"CAFEBABE mixpanel\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "mixed.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
