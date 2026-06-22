"""(Re)generate demos/02-clean/clean.apk - a minimal app with no known issues.

The bundle contains only first-party code and a benign resource layout, so
SBOMX detects no third-party libraries from its rule set and reports zero
findings (exit 0).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.clean'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    "com/acme/clean/MainActivity.class": b"CAFEBABE app\n",
    "res/values/strings.xml": b"<resources/>\n",
    "res/layout/activity_main.xml": b"<LinearLayout/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "clean.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
