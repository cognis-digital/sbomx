"""(Re)generate demos/07-manifest-resolve/stripped.apk.

A heavily stripped/obfuscated release where native libs ship WITHOUT version
strings in their filenames (e.g. plain `libssl.so`). SBOMX detects the
components but their version is unknown, so advisories are reported as
"potential" matches. A build-team-supplied `versions.json` manifest then maps
each library key to the exact shipped version, turning potentials into precise,
actionable findings.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.stripped'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    # No version in the filenames -> version-unknown until the manifest resolves them.
    "lib/arm64-v8a/libssl.so": b"\x7fELF openssl\n",
    "lib/arm64-v8a/libcrypto.so": b"\x7fELF openssl\n",
    "lib/arm64-v8a/libsqlite.so": b"\x7fELF sqlite\n",
    "okhttp3/OkHttpClient.class": b"CAFEBABE okhttp\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "stripped.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
