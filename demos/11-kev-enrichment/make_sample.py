"""(Re)generate demos/11-kev-enrichment/vuln-app.apk.

An .apk is a zip. This bundle ships two native libs at versions that are not
just CVE-affected but on CISA's Known-Exploited Vulnerabilities (KEV) list:

  * libwebp 1.2.0  -> CVE-2023-4863 (KEV, exploited zero-day in the wild)
  * libssl  1.0.1f -> CVE-2014-0160 Heartbleed (KEV)

Run:  python demos/11-kev-enrichment/make_sample.py
Then: sbomx scan demos/11-kev-enrichment/vuln-app.apk --enrich-kev --offline
"""
import os
import zipfile

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.example.kevdemo'/>\n",
    "classes.dex": b"dex\n035\x00placeholder\n",
    "lib/arm64-v8a/libwebp.so.1.2.0": b"\x7fELF libwebp\n",
    "lib/arm64-v8a/libssl.so.1.0.1f": b"\x7fELF openssl\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "vuln-app.apk")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in ENTRIES.items():
            zf.writestr(name, data)
    print("wrote", out)


if __name__ == "__main__":
    main()
