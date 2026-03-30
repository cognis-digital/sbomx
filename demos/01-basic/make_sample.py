"""Helper used to (re)generate demos/01-basic/sample-app.apk.

An .apk is just a zip; we synthesize a realistic member layout. Run with:
    python demos/01-basic/make_sample.py
The committed sample-app.apk was produced by this script.
"""
import os
import zipfile

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.example.demo'/>\n",
    "classes.dex": b"dex\n035\x00placeholder\n",
    "libs/okhttp-4.9.0.jar": b"PK-placeholder-okhttp\n",
    "okhttp3/OkHttpClient.class": b"CAFEBABE okhttp\n",
    "retrofit2/Retrofit.class": b"CAFEBABE retrofit\n",
    "com/google/gson/Gson.class": b"CAFEBABE gson\n",
    "com/google/firebase/crashlytics/FirebaseCrashlytics.class": b"CAFEBABE crashlytics\n",
    "com/appsflyer/AppsFlyerLib.class": b"CAFEBABE appsflyer\n",
    "lib/arm64-v8a/libssl.so.1.1.1k": b"\x7fELF openssl\n",
    "lib/arm64-v8a/libsqlite-3.27.0.so": b"\x7fELF sqlite\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "sample-app.apk")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in ENTRIES.items():
            zf.writestr(name, data)
    print("wrote", out)


if __name__ == "__main__":
    main()
