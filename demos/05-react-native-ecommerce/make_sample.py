"""(Re)generate demos/05-react-native-ecommerce/shop.apk.

A React Native e-commerce Android app. Ships react-native, an old okhttp and
an old Glide (both with advisories), plus a stack of marketing/analytics SDKs.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.shop'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    # React Native runtime (inventory component).
    "com/facebook/react/ReactInstanceManager.class": b"CAFEBABE rn\n",
    "lib/arm64-v8a/libreactnativejni.so": b"\x7fELF rn\n",
    # okhttp 4.9.0 < 4.9.2 -> CVE-2021-0341.
    "libs/okhttp-4.9.0.jar": b"PK okhttp\n",
    "okhttp3/OkHttpClient.class": b"CAFEBABE okhttp\n",
    # Glide 4.10.0 < 4.11.0 -> CVE-2020-8771 (accepts non-HTTPS image URLs).
    "libs/glide-4.10.0.jar": b"PK glide\n",
    "com/bumptech/glide/Glide.class": b"CAFEBABE glide\n",
    # Trackers: Adjust + Mixpanel + Firebase Analytics.
    "com/adjust/sdk/Adjust.class": b"CAFEBABE adjust\n",
    "com/mixpanel/android/mpmetrics/MixpanelAPI.class": b"CAFEBABE mixpanel\n",
    "com/google/firebase/analytics/FirebaseAnalytics.class": b"CAFEBABE fb\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "shop.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
