"""(Re)generate demos/08-game-adtech/game.apk.

A free-to-play mobile game packed with monetization/ad SDKs (a privacy-review
red flag) plus older native media libs with documented advisories. Useful for
demonstrating a tracker-heavy SBOM and an app-store privacy compliance review.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

ENTRIES = {
    "AndroidManifest.xml": b"<manifest package='com.acme.game'/>\n",
    "classes.dex": b"dex\n035\x00\n",
    "lib/arm64-v8a/libunity.so": b"\x7fELF unity\n",
    # Ad / monetization SDKs (all tracker DB entries):
    "com/unity3d/ads/UnityAds.class": b"CAFEBABE unityads\n",
    "com/applovin/sdk/AppLovinSdk.class": b"CAFEBABE applovin\n",
    "com/flurry/android/FlurryAgent.class": b"CAFEBABE flurry\n",
    "com/facebook/ads/AudienceNetworkAds.class": b"CAFEBABE fban\n",
    "com/appsflyer/AppsFlyerLib.class": b"CAFEBABE appsflyer\n",
    # Older native media libs:
    # libpng 1.6.36 < 1.6.37 -> CVE-2019-7317 (use-after-free).
    "lib/arm64-v8a/libpng16.so.1.6.36": b"\x7fELF png\n",
    # zlib 1.2.11 < 1.2.12 -> CVE-2018-25032 (memory corruption).
    "lib/arm64-v8a/libz.so.1.2.11": b"\x7fELF zlib\n",
    "res/values/strings.xml": b"<resources/>\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "game.apk")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
