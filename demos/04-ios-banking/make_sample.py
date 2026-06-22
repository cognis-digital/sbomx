"""(Re)generate demos/04-ios-banking/banking.ipa — an iOS .ipa fixture.

An .ipa is a ZIP under `Payload/<App>.app/`. This mimics a retail banking app
that bundles CocoaPods frameworks, one of which (Realm) ships at a version with
a documented advisory in SBOMX's DB.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _gen_common import write_apk  # noqa: E402

APP = "Payload/AcmeBank.app/"
ENTRIES = {
    APP + "Info.plist": b"<plist><dict><key>CFBundleIdentifier</key>"
                        b"<string>com.acme.bank</string></dict></plist>\n",
    APP + "AcmeBank": b"\xca\xfe\xba\xbe mach-o placeholder\n",
    # Networking frameworks (CocoaPods). AFNetworking has no advisory here, but
    # it is a real, detectable component for the SBOM inventory.
    APP + "Frameworks/Alamofire.framework/Alamofire": b"\xca\xfe\xba\xbe alamofire\n",
    APP + "Frameworks/Alamofire.framework/Info.plist": b"<plist/>\n",
    APP + "Frameworks/AFNetworking.framework/AFNetworking": b"\xca\xfe\xba\xbe afn\n",
    APP + "Frameworks/SDWebImage.framework/SDWebImage": b"\xca\xfe\xba\xbe sdwi\n",
    # Realm 9.8.0 < 10.0.0 -> CVE-2020-24613 (TLS cert not validated).
    APP + "Frameworks/Realm.framework/Realm-9.8.0": b"\xca\xfe\xba\xbe realm\n",
    # Native crypto shipped inside the app: openssl 1.1.1k < 1.1.1n -> CVE-2022-0778.
    APP + "Frameworks/libssl.so.1.1.1k": b"\x7fELF openssl\n",
}


def main() -> None:
    out = os.path.join(os.path.dirname(__file__), "banking.ipa")
    write_apk(out, ENTRIES)
    print("wrote", out)


if __name__ == "__main__":
    main()
