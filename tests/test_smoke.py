"""Smoke tests for SBOMX.

These build the demo .apk on the fly (no network), run the real engine and CLI,
and assert real detection / matching behavior.
"""
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbomx import core, TOOL_NAME, TOOL_VERSION
from sbomx.cli import main


DEMO_APK = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "sample-app.apk",
)

ENTRIES = {
    "AndroidManifest.xml": b"<manifest/>",
    "libs/okhttp-4.9.0.jar": b"x",
    "okhttp3/OkHttpClient.class": b"x",
    "com/google/gson/Gson.class": b"x",
    "com/google/firebase/crashlytics/FirebaseCrashlytics.class": b"x",
    "com/appsflyer/AppsFlyerLib.class": b"x",
    "lib/arm64-v8a/libssl.so.1.1.1k": b"x",
    "lib/arm64-v8a/libsqlite-3.27.0.so": b"x",
}


@pytest.fixture(scope="module")
def apk(tmp_path_factory):
    if os.path.exists(DEMO_APK):
        return DEMO_APK
    path = tmp_path_factory.mktemp("app") / "sample-app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in ENTRIES.items():
            zf.writestr(name, data)
    return str(path)


def test_version_comparison():
    assert core._cmp_versions("4.9.0", "4.9.2") < 0
    assert core._cmp_versions("1.1.1k", "1.1.1n") < 0
    assert core._cmp_versions("3.28.0", "3.27.0") > 0
    assert core._cmp_versions("1.2.12", "1.2.12") == 0


def test_detection_finds_known_libs(apk):
    comps = {c.key: c for c in core.detect_components(apk)}
    assert "okhttp" in comps
    assert comps["okhttp"].version == "4.9.0"
    assert "openssl" in comps
    assert comps["openssl"].version == "1.1.1k"
    assert "sqlite" in comps and comps["sqlite"].version == "3.27.0"
    assert "gson" in comps


def test_purl_format(apk):
    comps = {c.key: c for c in core.detect_components(apk)}
    assert comps["okhttp"].purl() == "pkg:maven/com.squareup.okhttp3/okhttp@4.9.0"


def test_findings_vulns_and_trackers(apk):
    result = core.scan(apk)
    vuln_ids = {f.id for f in result.vulnerabilities}
    assert "CVE-2021-0341" in vuln_ids   # okhttp 4.9.0 < 4.9.2
    assert "CVE-2022-0778" in vuln_ids   # openssl 1.1.1k < 1.1.1n
    assert "CVE-2019-8457" in vuln_ids   # sqlite 3.27.0 < 3.28.0
    tracker_keys = {f.component_key for f in result.trackers}
    assert "crashlytics" in tracker_keys
    assert "appsflyer" in tracker_keys


def test_safe_version_not_flagged():
    # okhttp at the fixed version should NOT match CVE-2021-0341
    comp = core.Component(key="okhttp", name="okhttp", version="4.9.2",
                          ecosystem="maven", purl_type="maven",
                          group="com.squareup.okhttp3", evidence="x")
    findings = core.match_findings([comp])
    assert all(f.id != "CVE-2021-0341" for f in findings if f.kind == "vulnerability")


def test_cyclonedx_structure(apk):
    result = core.scan(apk)
    bom = core.build_cyclonedx(result, TOOL_NAME, TOOL_VERSION)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert len(bom["components"]) >= 4
    assert any(v["id"] == "CVE-2021-0341" for v in bom["vulnerabilities"])
    # JSON must round-trip
    json.loads(json.dumps(bom))


def test_cli_json_and_exit_code(apk, capsys):
    rc = main(["scan", apk, "--format", "json"])
    out = capsys.readouterr().out
    bom = json.loads(out)
    assert bom["bomFormat"] == "CycloneDX"
    assert rc == 1  # findings exist -> non-zero with default --fail-on info


def test_cli_fail_on_never(apk, capsys):
    rc = main(["scan", apk, "--format", "table", "--fail-on", "never"])
    capsys.readouterr()
    assert rc == 0


def test_cli_fail_on_high_table(apk, capsys):
    rc = main(["scan", apk, "--fail-on", "high"])
    out = capsys.readouterr().out
    assert "Vulnerabilities" in out
    assert rc == 1  # openssl + sqlite are high severity


def test_directory_scan(tmp_path):
    d = tmp_path / "unpacked"
    (d / "okhttp3").mkdir(parents=True)
    (d / "okhttp3" / "OkHttpClient.class").write_text("x")
    (d / "libs").mkdir()
    (d / "libs" / "okhttp-4.9.0.jar").write_text("x")
    result = core.scan(str(d))
    assert any(c.key == "okhttp" for c in result.components)
