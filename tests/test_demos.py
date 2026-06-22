"""Verify every shipped demo fixture scans and produces its documented findings.

Each demo ships a generator (`make_sample.py`) and a committed fixture. These
tests (re)build the fixture in-process and assert the key findings so the demos
can never silently drift from their SCENARIO.md.
"""
import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sbomx import core  # noqa: E402

DEMOS = os.path.join(ROOT, "demos")


def _build(demo: str):
    """Run a demo's make_sample.py and return the produced fixture path."""
    path = os.path.join(DEMOS, demo, "make_sample.py")
    spec = importlib.util.spec_from_file_location(f"demo_{demo}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
    # the fixture is the only .apk/.ipa in the demo dir
    for fn in os.listdir(os.path.join(DEMOS, demo)):
        if fn.endswith((".apk", ".ipa")):
            return os.path.join(DEMOS, demo, fn)
    raise AssertionError("no fixture produced for " + demo)


def test_demo_04_ios_banking():
    r = core.scan(_build("04-ios-banking"))
    ids = {f.id for f in r.vulnerabilities}
    assert "CVE-2022-0778" in ids and "CVE-2020-24613" in ids
    assert any(c.key == "alamofire" for c in r.components)


def test_demo_05_react_native():
    r = core.scan(_build("05-react-native-ecommerce"))
    ids = {f.id for f in r.vulnerabilities}
    assert "CVE-2021-0341" in ids and "CVE-2020-8771" in ids
    tk = {f.component_key for f in r.trackers}
    assert {"adjust", "mixpanel"} <= tk


def test_demo_06_clean_release():
    r = core.scan(_build("06-clean-release"))
    assert r.vulnerabilities == []
    assert len(r.components) == 6


def test_demo_07_manifest_resolve():
    apk = _build("07-manifest-resolve")
    # without manifest -> potential (version unknown)
    r = core.scan(apk)
    assert all(not f.version_known for f in r.vulnerabilities)
    # with manifest -> resolved versions
    manifest = {"openssl": "1.0.2g", "sqlite": "3.25.0", "okhttp": "4.9.1"}
    r2 = core.scan(apk, manifest)
    ids = {f.id for f in r2.vulnerabilities}
    assert "CVE-2016-2107" in ids  # only fires when version is known
    assert all(f.version_known for f in r2.vulnerabilities)


def test_demo_08_game_adtech():
    r = core.scan(_build("08-game-adtech"))
    ids = {f.id for f in r.vulnerabilities}
    assert "CVE-2019-7317" in ids and "CVE-2018-25032" in ids
    assert len(r.trackers) == 5


def test_demo_09_flutter():
    r = core.scan(_build("09-flutter-app"))
    sev = {f.severity for f in r.vulnerabilities}
    assert sev == {"high"}
    assert len(r.vulnerabilities) == 3


def test_demo_10_extracted_dir_sarif():
    target = os.path.join(DEMOS, "10-ci-sarif-gate", "extracted_app")
    r = core.scan(target)
    ids = {f.id for f in r.vulnerabilities}
    assert "CVE-2022-25647" in ids and "CVE-2019-8457" in ids
    log = core.build_sarif(r, "sbomx", "test")
    assert log["version"] == "2.1.0"
    assert len(log["runs"][0]["results"]) == len(r.findings)
