"""Hardening tests: error paths, edge cases, and bad-input handling for SBOMX."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbomx import core
from sbomx.cli import main


# ---------------------------------------------------------------------------
# core._iter_archive_paths / scan: nonexistent and invalid targets
# ---------------------------------------------------------------------------

def test_scan_missing_file_raises():
    with pytest.raises(FileNotFoundError, match="does not exist"):
        core.scan("/nonexistent/path/to/app.apk")


def test_scan_not_zip_not_dir_raises(tmp_path):
    bad = tmp_path / "notazip.apk"
    bad.write_bytes(b"this is not a zip file at all")
    with pytest.raises(ValueError, match="neither a zip"):
        core.scan(str(bad))


def test_scan_empty_directory_returns_no_components(tmp_path):
    d = tmp_path / "empty_app"
    d.mkdir()
    result = core.scan(str(d))
    assert result.components == []
    assert result.findings == []


# ---------------------------------------------------------------------------
# core._parse_version: malformed version strings
# ---------------------------------------------------------------------------

def test_parse_version_double_dot():
    # "1..2" has an empty chunk — must not raise
    result = core._parse_version("1..2")
    assert isinstance(result, tuple)


def test_parse_version_leading_dot():
    result = core._parse_version(".5.0")
    assert isinstance(result, tuple)


def test_cmp_versions_empty_chunks():
    # Should not raise, just compare gracefully
    assert core._cmp_versions("1..0", "1.0.0") in (-1, 0, 1)


# ---------------------------------------------------------------------------
# core.build_cyclonedx: malformed CWE strings
# ---------------------------------------------------------------------------

def test_build_cyclonedx_malformed_cwe(tmp_path):
    """build_cyclonedx must not crash when a CWE string has no dash-number."""
    comp = core.Component(
        key="okhttp", name="okhttp", version="4.9.0",
        ecosystem="maven", purl_type="maven",
        group="com.squareup.okhttp3", evidence="libs/okhttp-4.9.0.jar",
    )
    finding = core.Finding(
        kind="vulnerability", component_key="okhttp", component_name="okhttp",
        component_version="4.9.0", id="CVE-2021-0341", severity="medium",
        summary="test", fixed_version="4.9.2", version_known=True,
        extra={"cwe": "CWE-"},          # missing number after dash
    )
    result = core.ScanResult(components=[comp], findings=[finding], target="test.apk")
    bom = core.build_cyclonedx(result, "sbomx", "0.1.0")
    vuln = bom["vulnerabilities"][0]
    assert vuln["cwes"] == []           # gracefully empty, not a crash


def test_build_cyclonedx_no_cwe():
    comp = core.Component(
        key="okhttp", name="okhttp", version="4.9.0",
        ecosystem="maven", purl_type="maven",
        group="com.squareup.okhttp3", evidence="x",
    )
    finding = core.Finding(
        kind="vulnerability", component_key="okhttp", component_name="okhttp",
        component_version="4.9.0", id="CVE-2021-0341", severity="medium",
        summary="test", fixed_version="4.9.2", version_known=True,
        extra={},                        # no "cwe" key at all
    )
    result = core.ScanResult(components=[comp], findings=[finding], target="x.apk")
    bom = core.build_cyclonedx(result, "sbomx", "0.1.0")
    assert bom["vulnerabilities"][0]["cwes"] == []


# ---------------------------------------------------------------------------
# core.to_json: new public helper
# ---------------------------------------------------------------------------

def test_to_json_returns_valid_json(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "okhttp3").mkdir()
    (d / "okhttp3" / "OkHttpClient.class").write_text("x")
    result = core.scan(str(d))
    js = core.to_json(result)
    bom = json.loads(js)
    assert bom["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# CLI: missing file -> exit 2, malformed manifest JSON -> exit 2
# ---------------------------------------------------------------------------

def test_cli_missing_target_exits_2(capsys):
    rc = main(["scan", "/no/such/file.apk"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_malformed_manifest_exits_2(tmp_path, capsys):
    d = tmp_path / "app"
    d.mkdir()
    bad_manifest = tmp_path / "bad.json"
    bad_manifest.write_text("{not valid json}")
    rc = main(["scan", str(d), "--manifest", str(bad_manifest)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_manifest_not_an_object_exits_2(tmp_path, capsys):
    d = tmp_path / "app"
    d.mkdir()
    array_manifest = tmp_path / "array.json"
    array_manifest.write_text('["okhttp", "4.9.0"]')
    rc = main(["scan", str(d), "--manifest", str(array_manifest)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


def test_cli_no_subcommand_exits_2(capsys):
    rc = main([])
    assert rc == 2


def test_cli_empty_dir_exits_0_with_fail_on_never(tmp_path, capsys):
    d = tmp_path / "empty"
    d.mkdir()
    rc = main(["scan", str(d), "--fail-on", "never"])
    capsys.readouterr()
    assert rc == 0
