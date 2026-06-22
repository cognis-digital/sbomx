"""Tests for the SARIF 2.1.0 and CSV export formats."""
import csv
import io
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbomx import core, TOOL_NAME, TOOL_VERSION
from sbomx.cli import main

ENTRIES = {
    "AndroidManifest.xml": b"<manifest/>",
    "libs/okhttp-4.9.0.jar": b"x",
    "okhttp3/OkHttpClient.class": b"x",
    "lib/arm64-v8a/libssl.so.1.1.1k": b"x",
    "lib/arm64-v8a/libsqlite-3.27.0.so": b"x",
    "com/appsflyer/AppsFlyerLib.class": b"x",
}


@pytest.fixture(scope="module")
def apk(tmp_path_factory):
    path = tmp_path_factory.mktemp("app") / "sample.apk"
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in ENTRIES.items():
            zf.writestr(name, data)
    return str(path)


# --- SARIF ---------------------------------------------------------------

def test_sarif_top_level_shape(apk):
    result = core.scan(apk)
    log = core.build_sarif(result, TOOL_NAME, TOOL_VERSION)
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(log["runs"]) == 1
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == TOOL_NAME
    # one result per finding
    assert len(run["results"]) == len(result.findings)
    # round-trips as JSON
    json.loads(json.dumps(log))


def test_sarif_rules_deduped_and_linked(apk):
    result = core.scan(apk)
    log = core.build_sarif(result, TOOL_NAME, TOOL_VERSION)
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))  # no dup rules
    # every result.ruleIndex points at a real rule with matching id
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["partialFingerprints"]["sbomxFinding/v1"]


def test_sarif_severity_levels(apk):
    result = core.scan(apk)
    log = core.build_sarif(result, TOOL_NAME, TOOL_VERSION)
    by_id = {r["ruleId"]: r for r in log["runs"][0]["results"]}
    assert by_id["CVE-2022-0778"]["level"] == "error"    # openssl HIGH
    assert by_id["CVE-2021-0341"]["level"] == "warning"  # okhttp MEDIUM
    # tracker -> note
    assert any(r["level"] == "note" for r in log["runs"][0]["results"])


def test_sarif_security_severity_and_cwe(apk):
    result = core.scan(apk)
    log = core.build_sarif(result, TOOL_NAME, TOOL_VERSION)
    rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
    rule = rules["CVE-2022-0778"]
    assert rule["properties"]["security-severity"] == "8.0"
    assert rule["properties"]["cwe"] == "CWE-835"
    assert rule["helpUri"].endswith("CVE-2022-0778")


def test_cli_sarif_output(apk, capsys):
    rc = main(["scan", apk, "--format", "sarif", "--fail-on", "never"])
    log = json.loads(capsys.readouterr().out)
    assert log["version"] == "2.1.0"
    assert rc == 0


# --- CSV -----------------------------------------------------------------

def test_csv_header_and_rows(apk):
    result = core.scan(apk)
    text = core.build_csv(result)
    rows = list(csv.reader(io.StringIO(text)))
    header = rows[0]
    assert header[:5] == ["kind", "id", "severity", "component", "version"]
    assert len(rows) - 1 == len(result.findings)
    # vulnerabilities sorted before trackers
    kinds = [r[0] for r in rows[1:]]
    assert kinds == sorted(kinds, key=lambda k: 0 if k == "vulnerability" else 1)


def test_csv_quotes_commas(apk):
    result = core.scan(apk)
    text = core.build_csv(result)
    # a tracker summary contains a comma-joined category list; csv must quote it
    rows = list(csv.reader(io.StringIO(text)))
    appsflyer = [r for r in rows if r[3] == "appsflyer"]
    assert appsflyer and "Advertisement" in appsflyer[0][8]


def test_cli_csv_output(apk, capsys):
    rc = main(["scan", apk, "--format", "csv", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert out.startswith("kind,id,severity,component,version")
    assert rc == 0
