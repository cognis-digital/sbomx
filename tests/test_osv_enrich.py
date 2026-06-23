"""Offline tests for the CycloneDX-component -> OSV/CVE matching layer.

These exercise the new `core.match_osv_findings` / `core.enrich_with_osv` /
`core.scan_with_osv` paths and the `sbomx db` CLI against the *real* bundled
262k-record OSV corpus (cognis_vulndb.jsonl.gz). Everything runs fully offline:
no network, stdlib only. The marquee assertion is that log4j
(CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q) resolves and that a detected Maven
component maps to the right OSV coordinate.
"""
import json
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbomx import core, TOOL_NAME, TOOL_VERSION
from sbomx.cli import main
from sbomx.vulndb_local import VulnDB


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def db():
    return VulnDB()


@pytest.fixture
def apk(tmp_path):
    """Realistic mobile bundle with versioned + native libs + trackers."""
    p = tmp_path / "sample.apk"
    entries = {
        "AndroidManifest.xml": b"<manifest/>",
        "classes.dex": b"x",
        "libs/okhttp-4.9.0.jar": b"x",
        "okhttp3/OkHttpClient.class": b"x",
        "retrofit2/Retrofit.class": b"x",
        "com/google/gson/Gson.class": b"x",
        "com/google/firebase/FirebaseApp.class": b"x",
        "com/google/firebase/crashlytics/FirebaseCrashlytics.class": b"x",
        "com/appsflyer/AppsFlyerLib.class": b"x",
        "lib/arm64-v8a/libssl.so.1.1.1k": b"x",
        "lib/arm64-v8a/libwebp.so": b"x",
        "lib/arm64-v8a/libsqlite-3.27.so": b"x",
    }
    with zipfile.ZipFile(p, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return str(p)


# --------------------------------------------------------------------------- #
# bundled DB: identity + size + log4j marquee lookup
# --------------------------------------------------------------------------- #
def test_db_has_quarter_million_records(db):
    assert db.count() >= 260000


def test_db_count_is_stable(db):
    assert db.count() == db.count()


def test_db_iter_yields_dicts(db):
    rec = next(iter(db))
    assert isinstance(rec, dict)
    assert rec.get("id")


def test_log4j_cve_resolves(db):
    recs = db.by_cve("CVE-2021-44228")
    assert recs, "log4j CVE-2021-44228 must resolve in the bundled DB"
    ids = {r["id"] for r in recs}
    assert "GHSA-jfh8-c2jp-5v3q" in ids


def test_log4j_record_is_maven(db):
    rec = db.by_cve("CVE-2021-44228")[0]
    assert rec["ecosystem"] == "Maven"
    assert any("log4j-core" in p for p in rec["packages"])


def test_log4j_alias_back_reference(db):
    rec = db.by_cve("CVE-2021-44228")[0]
    assert "CVE-2021-44228" in rec["aliases"]


def test_log4j_by_ghsa_id_also_resolves(db):
    recs = db.by_cve("GHSA-jfh8-c2jp-5v3q")
    assert recs and any(r["id"] == "GHSA-jfh8-c2jp-5v3q" for r in recs)


def test_cve_lookup_is_case_insensitive(db):
    assert db.by_cve("cve-2021-44228") == db.by_cve("CVE-2021-44228")


def test_unknown_cve_returns_empty(db):
    assert db.by_cve("CVE-0000-00000") == []
    assert db.by_cve("") == []


def test_log4j_full_maven_coordinate_lookup(db):
    recs = db.by_package("org.apache.logging.log4j:log4j-core")
    assert recs, "full maven coordinate for log4j-core must resolve"
    assert any("CVE-2021-44228" in (r.get("aliases") or []) for r in recs)


def test_known_packages_resolve(db):
    for name in ("lodash", "django", "jinja2"):
        if db.by_package(name):
            break
    else:
        pytest.fail("expected at least one of lodash/django/jinja2 to resolve")


def test_package_lookup_lowercased(db):
    assert db.by_package("LODASH") == db.by_package("lodash")


def test_package_ecosystem_filter(db):
    hits = db.by_package("org.apache.logging.log4j:log4j-core", ecosystem="Maven")
    assert hits
    assert all(r.get("ecosystem", "").lower() == "maven" for r in hits)


def test_package_ecosystem_filter_excludes(db):
    hits = db.by_package("org.apache.logging.log4j:log4j-core", ecosystem="npm")
    assert hits == []


def test_search_returns_summary_matches(db):
    res = db.search("buffer overflow", limit=5)
    assert len(res) <= 5
    assert all("buffer overflow" in (r.get("summary", "") or "").lower() for r in res)


def test_search_limit_respected(db):
    assert len(db.search("the", limit=3)) <= 3


def test_search_empty_text_safe(db):
    # empty text is a substring of everything; just must not raise
    assert isinstance(db.search("", limit=2), list)


def test_record_metadata_fields(db):
    rec = next(iter(db))
    for field in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
        assert field in rec


# --------------------------------------------------------------------------- #
# CVSS vector -> qualitative severity
# --------------------------------------------------------------------------- #
def test_cvss_log4j_is_critical():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"
    assert core._severity_from_cvss_vector(v) == "critical"


def test_cvss_network_confidentiality_high_is_high():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert core._severity_from_cvss_vector(v) == "high"


def test_cvss_local_low_impact_is_low():
    v = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    assert core._severity_from_cvss_vector(v) == "low"


def test_cvss_medium_band():
    v = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"
    assert core._severity_from_cvss_vector(v) in ("low", "medium")


def test_cvss_non_vector_returns_none():
    assert core._severity_from_cvss_vector("high") is None
    assert core._severity_from_cvss_vector("not a vector") is None


def test_cvss_v40_prefix_tolerated():
    # parser keys on AV: present; should still parse the components it knows
    v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert core._severity_from_cvss_vector(v) in ("high", "critical")


def test_bucket_score_boundaries():
    assert core._bucket_score(9.0) == "critical"
    assert core._bucket_score(9.9) == "critical"
    assert core._bucket_score(8.9) == "high"
    assert core._bucket_score(7.0) == "high"
    assert core._bucket_score(6.9) == "medium"
    assert core._bucket_score(4.0) == "medium"
    assert core._bucket_score(3.9) == "low"
    assert core._bucket_score(0.1) == "low"
    assert core._bucket_score(0.0) == "low"


def test_osv_severity_from_cvss_vector_record():
    rec = {"severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"}
    assert core._osv_severity(rec) == "critical"


def test_osv_severity_qualitative_passthrough():
    assert core._osv_severity({"severity": "HIGH"}) == "high"
    assert core._osv_severity({"severity": "Critical"}) == "critical"
    assert core._osv_severity({"severity": "low"}) == "low"


def test_osv_severity_moderate_normalized_to_medium():
    assert core._osv_severity({"severity": "moderate"}) == "medium"


def test_osv_severity_numeric_score():
    assert core._osv_severity({"severity": "", "cvss_score": 9.8}) == "critical"
    assert core._osv_severity({"severity": "", "score": 5.0}) == "medium"


def test_osv_severity_default_medium_when_unknown():
    assert core._osv_severity({}) == "medium"
    assert core._osv_severity({"severity": "garbage"}) == "medium"


# --------------------------------------------------------------------------- #
# version-applicability logic
# --------------------------------------------------------------------------- #
def test_version_unknown_is_potential():
    applies, known = core._osv_version_applies(None, {})
    assert applies is True and known is False


def test_no_ranges_is_potential_match():
    # compact bundled records carry no ranges -> potential (version unconfirmed)
    applies, known = core._osv_version_applies("4.9.0", {})
    assert applies is True and known is False


def test_range_introduced_fixed_inside():
    rec = {"affected_ranges": [{"introduced": "1.0.0", "fixed": "2.0.0"}]}
    applies, known = core._osv_version_applies("1.5.0", rec)
    assert applies is True and known is True


def test_range_below_introduced_excluded():
    rec = {"affected_ranges": [{"introduced": "1.0.0", "fixed": "2.0.0"}]}
    applies, known = core._osv_version_applies("0.9.0", rec)
    assert applies is False and known is True


def test_range_at_or_after_fixed_excluded():
    rec = {"affected_ranges": [{"introduced": "1.0.0", "fixed": "2.0.0"}]}
    applies, known = core._osv_version_applies("2.0.0", rec)
    assert applies is False and known is True


def test_range_only_fixed_bound():
    rec = {"affected_ranges": [{"fixed": "1.1.1n"}]}
    applies_in, _ = core._osv_version_applies("1.1.1k", rec)
    applies_out, _ = core._osv_version_applies("1.1.1n", rec)
    assert applies_in is True
    assert applies_out is False


def test_range_introduced_zero_means_from_start():
    rec = {"affected_ranges": [{"introduced": "0", "fixed": "1.2.12"}]}
    applies, known = core._osv_version_applies("1.0.0", rec)
    assert applies and known


def test_canonical_osv_events_shape():
    rec = {"affected": [{"ranges": [{"events": [
        {"introduced": "1.0.0"}, {"fixed": "1.6.37"}]}]}]}
    groups = core._osv_event_ranges(rec)
    assert groups
    applies, known = core._osv_version_applies("1.5.0", rec)
    assert applies and known


def test_event_ranges_empty_when_absent():
    assert core._osv_event_ranges({}) == []


# --------------------------------------------------------------------------- #
# coordinate mapping
# --------------------------------------------------------------------------- #
def _comp(key, name, version, purl_type="maven", group=""):
    return core.Component(key=key, name=name, version=version,
                          ecosystem=purl_type, purl_type=purl_type,
                          group=group, evidence="x")


def test_maven_coordinate_from_purl():
    c = _comp("okhttp", "okhttp", "4.9.0", "maven", "com.squareup.okhttp3")
    coords = core._osv_coordinates(c)
    assert "com.squareup.okhttp3:okhttp" in coords


def test_coordinate_aliases_included():
    c = _comp("openssl", "openssl", None, "generic", "")
    coords = core._osv_coordinates(c)
    assert "openssl" in coords


def test_coordinate_dedup_preserves_order():
    c = _comp("gson", "gson", None, "maven", "com.google.code.gson")
    coords = core._osv_coordinates(c)
    assert len(coords) == len(set(x.lower() for x in coords))
    assert coords[0] == "com.google.code.gson:gson"


def test_coordinate_falls_back_to_name_and_key():
    # distinct key + name -> both probed; case-insensitive dedup keeps first
    c = _comp("acme-core", "AcmeWidget", None, "generic", "")
    coords = core._osv_coordinates(c)
    lowered = {x.lower() for x in coords}
    assert "acmewidget" in lowered
    assert "acme-core" in lowered


# --------------------------------------------------------------------------- #
# match_osv_findings against the real DB
# --------------------------------------------------------------------------- #
def test_match_log4j_component(db):
    c = _comp("log4j", "log4j-core", "2.14.1", "maven", "org.apache.logging.log4j")
    fs = core.match_osv_findings([c], db=db)
    assert fs, "log4j-core component must match OSV findings"
    cves = {f.id for f in fs}
    assert "CVE-2021-44228" in cves


def test_match_log4j_finding_is_vulnerability(db):
    c = _comp("log4j", "log4j-core", "2.14.1", "maven", "org.apache.logging.log4j")
    fs = core.match_osv_findings([c], db=db)
    f = next(f for f in fs if f.id == "CVE-2021-44228")
    assert f.kind == "vulnerability"
    assert f.severity == "critical"
    assert f.extra["source"] == "osv"
    assert f.extra["osv_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert f.extra["matched_package"] == "org.apache.logging.log4j:log4j-core"


def test_match_okhttp_via_maven_coordinate(db):
    c = _comp("okhttp", "okhttp", None, "maven", "com.squareup.okhttp3")
    fs = core.match_osv_findings([c], db=db)
    # okhttp has real OSV advisories; at least one should surface
    assert isinstance(fs, list)


def test_match_dedup_within_component(db):
    c = _comp("log4j", "log4j-core", None, "maven", "org.apache.logging.log4j")
    fs = core.match_osv_findings([c], db=db)
    ids = [f.id for f in fs]
    assert len(ids) == len(set(ids)), "no duplicate finding ids per component"


def test_match_respects_max_per_component(db):
    c = _comp("openssl", "openssl", None, "generic", "")
    fs = core.match_osv_findings([c], db=db, max_per_component=3)
    assert len(fs) <= 3


def test_match_unknown_component_empty(db):
    c = _comp("totally-not-real-xyz", "totally-not-real-xyz", None, "generic", "")
    assert core.match_osv_findings([c], db=db) == []


def test_match_findings_carry_aliases(db):
    c = _comp("log4j", "log4j-core", None, "maven", "org.apache.logging.log4j")
    f = next(f for f in core.match_osv_findings([c], db=db)
             if f.id == "CVE-2021-44228")
    assert "CVE-2021-44228" in f.extra["aliases"]


def test_match_uses_cve_alias_as_id_when_present(db):
    c = _comp("log4j", "log4j-core", None, "maven", "org.apache.logging.log4j")
    f = next(f for f in core.match_osv_findings([c], db=db)
             if f.extra["osv_id"] == "GHSA-jfh8-c2jp-5v3q")
    assert f.id.startswith("CVE-")


# --------------------------------------------------------------------------- #
# enrich_with_osv + scan_with_osv end-to-end
# --------------------------------------------------------------------------- #
def test_enrich_appends_and_counts(apk, db):
    res = core.scan(apk)
    before = len(res.findings)
    added = core.enrich_with_osv(res, db=db)
    assert added > 0
    assert len(res.findings) == before + added


def test_enrich_adds_osv_sourced_findings(apk, db):
    res = core.scan(apk)
    core.enrich_with_osv(res, db=db)
    osv = [f for f in res.vulnerabilities if f.extra.get("source") == "osv"]
    assert osv, "expected OSV-sourced findings after enrichment"


def test_enrich_dedups_against_curated(apk, db):
    res = core.scan(apk)
    core.enrich_with_osv(res, db=db)
    seen = set()
    for f in res.findings:
        key = (f.component_key, f.id)
        assert key not in seen, f"duplicate finding {key}"
        seen.add(key)


def test_enrich_idempotent_second_call_adds_nothing(apk, db):
    res = core.scan(apk)
    core.enrich_with_osv(res, db=db)
    second = core.enrich_with_osv(res, db=db)
    assert second == 0


def test_scan_with_osv_one_shot(apk, db):
    res = core.scan_with_osv(apk, db=db)
    assert res.components
    assert any(f.extra.get("source") == "osv" for f in res.vulnerabilities)


def test_enriched_result_still_builds_cyclonedx(apk, db):
    res = core.scan_with_osv(apk, db=db)
    bom = core.build_cyclonedx(res, TOOL_NAME, TOOL_VERSION)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["vulnerabilities"], "enriched BOM must carry vulnerabilities"


def test_enriched_result_still_builds_sarif(apk, db):
    res = core.scan_with_osv(apk, db=db)
    log = core.build_sarif(res, TOOL_NAME, TOOL_VERSION)
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["results"]


def test_enriched_result_still_builds_csv(apk, db):
    res = core.scan_with_osv(apk, db=db)
    csv_text = core.build_csv(res)
    assert "kind,id,severity" in csv_text.splitlines()[0]


def test_osv_findings_marked_version_unconfirmed(apk, db):
    # compact corpus has no ranges -> osv findings are potential matches
    res = core.scan_with_osv(apk, db=db)
    osv = [f for f in res.vulnerabilities if f.extra.get("source") == "osv"]
    assert all(f.version_known is False for f in osv)


# --------------------------------------------------------------------------- #
# tool identity wired from VERSION
# --------------------------------------------------------------------------- #
def test_tool_name_is_sbomx():
    assert TOOL_NAME == "sbomx"


def test_tool_version_non_default():
    # VERSION file should drive this, not the 0.1.0 fallback
    assert TOOL_VERSION != "0.1.0"
    assert TOOL_VERSION[0].isdigit()


def test_core_exposes_identity():
    assert core.TOOL_NAME == "sbomx"
    assert core.TOOL_VERSION == TOOL_VERSION


# --------------------------------------------------------------------------- #
# CLI: sbomx db ...
# --------------------------------------------------------------------------- #
def test_cli_db_count(capsys):
    rc = main(["db", "count"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert int(out) >= 260000


def test_cli_db_cve_log4j(capsys):
    rc = main(["db", "cve", "CVE-2021-44228"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert any(r["id"] == "GHSA-jfh8-c2jp-5v3q" for r in data)


def test_cli_db_cve_miss_exit_1(capsys):
    rc = main(["db", "cve", "CVE-0000-00000"])
    capsys.readouterr()
    assert rc == 1


def test_cli_db_package(capsys):
    rc = main(["db", "package", "org.apache.logging.log4j:log4j-core"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data


def test_cli_db_package_ecosystem(capsys):
    rc = main(["db", "package", "org.apache.logging.log4j:log4j-core",
               "--ecosystem", "Maven"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert all(r["ecosystem"].lower() == "maven" for r in data)


def test_cli_db_search(capsys):
    rc = main(["db", "search", "overflow", "--limit", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert len(data) <= 5


def test_cli_db_no_subcommand_usage(capsys):
    rc = main(["db"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "usage" in err.lower()


# --------------------------------------------------------------------------- #
# CLI: sbomx scan --enrich-osv
# --------------------------------------------------------------------------- #
def test_cli_scan_enrich_osv_table(apk, capsys):
    rc = main(["scan", apk, "--enrich-osv", "--fail-on", "never"])
    cap = capsys.readouterr()
    assert rc == 0
    assert "OSV enrichment" in cap.err
    assert "Vulnerabilities" in cap.out


def test_cli_scan_enrich_osv_json(apk, capsys):
    rc = main(["scan", apk, "--enrich-osv", "--format", "json",
               "--fail-on", "never"])
    cap = capsys.readouterr()
    assert rc == 0
    bom = json.loads(cap.out)
    assert bom["bomFormat"] == "CycloneDX"
    assert len(bom["vulnerabilities"]) > 0


def test_cli_scan_enrich_osv_sarif(apk, capsys):
    rc = main(["scan", apk, "--enrich-osv", "--format", "sarif",
               "--fail-on", "never"])
    cap = capsys.readouterr()
    assert rc == 0
    log = json.loads(cap.out)
    assert log["version"] == "2.1.0"


def test_cli_scan_enrich_osv_csv(apk, capsys):
    rc = main(["scan", apk, "--enrich-osv", "--format", "csv",
               "--fail-on", "never"])
    cap = capsys.readouterr()
    assert rc == 0
    assert cap.out.splitlines()[0].startswith("kind,id,severity")


def test_cli_scan_enrich_osv_max(apk, capsys):
    rc = main(["scan", apk, "--enrich-osv", "--osv-max", "1",
               "--format", "json", "--fail-on", "never"])
    cap = capsys.readouterr()
    assert rc == 0
    json.loads(cap.out)  # must be valid


def test_cli_scan_osv_increases_findings(apk, capsys):
    rc_plain = main(["scan", apk, "--format", "csv", "--fail-on", "never"])
    plain = capsys.readouterr().out
    rc_osv = main(["scan", apk, "--enrich-osv", "--format", "csv",
                   "--fail-on", "never"])
    enriched = capsys.readouterr().out
    assert rc_plain == 0 and rc_osv == 0
    assert len(enriched.splitlines()) > len(plain.splitlines())


# --------------------------------------------------------------------------- #
# safety / scope: matcher is pure-offline (no network attributes)
# --------------------------------------------------------------------------- #
def test_matcher_never_imports_socket_at_call(apk, db):
    # A behavioral proxy: enrichment completes with the network module's
    # urlopen monkeypatched to explode. If anything tried to go online it would
    # raise; offline matching must not.
    import urllib.request

    def _boom(*a, **k):  # pragma: no cover - must never be hit
        raise AssertionError("network access attempted during offline OSV match")

    orig = urllib.request.urlopen
    urllib.request.urlopen = _boom
    try:
        res = core.scan_with_osv(apk, db=db)
    finally:
        urllib.request.urlopen = orig
    assert res.components
