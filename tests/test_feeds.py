"""Offline tests for the edge/air-gap data-feed ingestion + KEV enrichment.

These NEVER touch the network: COGNIS_FEEDS_CACHE is pointed at a committed,
trimmed real-data cache under tests/fixtures/feeds-cache, and every feed read
goes through the offline (cache-only) path.
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FIXTURE_CACHE = os.path.join(ROOT, "tests", "fixtures", "feeds-cache")


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    """Force all feed reads to the committed fixture cache (no network)."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", FIXTURE_CACHE)
    yield


def test_catalog_filtered_to_relevant_feeds():
    from sbomx import feeds
    ids = {f["id"] for f in feeds.list_feeds()}
    assert ids == set(feeds.RELEVANT_FEEDS) == {"osv", "cisa-kev"}
    # urls are the real authoritative sources, not invented endpoints
    by_id = {f["id"]: f for f in feeds.list_feeds()}
    assert by_id["cisa-kev"]["url"].startswith("https://www.cisa.gov/")
    assert by_id["osv"]["url"] == "https://api.osv.dev/v1/query"


def test_unrelated_feed_is_rejected():
    from sbomx import feeds
    with pytest.raises(KeyError):
        feeds.get("ofac-sdn", offline=True)


def test_kev_index_loads_offline():
    from sbomx import feeds
    idx = feeds.load_kev_index(offline=True)
    assert "CVE-2023-4863" in idx and "CVE-2014-0160" in idx
    rec = idx["CVE-2023-4863"]
    assert rec["dateAdded"] and rec["dueDate"]


def test_osv_feed_serves_offline():
    from sbomx import feeds
    data = feeds.get("osv", offline=True)
    assert isinstance(data, dict) and data.get("vulns")


def test_offline_with_no_cache_raises(monkeypatch, tmp_path):
    from sbomx import feeds
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        feeds.load_kev_index(offline=True)


def test_enrich_with_kev_flags_and_escalates():
    from sbomx import core, feeds
    demo = os.path.join(ROOT, "demos", "11-kev-enrichment", "vuln-app.apk")
    result = core.scan(demo)
    n = feeds.enrich_with_kev(result, offline=True)
    assert n == 2
    by_cve = {f.id: f for f in result.vulnerabilities}
    kev = by_cve["CVE-2023-4863"]
    assert kev.extra["kev"] is True
    assert kev.severity == "critical"          # actively-exploited => critical
    assert kev.extra["kev_date_added"] == "2023-09-13"
    # a non-KEV CVE on the same scan stays unflagged
    non_kev = by_cve["CVE-2016-2107"]
    assert non_kev.extra.get("kev") is False


def test_cli_scan_enrich_kev_offline(capsys):
    from sbomx import cli
    demo = os.path.join(ROOT, "demos", "11-kev-enrichment", "vuln-app.apk")
    rc = cli.main(["scan", demo, "--enrich-kev", "--offline", "--fail-on", "never"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CISA KNOWN-EXPLOITED" in out
    assert "CVE-2023-4863" in out


def test_cli_feeds_list(capsys):
    from sbomx import cli
    rc = cli.main(["feeds", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cisa-kev" in out and "osv" in out


def test_cli_feeds_get_offline(capsys):
    from sbomx import cli
    rc = cli.main(["feeds", "get", "cisa-kev", "--offline"])
    assert rc == 0
    assert "CVE-2023-4863" in capsys.readouterr().out


def test_snapshot_roundtrip(tmp_path, monkeypatch):
    """Air-gap sneakernet: export the fixture cache, import into a fresh dir."""
    from sbomx import datafeeds
    snap = tmp_path / "feeds.tar.gz"
    # export uses whatever COGNIS_FEEDS_CACHE points at (the fixture cache)
    n = datafeeds.snapshot_export(str(snap))
    assert n >= 1 and snap.exists()
    # import into a brand-new empty cache dir, then serve offline from it
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "enclave"))
    from sbomx import feeds
    imported = datafeeds.snapshot_import(str(snap))
    assert imported >= 1
    idx = feeds.load_kev_index(offline=True)
    assert "CVE-2014-0160" in idx
