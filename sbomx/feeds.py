"""feeds — edge/air-gap data-feed ingestion + finding enrichment for SBOMX.

SBOMX matches bundled mobile libraries against a curated offline VULN_DB. This
module pulls in *authoritative, real* public vulnerability feeds and uses them
to enrich those findings so an analyst sees not just "this CVE applies" but
"this CVE is on CISA's Known-Exploited list — patch it now".

Wired feeds (subset of the bundled catalog ``data_feeds_2026.json``, restricted
to this tool's vuln domain):

  * cisa-kev  CISA Known Exploited Vulnerabilities
              https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  * osv       OSV.dev package vulnerability query
              https://api.osv.dev/v1/query

Everything is delegated to the bundled, stdlib-only :mod:`sbomx.datafeeds`
ingestion engine: keyless HTTPS fetch -> disk cache -> ``get(..., offline=True)``
re-serve, plus tar snapshot export/import for sneakernet into an air-gapped
enclave. Set ``COGNIS_FEEDS_CACHE`` to control the cache location.

Defensive / authorized-use only.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import datafeeds

# Feed ids this tool consumes. Keep the catalog filtered to the vuln domain so
# `sbomx feeds list` never advertises feeds the tool can't actually use.
RELEVANT_FEEDS = ("osv", "cisa-kev")


# --------------------------------------------------------------------------- #
# catalog (filtered to this tool's relevant feeds)
# --------------------------------------------------------------------------- #
def relevant_catalog() -> dict:
    """The bundled catalog narrowed to :data:`RELEVANT_FEEDS`."""
    full = datafeeds.load_catalog()
    feeds = [f for f in full.get("feeds", []) if f.get("id") in RELEVANT_FEEDS]
    return {"feeds": feeds}


def list_feeds() -> List[dict]:
    return relevant_catalog()["feeds"]


def update(feed_id: str) -> str:
    _guard(feed_id)
    return str(datafeeds.update(feed_id, catalog=relevant_catalog()))


def get(feed_id: str, *, offline: bool = False, query: Optional[dict] = None) -> Any:
    _guard(feed_id)
    return datafeeds.get(feed_id, offline=offline, catalog=relevant_catalog(),
                         query=query)


def _guard(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise KeyError(
            f"{feed_id!r} is not a feed sbomx consumes; "
            f"choose one of {', '.join(RELEVANT_FEEDS)}")


# --------------------------------------------------------------------------- #
# CISA-KEV enrichment
# --------------------------------------------------------------------------- #
def load_kev_index(*, offline: bool = False) -> Dict[str, dict]:
    """Return ``{CVE-id: kev-record}`` from the CISA KEV feed.

    With ``offline=True`` this serves the on-disk cache only and never touches
    the network — the air-gap path. Raises ``FileNotFoundError`` if nothing is
    cached yet (run ``sbomx feeds update cisa-kev`` while connected first, or
    import a snapshot).
    """
    data = get("cisa-kev", offline=offline)
    index: Dict[str, dict] = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if cve:
            index[cve.upper()] = v
    return index


def enrich_with_kev(result, *, offline: bool = False) -> int:
    """Annotate every vulnerability finding whose CVE is on CISA's
    Known-Exploited list. Mutates ``finding.extra`` in place and returns the
    number of findings flagged.

    Each flagged finding gains ``extra['kev'] = True`` plus the authoritative
    KEV metadata (``kev_date_added``, ``kev_due_date``, ``kev_ransomware``,
    ``kev_name``). Because KEV = *actively exploited in the wild*, a flagged
    finding is also escalated to ``critical`` severity.
    """
    kev = load_kev_index(offline=offline)
    flagged = 0
    for f in result.vulnerabilities:
        rec = kev.get((f.id or "").upper())
        if not rec:
            f.extra.setdefault("kev", False)
            continue
        f.extra["kev"] = True
        f.extra["kev_name"] = rec.get("vulnerabilityName", "")
        f.extra["kev_date_added"] = rec.get("dateAdded", "")
        f.extra["kev_due_date"] = rec.get("dueDate", "")
        f.extra["kev_ransomware"] = rec.get("knownRansomwareCampaignUse", "Unknown")
        # Actively exploited => highest priority regardless of base severity.
        f.severity = "critical"
        flagged += 1
    return flagged
