# Demo 11 — CISA-KEV enrichment (edge / air-gap)

`vuln-app.apk` bundles two native libraries pinned to versions that are not
merely CVE-affected but appear on **CISA's Known Exploited Vulnerabilities
(KEV)** catalog — CVEs confirmed exploited in the wild:

| Component       | CVE            | Why it matters                                  |
|-----------------|----------------|-------------------------------------------------|
| `libwebp@1.2.0` | CVE-2023-4863  | WebP VP8L heap overflow, mass-exploited zero-day |
| `libssl@1.0.1f` | CVE-2014-0160  | Heartbleed TLS memory disclosure                |

## Run it (fully offline)

```bash
# fixtures ship a trimmed real KEV cache; point the feed cache at it
export COGNIS_FEEDS_CACHE="$PWD/tests/fixtures/feeds-cache"

sbomx scan demos/11-kev-enrichment/vuln-app.apk --enrich-kev --offline
```

Expected: both CVEs are marked `*** CISA KNOWN-EXPLOITED ***`, **escalated to
CRITICAL**, and annotated with the authoritative KEV `dateAdded` / `dueDate`
(federal patch deadline) — so an analyst patches the actively-exploited libs
first instead of triaging by base CVSS alone.

## Online refresh

```bash
sbomx feeds update cisa-kev      # fetch latest KEV (keyless HTTPS) -> cache
sbomx scan vuln-app.apk --enrich-kev   # no --offline = use/refresh cache
```

## Air-gap transfer

```bash
# connected host:
sbomx feeds update cisa-kev
python -m sbomx.datafeeds snapshot-export kev.tar.gz
# sneakernet kev.tar.gz across the gap, then on the enclave host:
python -m sbomx.datafeeds snapshot-import kev.tar.gz
sbomx scan vuln-app.apk --enrich-kev --offline
```
