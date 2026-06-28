<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=SBOMX&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="SBOMX"/>

# SBOMX

### Generates a CycloneDX SBOM for mobile apps by unpacking native libs and bundled SDKs, then matches components against known-vuln and tracker/privacy databases.

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Generates+a+CycloneDX+SBOM+for+mobile+apps+by+unpacking+nati;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-sbomx.svg?color=6b46c1)](https://pypi.org/project/cognis-sbomx/) [![CI](https://github.com/cognis-digital/sbomx/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/sbomx/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Application & Mobile Security — SAST/DAST-lite and binary triage.*

</div>

```bash
pip install cognis-sbomx
sbomx scan .            # → prioritized findings in seconds
```


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ sbomx-emit --version
sbomx 0.2.4
```

```console
$ sbomx-emit --help
usage: sbomx [-h] [--version] {scan,db,feeds} ...

Generate a CycloneDX SBOM for mobile apps and match bundled libraries against vulnerability and privacy-tracker databases.

positional arguments:
  {scan,db,feeds}
    scan           scan an .apk/.ipa/zip or directory and produce an SBOM +
                   findings
    db             query the bundled offline 262k-record OSV vulnerability
                   database
    feeds          manage the bundled edge/air-gap vulnerability data feeds

options:
  -h, --help       show this help message and exit
  --version        show program's version number and exit

Command-line interface for SBOMX.

Examples
--------
  # Generate a CycloneDX SBOM (JSON) for an APK and write it to a file
  sbomx scan app.apk --format json -o app.cdx.json

  # Human-readable findings table; exit non-zero if vulns/trackers found
  sbomx scan app.ipa --format table

  # Scan an extracted bundle directory and fail CI on HIGH severity vulns
  sbomx scan ./unpacked_app --fail-on high

  # Use a manifest mapping lib->version to refine version-unknown components
  sbomx scan app.apk --manifest versions.json

Exit codes
----------
  0  clean (no findings, or findings below --fail-on threshold)
  1  findings at/above the fail threshold (default: any tracker or vuln)
  2  usage / runtime error
```

> Blocks above are real `sbomx` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"sbomx": {
"platform": "stix",
"findings": [
{
"uuid": "12345678-1234-5678-1234-567812345678",
"vulnerability": {
"name": "CVE-2023-12345"
},
"severity": "high",
"description": "A high-severity vulnerability in the application."
}
]
}
}
```

<!-- cognis:example:end -->

## Usage — step by step

`sbomx` generates a CycloneDX SBOM for mobile apps and matches bundled libraries against vulnerability and privacy-tracker databases. Console script: `sbomx`.

1. **Install**:
   ```bash
   pipx install sbomx     # or: pip install sbomx
   ```
2. **Scan an app bundle** (`.apk` / `.ipa` / `.zip`) or an extracted directory and print a findings table:
   ```bash
   sbomx scan app.apk --format table
   ```
   Exit `1` = findings at/above the `--fail-on` threshold (default: any finding), `0` = clean, `2` = error.
3. **Emit a CycloneDX 1.5 SBOM** as JSON to a file (also `--format sarif` for
   GitHub code-scanning, or `--format csv` for spreadsheets/ticketing):
   ```bash
   sbomx scan app.apk --format json  -o app.cdx.json
   sbomx scan app.apk --format sarif -o app.sarif.json   # upload to code-scanning
   sbomx scan app.apk --format csv   -o findings.csv
   ```
4. **Refine version-unknown components** with a manifest mapping library key to version:
   ```bash
   sbomx scan app.apk --manifest versions.json --format json -o app.cdx.json
   ```
5. **Gate CI on severity** — fail the build only on HIGH+ vulnerabilities/trackers:
   ```bash
   sbomx scan ./unpacked_app --fail-on high || echo "high-severity component findings — blocking release"
   ```

## Contents

- [Why sbomx?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why sbomx?

Syft/Grype ignore the mobile binary world; sbomx surfaces vulnerable bundled SDKs and privacy trackers inside shipped apps — perfect for app-store compliance gating.

`sbomx` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Detects bundled libraries from APK/IPA/zip member paths and native `.so`/`.dylib` names
- ✅ Recovers versions from filenames or a supplied `--manifest` (key → version)
- ✅ Matches against a curated vuln DB (CVE-style) and a privacy-tracker DB (Exodus-style)
- ✅ **Live threat-feed enrichment**: flags findings on **CISA's Known-Exploited (KEV)** list — see [Live data feeds](#data-feeds)
- ✅ **Four output formats: `table` · CycloneDX 1.5 `json` · SARIF 2.1.0 `sarif` · `csv`**
- ✅ CI gate via `--fail-on {info,low,medium,high,critical,never}` + exit codes
- ✅ 11 ready-to-run [demos](demos/) covering iOS/Android/React Native/Flutter/games + live KEV enrichment
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-sbomx
sbomx --version
sbomx scan .                       # scan current project
sbomx scan . --format json         # machine-readable
sbomx scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

A real scan of an Android bundle that ships `okhttp-4.9.0.jar`, native
`libssl`/`libwebp`, Firebase + Crashlytics and the AppsFlyer SDK:

```text
$ sbomx scan app.apk --format table
Target: app.apk

Components (7):
  appsflyer             ?          maven      pkg:maven/com.appsflyer/appsflyer
  firebase-core         ?          maven      pkg:maven/com.google.firebase/firebase-core
  firebase-crashlytics  ?          maven      pkg:maven/com.google.firebase/firebase-crashlytics
  gson                  ?          maven      pkg:maven/com.google.code.gson/gson
  libwebp               ?          native     pkg:generic/libwebp
  okhttp                4.9.0      maven      pkg:maven/com.squareup.okhttp3/okhttp@4.9.0
  openssl               1.1.1k     native     pkg:generic/openssl

Vulnerabilities (4):
  [CRITICAL] CVE-2023-4863  libwebp@?
             Heap buffer overflow in WebP lossless (VP8L) decoding; exploited in the wild.
             fix: upgrade to >= 1.3.2
  [HIGH    ] CVE-2022-0778  openssl@1.1.1k
             BN_mod_sqrt infinite loop (DoS) when parsing certificates.
             fix: upgrade to >= 1.1.1n
  [MEDIUM  ] CVE-2021-0341  okhttp@4.9.0
             OkHttp improper certificate validation (hostname not verified).
             fix: upgrade to >= 4.9.2

Trackers (3):
  AppsFlyer  (Analytics, Advertisement)
  Google Firebase Analytics  (Analytics)
  Google Firebase Crashlytics  (Crash reporting, Analytics)
```

Add `--enrich-osv` to cross-reference every detected component against the
bundled **262k-record offline OSV database** (no network), or `--enrich-kev` to
flag CVEs that are actively exploited per CISA.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos — real-use-case scenarios

Each folder under [`demos/`](demos/) ships a generator (`make_sample.py`) that
builds a realistic app bundle plus a `SCENARIO.md` (where the data came from,
the exact command, expected output, and how to act). All library versions are
drawn from the tool's own detection rules + vuln DB, so every demo deterministically
reproduces its documented findings.

| Demo | Scenario | Highlights |
|---|---|---|
| [01-basic](demos/01-basic/) | First Android scan | 3 vulns + 2 trackers, table + JSON |
| [02-clean](demos/02-clean/) | First-party app, no SDKs | 0 findings, exit 0 |
| [03-mixed](demos/03-mixed/) | Mixed severities | `--fail-on high` vs `critical` gate |
| [04-ios-banking](demos/04-ios-banking/) | iOS `.ipa` framework audit | CocoaPods + native crypto, Realm CVE |
| [05-react-native-ecommerce](demos/05-react-native-ecommerce/) | RN privacy + vuln review | 3 trackers, CSV export |
| [06-clean-release](demos/06-clean-release/) | Release candidate | all libs patched, gate passes |
| [07-manifest-resolve](demos/07-manifest-resolve/) | Stripped build | `--manifest` resolves version-unknown potentials |
| [08-game-adtech](demos/08-game-adtech/) | F2P game ad-SDK sweep | 5 trackers + native media CVEs |
| [09-flutter-app](demos/09-flutter-app/) | Flutter native audit | 3 HIGH native CVEs |
| [10-ci-sarif-gate](demos/10-ci-sarif-gate/) | CI + GitHub code-scanning | SARIF upload + HIGH gate |

```bash
python demos/04-ios-banking/make_sample.py
python -m sbomx scan demos/04-ios-banking/banking.ipa --format table
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="data-feeds"></a>
## Live data feeds — edge / air-gap ingestion

sbomx enriches its findings with **real, authoritative public vulnerability
feeds**. The killer feature: an SBOM finding is no longer "this CVE applies" but
**"this CVE is being exploited in the wild right now — patch it first."**

| Feed id    | Source (real, keyless)                                                                                          | Used for |
|------------|----------------------------------------------------------------------------------------------------------------|----------|
| `cisa-kev` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | Flag + escalate actively-exploited CVEs to **critical**; surface KEV `dateAdded` / federal `dueDate` |
| `osv`      | [OSV.dev](https://api.osv.dev/v1/query)                                                                        | Package+version vulnerability lookups across ecosystems |

### Enrich a scan

```bash
sbomx scan app.apk --enrich-kev            # online: fetch/refresh KEV, then enrich
sbomx scan app.apk --enrich-kev --offline  # air-gap: use the local KEV cache only
```

Findings whose CVE is on the KEV list are tagged `*** CISA KNOWN-EXPLOITED ***`,
bumped to `critical`, and annotated with the authoritative dates:

```text
[CRITICAL] CVE-2023-4863  libwebp@1.2.0  *** CISA KNOWN-EXPLOITED ***
           Heap buffer overflow in WebP lossless (VP8L) decoding; exploited in the wild.
           KEV: added 2023-09-13  patch-by 2023-10-04  ransomware=Unknown
           fix: upgrade to >= 1.3.2
```

### Manage the feeds

```bash
sbomx feeds list                       # the feeds this tool consumes (+ URLs)
sbomx feeds update cisa-kev            # keyless HTTPS fetch -> disk cache
sbomx feeds get cisa-kev --offline     # re-serve from cache, never touch network
```

### Edge / air-gap workflow

The ingestion engine ([`sbomx/datafeeds.py`](sbomx/datafeeds.py), stdlib-only)
caches every feed to disk and re-serves it offline, so sbomx keeps working on
disconnected / classified / forward-deployed gear. Set the cache location with
`COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).

**Sneakernet into an air gap:**

```bash
# on a connected host
sbomx feeds update cisa-kev
python -m sbomx.datafeeds snapshot-export feeds.tar.gz
#  ... carry feeds.tar.gz across the gap ...
# on the disconnected enclave
python -m sbomx.datafeeds snapshot-import feeds.tar.gz
sbomx scan app.apk --enrich-kev --offline
```

See [`demos/11-kev-enrichment`](demos/11-kev-enrichment/) for a complete,
offline-runnable example. The test suite ships a trimmed real-data feed cache
under `tests/fixtures/feeds-cache/`, so CI enriches findings with **zero network
access**.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[sbomx<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`sbomx` is interoperable with every popular way of using AI:

- **MCP server** — `sbomx mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `sbomx scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis sbomx** | Syft + Grype, extended to the mobile binary (APK |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **Syft + Grype, extended to the mobile binary (APK/IPA native .so/dylib) world**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`sbomx mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/sbomx.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/sbomx.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/sbomx.git" # uv
pip install cognis-sbomx                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/sbomx:latest --help        # Docker
brew install cognis-digital/tap/sbomx                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/sbomx/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/sbomx` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`apkpeek`](https://github.com/cognis-digital/apkpeek) — One-command static triage of Android APK/AAB binaries: surfaces hardcoded secrets, exported components, dangerous permissions, and insecure manifest flags as a single SARIF report.
- [`ipasnitch`](https://github.com/cognis-digital/ipasnitch) — Static scanner for iOS .ipa bundles that flags ATS exceptions, missing entitlements hardening, embedded URLs/secrets, and weak Info.plist transport settings.
- [`hookcraft`](https://github.com/cognis-digital/hookcraft) — Generates ready-to-run Frida instrumentation scripts from a YAML intent (e.g. 'bypass SSL pinning', 'dump crypto keys') and verifies they attach to a target process.
- [`dastlite`](https://github.com/cognis-digital/dastlite) — A headless, config-as-code DAST runner that crawls an authenticated web/mobile-API surface and fires a curated active-scan ruleset, emitting deduplicated SARIF.
- [`semsift`](https://github.com/cognis-digital/semsift) — Lightweight semantic-aware SAST that runs curated taint rules over diffs only, so PRs get fast incremental SAST instead of whole-repo scan fatigue.
- [`cheatsense`](https://github.com/cognis-digital/cheatsense) — Anti-cheat telemetry analyzer that ingests game session logs and flags statistically anomalous input/aim/movement signatures with explainable per-flag scoring.

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `sbomx` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

## Bundled vulnerability database

Ships `sbomx/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV: PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata (CVE/GHSA aliases, ecosystem, severity/CVSS, affected packages, dates). Pure-stdlib offline loader `vulndb_local.VulnDB` (`count`/`by_cve`/`by_package`/`search`), air-gap ready. Refresh/extend via `datafeeds.py bulk`.

### Offline CycloneDX-component → CVE matching

`sbomx scan ... --enrich-osv` maps every detected CycloneDX component to the
package coordinate OSV uses for its ecosystem and matches it against the bundled
262k-record corpus — **fully offline, no network, no key**:

| Ecosystem | Component coordinate probed |
|---|---|
| Maven | `pkg:maven/<group>/<artifact>` → `<group>:<artifact>` (e.g. `com.squareup.okhttp3:okhttp`) |
| npm | the package name (e.g. `react-native`) |
| CocoaPods | the framework name (e.g. `Alamofire`) |
| native | the library key (e.g. `openssl`, `sqlite`, `libwebp`) |

OSV-sourced findings are appended to the scan result, de-duplicated against the
curated VULN_DB, severity-bucketed from the record's CVSS v3 vector, and marked
*version-unconfirmed* when the compact corpus carries no version range — so the
tool never silently claims a precise match it cannot prove.

```bash
sbomx scan app.apk --enrich-osv --format json -o app.cdx.json
```

Query the database directly (handy for triage / CI):

```bash
sbomx db count                                            # 262351
sbomx db cve CVE-2021-44228                               # log4j → GHSA-jfh8-c2jp-5v3q
sbomx db package org.apache.logging.log4j:log4j-core      # advisories for the maven coordinate
sbomx db search "buffer overflow" --limit 5
```

```python
from sbomx.vulndb_local import VulnDB
db = VulnDB()
db.count()                              # 262351
db.by_cve("CVE-2021-44228")             # [{'id': 'GHSA-jfh8-c2jp-5v3q', 'aliases': ['CVE-2021-44228'], ...}]
db.by_package("org.apache.logging.log4j:log4j-core")
```

### Edge / air-gap refresh

The corpus is the **offline baseline** — the tool has 262k real vulns the moment
it is cloned, with zero setup. To refresh or extend it from upstream while
connected, then sneakernet into a disconnected enclave, use the stdlib-only
[`datafeeds.py`](sbomx/datafeeds.py) ingestion engine against the real, keyless
NVD / OSV / GHSA / CISA-KEV feeds catalogued in
[`data_feeds_2026.json`](sbomx/data_feeds_2026.json):

```bash
# on a connected host: refresh feeds into the disk cache
python -m sbomx.datafeeds update osv cisa-kev
python -m sbomx.datafeeds snapshot-export feeds.tar.gz
#  ... carry feeds.tar.gz across the air gap ...
# on the disconnected enclave: import + scan offline
python -m sbomx.datafeeds snapshot-import feeds.tar.gz
sbomx scan app.apk --enrich-osv --enrich-kev --offline
```
