# Ports of sbomx

The same component-detection logic, ported across languages so you can drop
sbomx's mobile-SBOM scan into any stack or ship a single static binary. Every
port detects bundled third-party libraries from app member paths using the same
real-world rules as the Python reference (`../sbomx/core.py`) and emits a JSON
SBOM summary with the same component shape (`name` / `version` / `ecosystem` /
`purl` / `evidence`).

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../sbomx/` | `sbomx scan .` | `pytest` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js <dir>` | `node ports/javascript/test.js` |
| Go | `go/` | `cd ports/go && go run . <dir>` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- <dir>` | `cd ports/rust && cargo test` |

Each port walks an extracted app directory (or accepts explicit member paths)
and recovers versions from filenames (e.g. `okhttp-4.9.0.jar`). Example:

```bash
$ node ports/javascript/index.js demos/01-basic
{ "tool": "sbomx", "port": "javascript", "components": [ ... ], "count": 7 }
```

## Verified in CI

The [`ports.yml`](../.github/workflows/ports.yml) workflow builds **and tests**
the Go, Node, and Rust ports on every push that touches `ports/` — real
toolchains (`go test` / `cargo test` / `node test.js`) plus a smoke run against
a demo bundle. The ports are verifiable, not vaporware.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
