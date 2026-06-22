"""Shared helper for SBOMX demo fixture generators.

Each demo ships a `make_sample.py` that calls `write_apk(...)` /
`write_dir(...)` to (re)produce a realistic app bundle. An `.apk`/`.ipa` is
just a ZIP whose member paths mimic a real shipped app, so SBOMX can detect
the bundled libraries by their well-known package paths and native lib names.

All library keys and versions used in the demos are drawn from SBOMX's own
detection rules and vulnerability database (see `sbomx/core.py`) so every
demo deterministically reproduces the documented findings.
"""
from __future__ import annotations

import os
import zipfile


def write_apk(out_path: str, entries: dict) -> str:
    """Write a ZIP (apk/ipa/zip) with the given {member_path: bytes} entries."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data if isinstance(data, bytes) else data.encode())
    return out_path


def write_dir(out_dir: str, entries: dict) -> str:
    """Write an extracted bundle directory with the given relative files."""
    for rel, data in entries.items():
        full = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
    return out_dir
