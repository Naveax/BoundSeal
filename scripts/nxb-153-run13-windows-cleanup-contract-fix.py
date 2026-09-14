#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/tests/windows_validator_cleanup_source_contract.rs")
text = path.read_text(encoding="utf-8")

replacements = [
    (
        '        "immutable source stream cleanup failed",\n',
        '        "Label = \'immutable source stream\'",\n',
    ),
    (
        '        "Cargo.lock stream cleanup failed",\n',
        '        "Label = \'Cargo.lock stream\'",\n',
    ),
    (
        '        "tooling receipt stream cleanup failed",\n',
        '        "Label = \'tooling receipt stream\'",\n',
    ),
    (
        '        "cargo-deny stream cleanup failed",\n',
        '        "Label = \'cargo-deny stream\'",\n',
    ),
    (
        '        "cargo-audit stream cleanup failed",\n',
        '        "Label = \'cargo-audit stream\'",\n',
    ),
    (
        '        "validation lock cleanup failed",\n',
        '        "Label = \'validation lock\'",\n        '        "$($entry.Label) cleanup failed:",\n',
    ),
]

for replacement in replacements:
    old = replacement[0]
    new = "".join(replacement[1:])
    if old not in text:
        raise SystemExit(f"missing cleanup source-contract marker: {old.strip()}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8", newline="\n")
