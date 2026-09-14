#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/validate-nxb-153-windows-inner.ps1")
text = path.read_text(encoding="utf-8")
replacements = [
    (
        "        [Parameter(Mandatory = $true)][Collections.Generic.List[string]]$Log\n",
        "        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.List[string]]$Log\n",
        "cleanup probe Log parameter",
    ),
    (
        "        [Parameter(Mandatory = $true)][Collections.Generic.List[string]]$CleanupErrors,\n",
        "        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.List[string]]$CleanupErrors,\n",
        "validation outcome CleanupErrors parameter",
    ),
]
for old, new, label in replacements:
    if old not in text:
        raise SystemExit(f"missing {label} anchor")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
