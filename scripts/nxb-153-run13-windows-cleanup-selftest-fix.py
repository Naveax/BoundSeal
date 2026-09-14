#!/usr/bin/env python3
from pathlib import Path

path = Path("scripts/validate-nxb-153-windows-inner.ps1")
text = path.read_text(encoding="utf-8")
old = "        [Parameter(Mandatory = $true)][Collections.Generic.List[string]]$Log\n"
new = "        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.List[string]]$Log\n"
if old not in text:
    raise SystemExit("missing cleanup probe Log parameter anchor")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
