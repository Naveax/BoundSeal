#!/usr/bin/env python3
from pathlib import Path

path = Path(".github/workflows/nxb-153-admission.yml")
text = path.read_text(encoding="utf-8")

anchor = '''          if ($LASTEXITCODE -ne 0 -or $status) { throw 'checkout is not clean' }

      - name: Reject ambient Git authority before exact-head resolution
'''
insert = '''          if ($LASTEXITCODE -ne 0 -or $status) { throw 'checkout is not clean' }

      - name: Prove Windows validator cleanup fault arbitration
        shell: pwsh
        run: |
          $ErrorActionPreference = 'Stop'
          & .\\scripts\\validate-nxb-153-windows-inner.ps1 -RepoRoot . -SelfTest cleanup-faults

      - name: Reject ambient Git authority before exact-head resolution
'''
if "Prove Windows validator cleanup fault arbitration" not in text:
    if anchor not in text:
        raise SystemExit("missing Windows admission self-test insertion anchor")
    text = text.replace(anchor, insert, 1)

path.write_text(text, encoding="utf-8", newline="\n")
