from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "crates/nxb-resumable-runner/src/lib.rs"
text = path.read_text(encoding="utf-8")
old = "            maximum_workspace_bytes: 4 * 1024 * 1024,"
new = "            maximum_workspace_bytes: 32 * 1024 * 1024,"
if text.count(old) != 1:
    raise SystemExit("unexpected NXB-144 test workspace fixture anchor")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
