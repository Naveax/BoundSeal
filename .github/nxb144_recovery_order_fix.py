from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "crates/nxb-resumable-runner/src/lib.rs"
text = path.read_text(encoding="utf-8")

old = "        self.seed.validate(plan)?;\n        self.seed.validate_plan_scope(self)?;"
new = "        self.seed.validate_plan_scope(self)?;\n        self.seed.validate(plan)?;"
if text.count(old) != 1:
    raise SystemExit("seed validation ordering anchor missing")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
