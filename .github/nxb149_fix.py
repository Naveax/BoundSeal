from pathlib import Path

path = Path("crates/nxb-evidence-key-provider/src/lib.rs")
text = path.read_text(encoding="utf-8")
old = "        bytes: Vec<u8>,\n    ) -> Result<Self, EvidenceKeyProviderError> {"
new = "        mut bytes: Vec<u8>,\n    ) -> Result<Self, EvidenceKeyProviderError> {"
if text.count(old) != 1:
    raise SystemExit("expected exactly one ProviderKeyMaterial byte parameter")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
