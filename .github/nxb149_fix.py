from pathlib import Path

path = Path("crates/nxb-evidence-key-provider/src/lib.rs")
text = path.read_text(encoding="utf-8")
old = "        let mut bytes = vec![3_u8; EVIDENCE_SEALING_KEY_BYTES];"
new = "        let mut bytes = [3_u8; EVIDENCE_SEALING_KEY_BYTES];"
if text.count(old) != 1:
    raise SystemExit("expected exactly one zeroization fixture buffer")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
