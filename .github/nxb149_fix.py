from pathlib import Path

path = Path("crates/nxb-evidence-key-provider/src/lib.rs")
text = path.read_text(encoding="utf-8")

library_import = "use zeroize::{Zeroize, Zeroizing};"
if text.count(library_import) != 1:
    raise SystemExit("expected exactly one library zeroize import")
text = text.replace(library_import, "use zeroize::Zeroizing;", 1)

test_marker = "mod tests {\n    use super::*;\n"
if text.count(test_marker) != 1:
    raise SystemExit("expected exactly one tests module marker")
text = text.replace(
    test_marker,
    test_marker + "    use zeroize::Zeroize;\n",
    1,
)

path.write_text(text, encoding="utf-8", newline="\n")
