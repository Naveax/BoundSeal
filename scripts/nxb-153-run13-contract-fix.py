#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/tests/workspace_replacement_authority_source_contract.rs")
text = path.read_text(encoding="utf-8")
old = '''    for marker in [
        "const TRUSTED_LN: &str = \\\"/usr/bin/ln\\\";",
        ".arg(\\\"-L\\\")",
        ".arg(\\\"--\\\")",
        ".env_clear()",
        "prepared.file.as_raw_fd()",
        "parent.claim_prepared(&prepared, destination)?;",
        "parent.validate_child_binding(destination, &prepared, \\\"replacement destination\\\")?;",
    ] {
        assert!(production.contains(marker), "{REPLACEMENT_PATH}: missing create-only marker: {marker}");
    }
'''
new = '''    assert!(
        replacement.contains("const TRUSTED_LN: &str = \\\"/usr/bin/ln\\\";"),
        "{REPLACEMENT_PATH}: missing trusted hard-link application marker"
    );
    for marker in [
        ".arg(\\\"-L\\\")",
        ".arg(\\\"--\\\")",
        ".env_clear()",
        "prepared.file.as_raw_fd()",
        "parent.claim_prepared(&prepared, destination)?;",
        "parent.validate_child_binding(destination, &prepared, \\\"replacement destination\\\")?;",
    ] {
        assert!(production.contains(marker), "{REPLACEMENT_PATH}: missing create-only marker: {marker}");
    }
'''
if old not in text:
    raise SystemExit("missing replacement contract placement anchor")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
