from pathlib import Path
import re

path = Path(__file__).resolve().parents[1] / "crates/nxb-operator-runtime/src/lib.rs"
text = path.read_text(encoding="utf-8")

text = text.replace("    lock: RuntimeLock,\n", "    _lock: RuntimeLock,\n", 1)
constructor_count = text.count("            lock,\n")
if constructor_count != 2:
    raise SystemExit(f"unexpected runtime lock constructor count: {constructor_count}")
text = text.replace("            lock,\n", "            _lock: lock,\n")

initialized_pattern = re.compile(
    r"        let initialized = (OperatorStateStore::initialize\([\s\S]*?\));\n"
    r"        let \(state_store, state\) = match initialized \{\n"
    r"            Ok\(value\) => value,\n"
    r"            Err\(error\) => return Err\(error\.into\(\)\),\n"
    r"        \};"
)
text, count = initialized_pattern.subn(
    r"        let (state_store, state) = \1?;", text, count=1
)
if count != 1:
    raise SystemExit("initialize question-mark anchor not found")

opened_pattern = re.compile(
    r"        let opened = (OperatorStateStore::open\([\s\S]*?\));\n"
    r"        let \(state_store, state\) = match opened \{\n"
    r"            Ok\(value\) => value,\n"
    r"            Err\(error\) => return Err\(error\.into\(\)\),\n"
    r"        \};"
)
text, count = opened_pattern.subn(
    r"        let (state_store, state) = \1?;", text, count=1
)
if count != 1:
    raise SystemExit("open question-mark anchor not found")

scan_pattern = re.compile(
    r"        let scan = match (scan_journal\([\s\S]*?\)) \{\n"
    r"            Ok\(scan\) => scan,\n"
    r"            Err\(error\) => return Err\(error\),\n"
    r"        \};"
)
text, count = scan_pattern.subn(r"        let scan = \1?;", text, count=1)
if count != 1:
    raise SystemExit("journal scan question-mark anchor not found")

path.write_text(text, encoding="utf-8", newline="\n")
