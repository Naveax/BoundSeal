from pathlib import Path

path = Path(__file__).resolve().parents[1] / "crates/nxb-operator-runtime/src/lib.rs"
text = path.read_text(encoding="utf-8")
old = '''        let (root, plan, consumed) = setup("success");
        let clock = RuntimeClock {
'''
new = '''        let (root, runtime_plan, consumed) = setup("success");
        let clock = RuntimeClock {
'''
if old not in text:
    raise SystemExit("success fixture binding anchor not found")
text = text.replace(old, new, 1)
old = '''            root.join("journal"),
            plan,
            &consumed,
            clock,
'''
new = '''            root.join("journal"),
            runtime_plan,
            &consumed,
            clock,
'''
if old not in text:
    raise SystemExit("success fixture initialize anchor not found")
text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8", newline="\n")
