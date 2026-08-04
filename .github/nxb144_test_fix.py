from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "crates/nxb-resumable-runner/src/lib.rs"
text = path.read_text(encoding="utf-8")

old_import = "use nxb_operator_state::OperatorRunStatus;"
new_import = "use nxb_operator_state::{OperatorRunStatus, RecoveredOperatorState};"
if text.count(old_import) != 1:
    raise SystemExit("unexpected NXB-144 operator-state import anchor")
text = text.replace(old_import, new_import, 1)

old_budget = "            maximum_workspace_bytes: 4 * 1024 * 1024,"
new_budget = "            maximum_workspace_bytes: 32 * 1024 * 1024,"
if text.count(old_budget) != 1:
    raise SystemExit("unexpected NXB-144 test workspace fixture anchor")
text = text.replace(old_budget, new_budget, 1)

old_terminal = '''        let runtime_state = runtime
            .complete_teardown(&sha('9'), clock(1_104))
            .expect("complete teardown");
'''
new_terminal = '''        let _runtime_state = runtime
            .complete_teardown(&sha('9'), clock(1_104))
            .expect("complete teardown");
'''
if text.count(old_terminal) != 1:
    raise SystemExit("unexpected NXB-144 terminal test anchor")
text = text.replace(old_terminal, new_terminal, 1)

path.write_text(text, encoding="utf-8", newline="\n")
