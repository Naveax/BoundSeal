#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/src/target/activation.rs")
text = path.read_text(encoding="utf-8")

old_thread_local = '''#[cfg(test)]
std::thread_local! {
    static DISABLE_GATE_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut(DisableGateTestPhase)>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_disable_gate_test_hook(hook: Option<Box<dyn FnMut(DisableGateTestPhase)>>) {
'''
new_thread_local = '''#[cfg(test)]
type DisableGateTestHook = Box<dyn FnMut(DisableGateTestPhase)>;

#[cfg(test)]
std::thread_local! {
    static DISABLE_GATE_TEST_HOOK: std::cell::RefCell<Option<DisableGateTestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_disable_gate_test_hook(hook: Option<DisableGateTestHook>) {
'''

if old_thread_local not in text:
    raise SystemExit("missing activation disable-gate hook type-complexity anchor")
text = text.replace(old_thread_local, new_thread_local, 1)
path.write_text(text, encoding="utf-8", newline="\n")
