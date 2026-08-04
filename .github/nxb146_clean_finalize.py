from __future__ import annotations

import sys
from pathlib import Path


def replace_exact(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"NXB-146 {label} mismatch: {count}")
    return text.replace(old, new, 1)


def pre() -> None:
    cargo = Path("Cargo.toml")
    text = cargo.read_text(encoding="utf-8")
    member = '    "crates/nxb-run-closure",\n'
    if member not in text:
        anchor = '    "crates/nxb-resumable-runner",\n'
        text = replace_exact(text, anchor, anchor + member, "workspace anchor")
        cargo.write_text(text, encoding="utf-8")

    path = Path("/tmp/nxb146_host_binding.py")
    text = path.read_text(encoding="utf-8")
    old = '''tests = replace_once(
    tests,
    \'''        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
\''',
    \'''        &runner_checkpoint,
        &runtime,
        &bundle,
        &teardown,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime, sha('d')),
\''',
    "complete build call",
)
'''
    new = '''old_complete_build_call = \'''        &runner_checkpoint,
        &runtime,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime),
\'''
new_complete_build_call = \'''        &runner_checkpoint,
        &runtime,
        &bundle,
        &teardown,
        &export,
        complete_input(&export, &runner_checkpoint, &runtime, sha('d')),
\'''
if old_complete_build_call not in tests:
    raise SystemExit("NXB-146 complete build call anchor missing")
tests = tests.replace(old_complete_build_call, new_complete_build_call, 1)
'''
    path.write_text(
        replace_exact(text, old, new, "materializer normalization"),
        encoding="utf-8",
    )


def post() -> None:
    lib = Path("crates/nxb-run-closure/src/lib.rs")
    text = lib.read_text(encoding="utf-8")
    text = replace_exact(
        text,
        "failure_sha256: hash_bytes(failure.as_bytes()),",
        "failure_sha256: lower_hex(&Sha256::digest(failure.as_bytes())),",
        "failure hash",
    )
    for signature in ["    pub fn build(\n", "    pub fn verify_components(\n"]:
        text = replace_exact(
            text,
            signature,
            "    #[allow(clippy::too_many_arguments)]\n" + signature,
            f"bounded API {signature.strip()}",
        )
    lib.write_text(text, encoding="utf-8")

    tests_path = Path("crates/nxb-run-closure/tests/closure.rs")
    tests = tests_path.read_text(encoding="utf-8")
    old = '''        &runtime,
        &export,
        input,
'''
    new = '''        &runtime,
        &launch_bundle(&plan, &runner_manifest),
        &completed_teardown(&runner_checkpoint, &runtime),
        &export,
        input,
'''
    tests_path.write_text(
        replace_exact(tests, old, new, "metadata adversarial call"),
        encoding="utf-8",
    )


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"pre", "post"}:
        raise SystemExit("usage: nxb146_clean_finalize.py pre|post")
    if sys.argv[1] == "pre":
        pre()
    else:
        post()


if __name__ == "__main__":
    main()
