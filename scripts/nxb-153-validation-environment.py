#!/usr/bin/env python3
"""Fail-closed ambient validation-environment authority guard for NXB-153."""

from __future__ import annotations

import json
import os
import sys
from typing import Mapping, NoReturn

FORBIDDEN_EXACT = frozenset(
    {
        "CARGO",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
    }
)

# These families map directly to Cargo/rustup configuration or can substitute
# compiler/runner/profile/source behavior. The audit runs before NXB-153 stages
# its own controlled CARGO_HOME/TARGET_DIR/offline values.
FORBIDDEN_PREFIXES = (
    "CARGO_ALIAS_",
    "CARGO_BUILD_",
    "CARGO_NET_",
    "CARGO_PROFILE_",
    "CARGO_REGISTRIES_",
    "CARGO_REGISTRY_",
    "CARGO_SOURCE_",
    "CARGO_TARGET_",
    "RUSTC_",
    "RUSTDOC_",
    "RUSTUP_",
)


class EnvironmentAuthorityError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise EnvironmentAuthorityError(message)


def authority_key(name: str) -> bool:
    canonical = name.upper()
    if canonical in FORBIDDEN_EXACT:
        return True
    return any(canonical.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)


def audit_environment(environment: Mapping[str, str]) -> dict[str, object]:
    collisions = sorted(
        {name for name in environment if authority_key(name)},
        key=lambda value: value.upper(),
    )
    if collisions:
        # Values are intentionally never printed: registry tokens or other
        # sensitive data must not leak merely because a variable name is banned.
        fail(
            "ambient Rust/Cargo/Python authority variables are not admitted: "
            + ", ".join(collisions)
        )
    return {
        "ambient_variables_checked": len(environment),
        "authority_variables_present": 0,
        "policy": "nxb-153-rust-cargo-python-authority-v1",
    }


def self_test() -> None:
    allowed = {
        "HOME": "/tmp/nxb-home",
        "PATH": "/usr/bin:/bin",
        "HTTPS_PROXY": "http://proxy.invalid:8080",
        "PYTHONUTF8": "1",
        "SYSTEMROOT": r"C:\Windows",
    }
    result = audit_environment(allowed)
    if result["authority_variables_present"] != 0:
        fail("self-test allowed environment returned an invalid authority count")

    rejected_names = (
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_DIST_SERVER",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_RUSTC",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_REGISTRIES_CRATES_IO_INDEX",
        "CARGO_SOURCE_CRATES_IO_REPLACE_WITH",
        "CARGO_NET_OFFLINE",
        "PYTHONPATH",
        "PYTHONHOME",
    )
    for name in rejected_names:
        try:
            audit_environment({name: "untrusted"})
        except EnvironmentAuthorityError:
            continue
        fail(f"self-test accepted forbidden ambient authority variable: {name}")

    # Matching is deliberately case-insensitive so the same policy applies on
    # Windows and does not acquire platform-specific spelling loopholes.
    try:
        audit_environment({"rustflags": "-C opt-level=0"})
    except EnvironmentAuthorityError:
        pass
    else:
        fail("self-test accepted case-variant forbidden authority variable")

    print("NXB-153 validation environment authority self-test passed.")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        fail("exactly one mode is required")
    mode = argv[1]
    if mode == "self-test":
        self_test()
    elif mode == "audit":
        result = audit_environment(os.environ)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        fail(f"unknown mode: {mode}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except EnvironmentAuthorityError as error:
        print(f"NXB-153 validation environment authority failed: {error}", file=sys.stderr)
        raise SystemExit(1)
