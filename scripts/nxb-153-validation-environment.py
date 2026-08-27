#!/usr/bin/env python3
"""Fail-closed ambient validation-environment authority guard for NXB-153."""

from __future__ import annotations

import json
import os
import sys
from typing import Mapping, NoReturn

FORBIDDEN_EXACT = frozenset(
    {
        "AR",
        "BINDGEN_EXTRA_CLANG_ARGS",
        "CARGO",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CC",
        "CC_ENABLE_DEBUG_OUTPUT",
        "CFLAGS",
        "CL",
        "CPP",
        "CPPFLAGS",
        "CRATE_CC_NO_DEFAULTS",
        "CXX",
        "CXXFLAGS",
        "LD",
        "LDFLAGS",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RANLIB",
        "RANLIBFLAGS",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "_CL_",
    }
)

# These families map directly to Cargo/rustup configuration or can substitute
# compiler/runner/profile/source/native-build behavior. The audit runs before
# NXB-153 stages its own controlled CARGO_HOME/TARGET_DIR/offline values.
FORBIDDEN_PREFIXES = (
    "AR_",
    "BINDGEN_EXTRA_CLANG_ARGS_",
    "CARGO_ALIAS_",
    "CARGO_BUILD_",
    "CARGO_NET_",
    "CARGO_PROFILE_",
    "CARGO_REGISTRIES_",
    "CARGO_REGISTRY_",
    "CARGO_SOURCE_",
    "CARGO_TARGET_",
    "CC_",
    "CFLAGS_",
    "CPPFLAGS_",
    "CXX_",
    "CXXFLAGS_",
    "LD_",
    "LDFLAGS_",
    "RANLIB_",
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
            "ambient compiler/Cargo/Python authority variables are not admitted: "
            + ", ".join(collisions)
        )
    return {
        "ambient_variables_checked": len(environment),
        "authority_variables_present": 0,
        "policy": "nxb-153-compiler-cargo-python-authority-v2",
    }


def self_test() -> None:
    allowed = {
        "HOME": "/tmp/nxb-home",
        "PATH": "/usr/bin:/bin",
        "HTTPS_PROXY": "http://proxy.invalid:8080",
        "PYTHONUTF8": "1",
        "SYSTEMROOT": r"C:\Windows",
        # Visual Studio/SDK discovery remains host authority rather than an
        # operator-selectable compiler override in this contract.
        "INCLUDE": r"C:\sdk\include",
        "LIB": r"C:\sdk\lib",
        "LIBPATH": r"C:\sdk\libpath",
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
        "CC",
        "CC_X86_64_UNKNOWN_LINUX_GNU",
        "CFLAGS",
        "CFLAGS_X86_64_UNKNOWN_LINUX_GNU",
        "AR",
        "AR_X86_64_UNKNOWN_LINUX_GNU",
        "CL",
        "_CL_",
        "CRATE_CC_NO_DEFAULTS",
        "BINDGEN_EXTRA_CLANG_ARGS",
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
        audit_environment({"cflags_x86_64_pc_windows_msvc": "/DUNTRUSTED"})
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
